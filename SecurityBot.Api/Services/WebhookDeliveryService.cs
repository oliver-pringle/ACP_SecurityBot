using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SecurityBot.Api.Models;

namespace SecurityBot.Api.Services;

public class WebhookDeliveryService
{
    private readonly HttpClient _http;
    private readonly ILogger<WebhookDeliveryService> _logger;
    private readonly bool _allowHttpWebhooks;
    private readonly bool _disableWebhookDnsValidation;
    private const int BodyCapBytes = 1_048_576; // 1 MB
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public WebhookDeliveryService(HttpClient http, IConfiguration cfg, ILogger<WebhookDeliveryService> logger)
    {
        _http = http;
        _logger = logger;
        _http.Timeout = Timeout;
        (_allowHttpWebhooks, _disableWebhookDnsValidation) = WebhookFlagsHelper.Resolve(cfg);
    }

    /// HMAC-SHA256 over a canonical envelope binding subscriptionId + tick +
    /// timestamp + body. The subscriptionId binding (audit F4) means a captured
    /// (tick, ts, body, sig) tuple from subscription A cannot be replayed as a
    /// fake delivery to subscription B even when they share an HMAC secret
    /// (unlikely in this bot since secrets are per-row, but a defence-in-depth
    /// belt against clones that ever reuse secrets or merge subscriptions).
    ///
    /// Canonical: "{subscriptionId}.{tick}.{timestamp}.{body}"
    ///
    /// Receivers should derive the canonical string the same way using the
    /// X-Subscription-Id + X-Subscription-Tick + X-Subscription-Timestamp
    /// headers + the EXACT raw request body, then HMAC-SHA256 with the secret
    /// delivered in the ACP subscription receipt. See README "Webhook receiver
    /// requirements" for the full verification recipe.
    public static string ComputeSignature(string subscriptionId, string secret, int tick, long timestamp, string body)
    {
        var canonical = $"{subscriptionId}.{tick}.{timestamp}.{body}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
        return "sha256=" + Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// Pre-F4 signature overload, kept for callers / tests that haven't
    /// migrated and clones that intentionally stayed on the legacy canonical.
    /// Computes HMAC-SHA256 over "{tick}.{timestamp}.{body}" — the boilerplate
    /// no longer uses this internally; will be removed in a future major.
    [Obsolete("Use ComputeSignature(subscriptionId, secret, tick, timestamp, body). Audit F4: bind subscriptionId into the canonical.")]
    public static string ComputeSignature(string secret, int tick, long timestamp, string body)
    {
        var canonical = $"{tick}.{timestamp}.{body}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
        return "sha256=" + Convert.ToHexString(hash).ToLowerInvariant();
    }

    public async Task<DeliveryResult> DeliverAsync(Subscription sub, int tickNumber, string bodyJson, CancellationToken ct = default)
    {
        if (Encoding.UTF8.GetByteCount(bodyJson) > BodyCapBytes)
            return new DeliveryResult(false, $"payload exceeds {BodyCapBytes} bytes");

        // Defence in depth — the TickScheduler routes inJobStream rows to
        // InJobStreamDeliveryService instead, so this method should never
        // see one. If it does (race / config drift / new caller), refuse
        // rather than dereference null WebhookUrl/WebhookSecret.
        if (string.IsNullOrEmpty(sub.WebhookUrl) || string.IsNullOrEmpty(sub.WebhookSecret))
            return new DeliveryResult(false,
                $"subscription {sub.Id} has no webhook configuration (pushMode={sub.PushMode})");

        // Re-validate at delivery time. The subscribe endpoint validates on
        // insert, but a) older rows may pre-date the check, b) DNS for the
        // host may have rebound to a private IP since insert.
        var urlCheck = WebhookUrlValidator.Validate(sub.WebhookUrl, _allowHttpWebhooks, _disableWebhookDnsValidation);
        if (!urlCheck.Ok)
            return new DeliveryResult(false, $"webhookUrl rejected: {urlCheck.Error}");

        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = ComputeSignature(sub.Id, sub.WebhookSecret, tickNumber, ts, bodyJson);

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, sub.WebhookUrl);
            req.Content = new StringContent(bodyJson, Encoding.UTF8);
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            req.Headers.Add("X-Subscription-Id", sub.Id);
            req.Headers.Add("X-Subscription-Tick", tickNumber.ToString());
            req.Headers.Add("X-Subscription-Timestamp", ts.ToString());
            req.Headers.Add("X-Subscription-Signature", sig);

            using var resp = await _http.SendAsync(req, ct);
            if ((int)resp.StatusCode is >= 200 and < 300)
                return new DeliveryResult(true, null);

            return new DeliveryResult(false, $"HTTP {(int)resp.StatusCode}");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return new DeliveryResult(false, "timeout");
        }
        catch (HttpRequestException ex)
        {
            return new DeliveryResult(false, $"http: {ex.Message}");
        }
    }
}

public record DeliveryResult(bool Ok, string? Error);
