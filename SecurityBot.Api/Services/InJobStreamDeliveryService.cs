using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SecurityBot.Api.Models;

namespace SecurityBot.Api.Services;

// inJobStream delivery — analogue of WebhookDeliveryService.
//
// Instead of HMAC-POSTing to a buyer-hosted URL, this service POSTs the tick
// payload to the sidecar's internal HTTP server at PushUrl. The sidecar holds
// the live AcpAgent and calls sendJobMessage(chainId, jobId, payload,
// "structured") on the kept-open ACP job. Same payload caps + same
// DeliveryResult shape as WebhookDeliveryService so the worker can branch on
// PushMode without changing accounting.
//
// Auth: X-API-Key matches the bot's internal key. The sidecar's stream-push
// listener binds on an INTERNAL port only (never exposed through Caddy).
public class InJobStreamDeliveryService
{
    private readonly HttpClient _http;
    private readonly ILogger<InJobStreamDeliveryService> _logger;
    private readonly string _pushUrl;
    private readonly string _submitFinalUrl;
    private readonly string? _apiKey;
    private const int BodyCapBytes = 1_048_576; // 1 MB
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    public InJobStreamDeliveryService(HttpClient http, IConfiguration cfg, ILogger<InJobStreamDeliveryService> logger)
    {
        _http = http;
        _logger = logger;
        _http.Timeout = Timeout;
        var baseUrl = cfg["StreamPush:BaseUrl"]
            ?? Environment.GetEnvironmentVariable("SECURITYBOT_STREAM_PUSH_URL")
            ?? "http://localhost:6001";
        _pushUrl = $"{baseUrl.TrimEnd('/')}/v1/internal/push-tick";
        _submitFinalUrl = $"{baseUrl.TrimEnd('/')}/v1/internal/submit-final";
        _apiKey = cfg["ApiKey"]
            ?? Environment.GetEnvironmentVariable("SECURITYBOT_API_KEY");
    }

    public Task<DeliveryResult> PushAsync(Subscription sub, int tickNumber, string payloadJson, CancellationToken ct = default)
        => PostAsync(_pushUrl, BuildPushBody(sub, tickNumber, payloadJson), ct);

    public Task<DeliveryResult> FinaliseAsync(Subscription sub, string finalPayloadJson, CancellationToken ct = default)
        => PostAsync(_submitFinalUrl, BuildFinaliseBody(sub, finalPayloadJson), ct);

    private static string BuildPushBody(Subscription sub, int tickNumber, string payloadJson)
    {
        if (sub.StreamChainId is null || string.IsNullOrEmpty(sub.StreamJobId))
            throw new InvalidOperationException(
                $"inJobStream sub {sub.Id} is missing StreamChainId or StreamJobId");
        var body = new
        {
            subscriptionId = sub.Id,
            chainId        = sub.StreamChainId.Value,
            jobId          = sub.StreamJobId,
            tickNumber,
            payloadJson
        };
        return JsonSerializer.Serialize(body);
    }

    private static string BuildFinaliseBody(Subscription sub, string finalPayloadJson)
    {
        if (sub.StreamChainId is null || string.IsNullOrEmpty(sub.StreamJobId))
            throw new InvalidOperationException(
                $"inJobStream sub {sub.Id} is missing StreamChainId or StreamJobId");
        var body = new
        {
            subscriptionId    = sub.Id,
            chainId           = sub.StreamChainId.Value,
            jobId             = sub.StreamJobId,
            finalPayloadJson
        };
        return JsonSerializer.Serialize(body);
    }

    private async Task<DeliveryResult> PostAsync(string url, string bodyJson, CancellationToken ct)
    {
        if (Encoding.UTF8.GetByteCount(bodyJson) > BodyCapBytes)
            return new DeliveryResult(false, $"payload exceeds {BodyCapBytes} bytes");

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            req.Content = new StringContent(bodyJson, Encoding.UTF8);
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            if (!string.IsNullOrEmpty(_apiKey)) req.Headers.Add("X-API-Key", _apiKey);

            using var resp = await _http.SendAsync(req, ct);
            if ((int)resp.StatusCode is >= 200 and < 300)
                return new DeliveryResult(true, null);

            // 410 Gone from the sidecar = the ACP job is no longer active
            // (expired, completed elsewhere, or never opened). The worker
            // treats this as a terminal failure for the row rather than a
            // retryable one — surface it in the error string so RetryWorker
            // can short-circuit if we ever wire that.
            var body = await resp.Content.ReadAsStringAsync(ct);
            var label = resp.StatusCode == HttpStatusCode.Gone ? "gone" : $"HTTP {(int)resp.StatusCode}";
            return new DeliveryResult(false, $"{label}: {Truncate(body, 256)}");
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

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
