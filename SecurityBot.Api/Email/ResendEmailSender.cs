using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SecurityBot.Api.Email;

// Transactional email backend over the Resend HTTP API (https://api.resend.com/emails).
//
// Why Resend + a plain HttpClient: the email research spike (docs/email-spike-findings.md)
// established that a Virtuals @agents.world inbox is a REAL, externally-deliverable
// Mailgun/SES-backed mailbox — there is NO special Virtuals send API, so any standard
// transactional sender reaches it. Resend is a single authenticated POST, so no new NuGet
// dependency is pulled in.
//
// This sender is registered ONLY when both RESEND_API_KEY and SECURITYBOT_EMAIL_FROM are
// configured (see Program.cs). With either missing the bot falls back to NoopEmailSender
// ("no_backend"), so email stays default-OFF exactly as in v1.
//
// IMPORTANT: SECURITYBOT_EMAIL_FROM must be an address on a domain VERIFIED in the Resend
// dashboard (SPF/DKIM/DMARC), or mail to agents.world (Mailgun inbound) will be spam-filtered.
//
// The recipient is BUYER-SUPPLIED (recipientEmail on the scan request). The audited agent's
// @agents.world address is not exposed by the public V2 marketplace API, so it cannot be
// auto-resolved — see the spike doc.
public sealed class ResendEmailSender : IEmailSender
{
    private const int BodyCapBytes = 256 * 1024;

    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly string _fromAddress;
    private readonly ILogger<ResendEmailSender> _logger;

    public ResendEmailSender(
        HttpClient http, string apiKey, string fromAddress, ILogger<ResendEmailSender> logger)
    {
        _http = http;
        _apiKey = apiKey;
        _fromAddress = fromAddress;
        _logger = logger;
    }

    public async Task<EmailResult> SendScanReportAsync(string toAgentEmail, object report, CancellationToken ct)
    {
        // Defensive: the caller already validates the recipient, but never send to an
        // empty/whitespace address — report it honestly as skipped rather than failing.
        if (string.IsNullOrWhiteSpace(toAgentEmail))
            return new EmailResult("skipped");

        try
        {
            var (subject, html, text) = BuildMessage(report);
            var payload = new
            {
                from = _fromAddress,
                to = new[] { toAgentEmail },
                subject,
                html,
                text,
            };

            using var msg = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails");
            msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
            msg.Content = new StringContent(
                JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            using var resp = await _http.SendAsync(msg, ct);
            if (resp.IsSuccessStatusCode)
                return new EmailResult("sent");

            // Don't log the body verbatim (it can echo the recipient / provider detail).
            _logger.LogWarning("[email] Resend rejected the send: HTTP {Status}", (int)resp.StatusCode);
            return new EmailResult("failed");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Caller cancelled — surface as failed, never throw into the scan path.
            return new EmailResult("failed");
        }
        catch (Exception ex)
        {
            // The scan must succeed even if the optional email tier throws. Log the type
            // only (no message — P30, never leak internal detail).
            _logger.LogWarning("[email] Resend send threw {Type}", ex.GetType().Name);
            return new EmailResult("failed");
        }
    }

    // Render the scan report (an anonymous object assembled by the scan handler) into a
    // subject + HTML + plaintext body. Everything interpolated into HTML is HtmlEncoded —
    // baseUrl/summary are attacker-influenced (the scanned host), so an un-encoded value
    // could inject markup into the email (P10/P30 self-application).
    private static (string subject, string html, string text) BuildMessage(object report)
    {
        JsonElement j;
        try { j = JsonSerializer.SerializeToElement(report); }
        catch { j = default; }

        string Str(string k) =>
            j.ValueKind == JsonValueKind.Object && j.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() ?? "" : "";
        int Int(string k) =>
            j.ValueKind == JsonValueKind.Object && j.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)
                ? i : 0;

        var baseUrl = Str("baseUrl");
        var grade = Str("grade");
        var verdict = Str("verdict");
        var summary = Str("summary");
        var score = Int("score");

        var rows = new StringBuilder();
        var textRows = new StringBuilder();
        if (j.ValueKind == JsonValueKind.Object
            && j.TryGetProperty("findings", out var findings)
            && findings.ValueKind == JsonValueKind.Array)
        {
            foreach (var f in findings.EnumerateArray())
            {
                string F(string k) => f.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                var pid = F("patternId");
                var title = F("title");
                var sev = F("severity");
                var fv = F("verdict");
                rows.Append($"<tr><td>{Enc(pid)}</td><td>{Enc(title)}</td><td>{Enc(sev)}</td><td>{Enc(fv)}</td></tr>");
                textRows.Append($"  [{pid}] {title} - {sev} - {fv}\n");
            }
        }

        var subject = $"Security audit: {baseUrl} - {score}/100 ({grade})";

        var html =
            $"<h2>Security audit - {Enc(baseUrl)}</h2>" +
            $"<p><strong>Score:</strong> {score}/100 ({Enc(grade)}) &nbsp; <strong>Verdict:</strong> {Enc(verdict)}</p>" +
            $"<p>{Enc(summary)}</p>" +
            "<table border=\"1\" cellpadding=\"4\" cellspacing=\"0\">" +
            "<thead><tr><th>Pattern</th><th>Title</th><th>Severity</th><th>Verdict</th></tr></thead>" +
            $"<tbody>{rows}</tbody></table>" +
            "<p style=\"color:#888;font-size:12px\">Delivered by TheSecurityBot - passive, read-only audit. " +
            "Reply STOP is not monitored; this is a one-off report you requested.</p>";

        var text =
            $"Security audit - {baseUrl}\n" +
            $"Score: {score}/100 ({grade})   Verdict: {verdict}\n\n" +
            $"{summary}\n\nFindings:\n{textRows}\n-- TheSecurityBot";

        // Cap the serialized body defensively (a pathological findings list shouldn't
        // produce a multi-MB email).
        if (Encoding.UTF8.GetByteCount(html) > BodyCapBytes)
            html = html[..Math.Min(html.Length, BodyCapBytes / 2)] + "</tbody></table><p>(truncated)</p>";

        return (subject, html, text);
    }

    private static string Enc(string? s) => System.Net.WebUtility.HtmlEncode(s ?? "");
}
