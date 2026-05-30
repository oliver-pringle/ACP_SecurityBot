using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SecurityBot.Api.Email;
using Xunit;

namespace SecurityBot.Tests;

// The email research spike (docs/email-spike-findings.md) established that an
// @agents.world inbox is a real Mailgun/SES mailbox reachable by any transactional
// sender, so the real backend is a single authenticated POST to the Resend API.
// These tests pin that contract without touching the network.
public class ResendEmailSenderTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly bool _throw;
        public HttpRequestMessage? Captured;
        public string? CapturedBody;

        public FakeHandler(HttpStatusCode status = HttpStatusCode.OK, bool shouldThrow = false)
        {
            _status = status;
            _throw = shouldThrow;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            if (_throw) throw new HttpRequestException("boom");
            return new HttpResponseMessage(_status)
            {
                Content = new StringContent("{\"id\":\"x\"}", Encoding.UTF8, "application/json"),
            };
        }
    }

    private static object SampleReport() => new
    {
        baseUrl = "https://api.example.com",
        agentAddress = "0xabc",
        score = 82,
        grade = "B",
        verdict = "WARN",
        summary = "18 of 49 observable.",
        scannedAt = "2026-05-30T12:00:00Z",
        findings = new[]
        {
            new { patternId = "P31", title = "Headers", severity = "medium", verdict = "fail" },
        },
    };

    private static ResendEmailSender Make(FakeHandler h) =>
        new(new HttpClient(h), "re_test_key", "audit@securitybot.dev",
            NullLogger<ResendEmailSender>.Instance);

    [Fact]
    public async Task Returns_sent_and_posts_to_resend_with_bearer_auth()
    {
        var h = new FakeHandler(HttpStatusCode.OK);

        var result = await Make(h).SendScanReportAsync("buyer@example.com", SampleReport(), default);

        Assert.Equal("sent", result.Status);
        Assert.NotNull(h.Captured);
        Assert.Equal(HttpMethod.Post, h.Captured!.Method);
        Assert.Equal("https://api.resend.com/emails", h.Captured.RequestUri!.ToString());
        Assert.Equal("Bearer", h.Captured.Headers.Authorization!.Scheme);
        Assert.Equal("re_test_key", h.Captured.Headers.Authorization.Parameter);
        Assert.NotNull(h.CapturedBody);
        Assert.Contains("buyer@example.com", h.CapturedBody);     // to
        Assert.Contains("audit@securitybot.dev", h.CapturedBody); // from
        Assert.Contains("82", h.CapturedBody);                    // score in subject/body
    }

    [Fact]
    public async Task Returns_failed_on_non_2xx()
    {
        var result = await Make(new FakeHandler(HttpStatusCode.UnprocessableEntity))
            .SendScanReportAsync("buyer@example.com", SampleReport(), default);

        Assert.Equal("failed", result.Status);
    }

    [Fact]
    public async Task Returns_failed_when_handler_throws()
    {
        var result = await Make(new FakeHandler(shouldThrow: true))
            .SendScanReportAsync("buyer@example.com", SampleReport(), default);

        Assert.Equal("failed", result.Status);
    }

    [Fact]
    public async Task Returns_skipped_on_empty_recipient_without_calling_http()
    {
        var h = new FakeHandler(HttpStatusCode.OK);

        var result = await Make(h).SendScanReportAsync("   ", SampleReport(), default);

        Assert.Equal("skipped", result.Status);
        Assert.Null(h.Captured); // no HTTP call made for an empty recipient
    }

    [Fact]
    public async Task Does_not_emit_raw_html_tags_from_attacker_influenced_fields()
    {
        // The scanned host (baseUrl) + summary are attacker-influenced. A literal <script>
        // or <img ...> must never appear unescaped in the outbound message body (HtmlEncode
        // in the sender + System.Text.Json escaping both guarantee this).
        var malicious = new
        {
            baseUrl = "https://x/<script>alert(1)</script>",
            agentAddress = "0xabc",
            score = 0,
            grade = "F",
            verdict = "FAIL",
            summary = "<img src=x onerror=alert(1)>",
            scannedAt = "2026-05-30T12:00:00Z",
            findings = Array.Empty<object>(),
        };
        var h = new FakeHandler(HttpStatusCode.OK);

        var result = await Make(h).SendScanReportAsync("buyer@example.com", malicious, default);

        Assert.Equal("sent", result.Status);
        Assert.NotNull(h.CapturedBody);
        Assert.DoesNotContain("<script>", h.CapturedBody);
        Assert.DoesNotContain("<img ", h.CapturedBody);
    }
}
