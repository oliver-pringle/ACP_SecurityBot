using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests;

// The three observable checks added 2026-05-30 after the audit batch collation:
// CorsCheck (P42), ServerBannerCheck (P43), StubDataCheck (P38 observable variant).
public class ObservableChecksTests
{
    private static ProbeResponse Resp(string label, params (string, string)[] headers)
        => Resp(label, "{}", headers);

    private static ProbeResponse Resp(string label, string body, params (string, string)[] headers)
    {
        var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in headers) h[k] = v;
        return new ProbeResponse(label, "https://x/" + label, 200, h, body, Reached: true);
    }

    private static ProbeContext Ctx(params ProbeResponse[] rs) => new("https://x", rs);

    private static ProbeContext NotReached() => new("https://x", new[]
    {
        new ProbeResponse("health", "u", 0, new Dictionary<string, string>(), "", Reached: false),
    });

    // ---------- CorsCheck (P42) ----------
    [Fact]
    public async Task Cors_wildcard_is_Present_Medium()
    {
        var f = await new CorsCheck().RunAsync(Ctx(Resp("health", ("Access-Control-Allow-Origin", "*"))), default);
        Assert.Equal("P42", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public async Task Cors_wildcard_with_credentials_is_Present_High()
    {
        var f = await new CorsCheck().RunAsync(Ctx(Resp("health",
            ("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true"))), default);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public async Task Cors_specific_origin_is_Pass()
    {
        var f = await new CorsCheck().RunAsync(Ctx(Resp("health", ("Access-Control-Allow-Origin", "https://app.example"))), default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task Cors_not_reached_is_NotObservable()
    {
        var f = await new CorsCheck().RunAsync(NotReached(), default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task Cors_ignores_synthetic_ratelimit_probe()
    {
        var f = await new CorsCheck().RunAsync(Ctx(
            Resp("ratelimit_probe", ("Access-Control-Allow-Origin", "*")),
            Resp("health")), default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    // ---------- ServerBannerCheck (P43) ----------
    [Fact]
    public async Task ServerBanner_kestrel_is_Present()
    {
        var f = await new ServerBannerCheck().RunAsync(Ctx(Resp("health", ("Server", "Kestrel"))), default);
        Assert.Equal("P43", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task ServerBanner_x_powered_by_is_Present()
    {
        var f = await new ServerBannerCheck().RunAsync(Ctx(Resp("health", ("X-Powered-By", "ASP.NET"))), default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task ServerBanner_versioned_server_is_Present()
    {
        var f = await new ServerBannerCheck().RunAsync(Ctx(Resp("health", ("Server", "nginx/1.25.1"))), default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task ServerBanner_versionless_proxy_is_Pass()
    {
        // "Server: cloudflare" / "Server: Caddy" with no version + no app framework -> not the bot's leak
        var f = await new ServerBannerCheck().RunAsync(Ctx(Resp("health", ("Server", "cloudflare"))), default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task ServerBanner_no_banner_is_Pass()
    {
        var f = await new ServerBannerCheck().RunAsync(Ctx(Resp("health")), default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    // ---------- StubDataCheck (P38 observable) ----------
    [Fact]
    public async Task Stub_replace_with_placeholder_is_Present()
    {
        var f = await new StubDataCheck().RunAsync(Ctx(Resp("resource_0", "{\"key\":\"REPLACE_WITH_REAL_KEY\"}")), default);
        Assert.Equal("P38", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Stub_literal_0xstub_is_Present()
    {
        var f = await new StubDataCheck().RunAsync(Ctx(Resp("resource_0", "{\"attestationUid\":\"0xSTUB\"}")), default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Stub_lorem_ipsum_is_Present()
    {
        var f = await new StubDataCheck().RunAsync(Ctx(Resp("root", "{\"description\":\"lorem ipsum dolor sit amet\"}")), default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Stub_word_synthetic_in_prose_is_NOT_flagged()
    {
        // Regression guard for the SecurityBot self-FP: a body that merely DESCRIBES
        // synthetic/placeholder patterns (like the patternCatalogue Resource) must Pass.
        var f = await new StubDataCheck().RunAsync(Ctx(Resp("resource_0",
            "{\"title\":\"Silent synthetic / stub fallback not labelled\",\"operator\":\"0x0000000000000000000000000000000000000000\"}")), default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task Stub_clean_body_is_Pass()
    {
        var f = await new StubDataCheck().RunAsync(Ctx(Resp("resource_0", "{\"score\":97,\"grade\":\"A\"}")), default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task Stub_marker_only_in_non_inspected_label_is_NotObservable()
    {
        // "health" is not an inspected body prefix (resource/root/paid_unauth); a marker there is ignored.
        var f = await new StubDataCheck().RunAsync(Ctx(Resp("health", "{\"x\":\"REPLACE_WITH_Y\"}")), default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
