using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class TlsTransportCheckTests
{
    [Fact]
    public async Task Present_when_base_url_is_plaintext_http()
    {
        var ctx = new ProbeContext("http://x.example", new[] { Resp("health") });
        var f = await new TlsTransportCheck().RunAsync(ctx, default);
        Assert.Equal("P31-TLS", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public async Task Pass_when_https_with_hsts()
    {
        var ctx = Ctx(Resp("health", headers: new Dictionary<string, string>
        {
            ["Strict-Transport-Security"] = "max-age=31536000",
        }));
        var f = await new TlsTransportCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task Partial_when_https_without_hsts()
    {
        var ctx = Ctx(Resp("health"));
        var f = await new TlsTransportCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Partial, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_https_and_nothing_reached()
    {
        var ctx = Ctx(Resp("health", reached: false));
        var f = await new TlsTransportCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
