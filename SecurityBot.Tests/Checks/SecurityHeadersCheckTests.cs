using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class SecurityHeadersCheckTests
{
    [Fact]
    public async Task Present_when_headers_missing()
    {
        var ctx = Ctx(Resp("health", headers: new Dictionary<string, string>()));
        var f = await new SecurityHeadersCheck().RunAsync(ctx, default);
        Assert.Equal("P31", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Pass_when_all_present()
    {
        var ctx = Ctx(Resp("health", headers: new Dictionary<string, string>
        {
            ["X-Frame-Options"] = "DENY",
            ["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'",
            ["X-Content-Type-Options"] = "nosniff",
        }));
        var f = await new SecurityHeadersCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_nothing_reached()
    {
        var ctx = Ctx(Resp("health", reached: false));
        var f = await new SecurityHeadersCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
