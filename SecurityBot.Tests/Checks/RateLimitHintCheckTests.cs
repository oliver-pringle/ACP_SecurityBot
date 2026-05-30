using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class RateLimitHintCheckTests
{
    [Fact]
    public async Task Pass_when_probe_observed_429()
    {
        var ctx = Ctx(Resp("ratelimit_probe", status: 429));
        var f = await new RateLimitHintCheck().RunAsync(ctx, default);
        Assert.Equal("P15/P19", f.PatternId);
        Assert.Equal(Verdict.Pass, f.Verdict);
        Assert.Equal(Severity.Low, f.Severity);
    }

    [Fact]
    public async Task Partial_when_probe_returned_200()
    {
        var ctx = Ctx(Resp("ratelimit_probe", status: 200));
        var f = await new RateLimitHintCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Partial, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_probe_missing()
    {
        var ctx = Ctx(Resp("health", status: 200));
        var f = await new RateLimitHintCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_probe_not_reached()
    {
        var ctx = Ctx(Resp("ratelimit_probe", status: 429, reached: false));
        var f = await new RateLimitHintCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
