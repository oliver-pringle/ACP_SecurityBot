using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class AuthPostureCheckTests
{
    [Fact]
    public async Task Present_when_paid_unauth_returns_200()
    {
        var ctx = Ctx(Resp("paid_unauth", status: 200));
        var f = await new AuthPostureCheck().RunAsync(ctx, default);
        Assert.Equal("P1/P18", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public async Task Pass_when_paid_unauth_returns_401()
    {
        var ctx = Ctx(Resp("paid_unauth", status: 401));
        var f = await new AuthPostureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task Pass_when_paid_unauth_returns_403()
    {
        var ctx = Ctx(Resp("paid_unauth", status: 403));
        var f = await new AuthPostureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_paid_unauth_missing()
    {
        var ctx = Ctx(Resp("health", status: 200));
        var f = await new AuthPostureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_paid_unauth_not_reached()
    {
        var ctx = Ctx(Resp("paid_unauth", status: 200, reached: false));
        var f = await new AuthPostureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_paid_unauth_returns_404()
    {
        var ctx = Ctx(Resp("paid_unauth", status: 404));
        var f = await new AuthPostureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
