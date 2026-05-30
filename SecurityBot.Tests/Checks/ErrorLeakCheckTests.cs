using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class ErrorLeakCheckTests
{
    [Fact]
    public async Task Present_when_stack_trace_marker()
    {
        var body = "System.NullReferenceException: x\n   at System.Foo.Bar()";
        var ctx = Ctx(Resp("malformed", status: 500, body: body));
        var f = await new ErrorLeakCheck().RunAsync(ctx, default);
        Assert.Equal("P30", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public async Task Present_when_sqlite_marker()
    {
        var body = "Microsoft.Data.Sqlite.SqliteException: no such table";
        var ctx = Ctx(Resp("malformed", status: 500, body: body));
        var f = await new ErrorLeakCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Present_when_internal_docker_host_marker()
    {
        var body = "failed connecting to oraclebot-api:5000";
        var ctx = Ctx(Resp("malformed", status: 502, body: body));
        var f = await new ErrorLeakCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Pass_when_clean_error_body()
    {
        var body = "{\"error\":\"INVALID_REQUEST\"}";
        var ctx = Ctx(Resp("malformed", status: 400, body: body));
        var f = await new ErrorLeakCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_malformed_missing()
    {
        var ctx = Ctx(Resp("health", status: 200));
        var f = await new ErrorLeakCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_malformed_not_reached()
    {
        var ctx = Ctx(Resp("malformed", status: 500, body: "at System.Foo()", reached: false));
        var f = await new ErrorLeakCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
