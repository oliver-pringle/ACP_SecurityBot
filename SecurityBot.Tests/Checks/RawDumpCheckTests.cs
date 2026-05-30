using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class RawDumpCheckTests
{
    private static IDictionary<string, string> Json() =>
        new Dictionary<string, string> { ["Content-Type"] = "application/json" };

    [Fact]
    public async Task Present_when_large_top_level_array()
    {
        var elems = string.Join(",", Enumerable.Range(0, 60).Select(i => $"{{\"id\":{i}}}"));
        var body = "[" + elems + "]";
        var ctx = Ctx(Resp("resource_0", headers: Json(), body: body));
        var f = await new RawDumpCheck().RunAsync(ctx, default);
        Assert.Equal("P10", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public async Task Present_when_db_column_names_present()
    {
        var body = "{\"id\":1,\"created_at\":\"x\",\"webhook_secret\":\"shh\"}";
        var ctx = Ctx(Resp("resource_1", headers: Json(), body: body));
        var f = await new RawDumpCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Pass_when_clean_small_object()
    {
        var body = "{\"chains\":[\"base\"],\"count\":1}";
        var ctx = Ctx(Resp("resource_0", headers: Json(), body: body));
        var f = await new RawDumpCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_resource_reached()
    {
        var ctx = Ctx(Resp("health", headers: Json(), body: "{}"));
        var f = await new RawDumpCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
