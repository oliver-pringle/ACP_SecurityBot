using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class SchemaDescriptionCheckTests
{
    [Fact]
    public async Task Partial_when_a_property_lacks_description()
    {
        var body = """
        {"properties":{"a":{"type":"string","description":"ok"},"b":{"type":"string"}}}
        """;
        var ctx = Ctx(Resp("resource_0", body: body));
        var f = await new SchemaDescriptionCheck().RunAsync(ctx, default);
        Assert.Equal("P32", f.PatternId);
        Assert.Equal(Verdict.Partial, f.Verdict);
        Assert.Equal(Severity.Low, f.Severity);
    }

    [Fact]
    public async Task Pass_when_all_properties_described()
    {
        var body = """
        {"properties":{"a":{"type":"string","description":"ok"},"b":{"type":"number","description":"also ok"}}}
        """;
        var ctx = Ctx(Resp("resource_0", body: body));
        var f = await new SchemaDescriptionCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_properties_object_found()
    {
        var ctx = Ctx(Resp("resource_0", body: "{\"chains\":[\"base\"],\"count\":1}"));
        var f = await new SchemaDescriptionCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_resource_reached()
    {
        var ctx = Ctx(Resp("health", body: "{}"));
        var f = await new SchemaDescriptionCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_body_is_not_json()
    {
        var ctx = Ctx(Resp("resource_0", body: "not json at all"));
        var f = await new SchemaDescriptionCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }

    [Fact]
    public async Task Partial_when_nested_properties_object_missing_description()
    {
        var body = """
        {"requirementSchema":{"properties":{"x":{"type":"string"}}}}
        """;
        var ctx = Ctx(Resp("resource_0", body: body));
        var f = await new SchemaDescriptionCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Partial, f.Verdict);
    }
}
