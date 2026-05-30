using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class ResourceDisclosureCheckTests
{
    [Fact]
    public async Task Present_when_operator_eoa_disclosed()
    {
        var body = "{\"operatorAddress\":\"0x693a1b2c3d4e5f60718293a4b5c6d7e8f9001122\"}";
        var ctx = Ctx(Resp("resource_0", body: body));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal("P9", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public async Task Present_when_rpc_url_with_api_key_disclosed()
    {
        var body = "{\"rpcUrl\":\"https://base-mainnet.g.alchemy.com/v2/SECRETKEY123\"}";
        var ctx = Ctx(Resp("resource_1", body: body));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Pass_when_bodies_clean()
    {
        var ctx = Ctx(Resp("resource_0", body: "{\"chains\":[\"base\",\"ethereum\"],\"count\":2}"));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_resource_reached()
    {
        var ctx = Ctx(Resp("health", body: "{\"ok\":true}"));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
