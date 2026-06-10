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

    // --- broadened credential detection (2026-06-10) ---

    [Theory]
    [InlineData("{\"k\":\"sk-AbCdEf0123456789AbCdEf0123456789\"}")]                       // OpenAI classic
    [InlineData("{\"k\":\"sk-proj-AbCdEf0123456789_AbCdEf0123\"}")]                        // OpenAI project
    [InlineData("{\"k\":\"sk-ant-api03-AbCdEf0123456789_AbCdEf\"}")]                       // Anthropic
    [InlineData("{\"k\":\"AKIAIOSFODNN7EXAMPLE9\"}")]                                       // AWS access key id
    [InlineData("{\"k\":\"ghp_AbCdEf0123456789AbCdEf0123456789ABCD\"}")]                   // GitHub PAT (classic)
    [InlineData("{\"k\":\"github_pat_11ABCDEFG0AbCdEf0123456789_AbCdEf0123456789ABCD\"}")] // GitHub fine-grained
    [InlineData("{\"k\":\"-----BEGIN EC PRIVATE KEY-----\\nMIIB...\"}")]                    // PEM private key
    public async Task Present_when_credential_disclosed(string body)
    {
        var ctx = Ctx(Resp("resource_0", body: body));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal("P9", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public async Task Present_evidence_masks_the_secret_does_not_re_leak_it()
    {
        const string secret = "sk-AbCdEf0123456789AbCdEf0123456789SECRETTAIL";
        var ctx = Ctx(Resp("resource_0", body: $"{{\"openaiKey\":\"{secret}\"}}"));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.DoesNotContain(secret, f.Evidence);                 // full secret never echoed
        Assert.DoesNotContain("SECRETTAIL", f.Evidence);
        Assert.Contains("redacted", f.Evidence);
    }

    [Theory]
    [InlineData("{\"note\":\"rotate your private key and api keys regularly\"}")]   // prose, no PEM header / token
    [InlineData("{\"sku\":\"sk-7\",\"status\":\"ok\"}")]                              // short sk- (not a key)
    [InlineData("{\"pattern\":\"P9 flags keyed RPC URLs and credentials\"}")]        // catalogue-style prose
    public async Task Pass_when_no_real_credential(string body)
    {
        var ctx = Ctx(Resp("resource_0", body: body));
        var f = await new ResourceDisclosureCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }
}
