using SecurityBot.Api.Resolution;
using Xunit;

namespace SecurityBot.Tests;

public class TargetResolverTests
{
    private static MarketplaceTargetResolver WithMarketplace(IReadOnlyList<string> urls)
        => new MarketplaceTargetResolver((addr, ct) => Task.FromResult(urls));

    // (a) explicit baseUrl provided -> Auditable, ResolvedVia="baseUrl", BaseUrl echoes scheme+host.
    [Fact]
    public async Task Explicit_baseUrl_is_auditable_via_baseUrl()
    {
        var r = await WithMarketplace(Array.Empty<string>())
            .ResolveAsync(agentAddress: null, baseUrl: "https://api.bar.dev", default);
        Assert.True(r.Auditable);
        Assert.Equal("baseUrl", r.ResolvedVia);
        Assert.Equal("https://api.bar.dev", r.BaseUrl);
    }

    // baseUrl with a path is reduced to scheme+authority.
    [Fact]
    public async Task Explicit_baseUrl_with_path_is_reduced_to_scheme_and_authority()
    {
        var r = await WithMarketplace(Array.Empty<string>())
            .ResolveAsync(agentAddress: null, baseUrl: "https://api.bar.dev/v1/resources/x", default);
        Assert.True(r.Auditable);
        Assert.Equal("baseUrl", r.ResolvedVia);
        Assert.Equal("https://api.bar.dev", r.BaseUrl);
    }

    // (b) only agentAddress, marketplace returns two URLs sharing host -> base host derived.
    [Fact]
    public async Task AgentAddress_resolves_base_host_from_resource_urls()
    {
        var r = await WithMarketplace(new[] { "https://api.foo.dev/v1/resources/a", "https://api.foo.dev/v1/resources/b" })
            .ResolveAsync(agentAddress: "0xabc", baseUrl: null, default);
        Assert.True(r.Auditable);
        Assert.Equal("marketplace", r.ResolvedVia);
        Assert.Equal("https://api.foo.dev", r.BaseUrl);
        Assert.Equal(2, r.ResourceUrls.Count);
    }

    // (c) neither provided -> not auditable, Reason mentions "required".
    [Fact]
    public async Task Neither_provided_is_not_auditable()
    {
        var r = await WithMarketplace(Array.Empty<string>()).ResolveAsync(null, null, default);
        Assert.False(r.Auditable);
        Assert.NotNull(r.Reason);
        Assert.Contains("required", r.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // (d) only agentAddress, marketplace returns ZERO URLs -> not auditable, marketplace via, no-surface reason.
    [Fact]
    public async Task AgentAddress_with_no_resources_is_not_auditable()
    {
        var r = await WithMarketplace(Array.Empty<string>()).ResolveAsync("0xabc", null, default);
        Assert.False(r.Auditable);
        Assert.Equal("marketplace", r.ResolvedVia);
        Assert.NotNull(r.Reason);
        Assert.Contains("auditable", r.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // (e) baseUrl that is not a valid absolute http(s) URL -> not auditable, invalid/unsupported reason.
    [Fact]
    public async Task Invalid_baseUrl_is_not_auditable()
    {
        var r = await WithMarketplace(Array.Empty<string>()).ResolveAsync(null, "ftp://x", default);
        Assert.False(r.Auditable);
        Assert.NotNull(r.Reason);
        Assert.Contains("URL", r.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Garbage_baseUrl_is_not_auditable()
    {
        var r = await WithMarketplace(Array.Empty<string>()).ResolveAsync(null, "not a url", default);
        Assert.False(r.Auditable);
        Assert.NotNull(r.Reason);
        Assert.Contains("URL", r.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // First marketplace URL unparseable falls through to the next valid one.
    [Fact]
    public async Task AgentAddress_skips_unparseable_first_url()
    {
        var r = await WithMarketplace(new[] { "not a url", "https://api.foo.dev/v1/resources/b" })
            .ResolveAsync(agentAddress: "0xabc", baseUrl: null, default);
        Assert.True(r.Auditable);
        Assert.Equal("marketplace", r.ResolvedVia);
        Assert.Equal("https://api.foo.dev", r.BaseUrl);
    }

    // All marketplace URLs unparseable is treated as zero -> not auditable.
    [Fact]
    public async Task AgentAddress_all_urls_unparseable_is_not_auditable()
    {
        var r = await WithMarketplace(new[] { "not a url", "ftp://x" })
            .ResolveAsync(agentAddress: "0xabc", baseUrl: null, default);
        Assert.False(r.Auditable);
        Assert.Equal("marketplace", r.ResolvedVia);
        Assert.NotNull(r.Reason);
    }

    // baseUrl wins when both are provided (does not call the marketplace).
    [Fact]
    public async Task BaseUrl_takes_precedence_over_agentAddress()
    {
        var called = false;
        var resolver = new MarketplaceTargetResolver((addr, ct) =>
        {
            called = true;
            return Task.FromResult<IReadOnlyList<string>>(new[] { "https://api.foo.dev/v1/resources/a" });
        });
        var r = await resolver.ResolveAsync(agentAddress: "0xabc", baseUrl: "https://api.bar.dev", default);
        Assert.True(r.Auditable);
        Assert.Equal("baseUrl", r.ResolvedVia);
        Assert.Equal("https://api.bar.dev", r.BaseUrl);
        Assert.False(called);
    }
}
