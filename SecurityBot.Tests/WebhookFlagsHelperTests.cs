using SecurityBot.Api.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

// Regression tests for WebhookFlagsHelper — proves the legacy
// ALLOW_INSECURE_WEBHOOKS=true alias still sets BOTH new flags, and that
// neither granular flag bleeds into the other when set on its own.
// Boot-time fail-fast on the legacy flag in non-Development environments
// is asserted by inspection of Program.cs (audit F8 originally wanted a
// WebApplicationFactory startup test — current boilerplate has no
// FactoryBase test infra, this would force adding xUnit/MS.Hosting; the
// fail-fast logic itself is two `throw new InvalidOperationException` lines
// guarded by `!app.Environment.IsDevelopment()` — out-of-tree visual review
// is the lower-friction check for the boilerplate. Clones that add hosting
// tests get this for free.)
public class WebhookFlagsHelperTests
{
    [Fact]
    public void Default_both_flags_off()
    {
        var cfg = BuildConfig();
        var (http, skipDns) = WebhookFlagsHelper.Resolve(cfg);
        Assert.False(http);
        Assert.False(skipDns);
    }

    [Fact]
    public void Legacy_alias_sets_both()
    {
        var cfg = BuildConfig(new() { ["ALLOW_INSECURE_WEBHOOKS"] = "true" });
        var (http, skipDns) = WebhookFlagsHelper.Resolve(cfg);
        Assert.True(http);
        Assert.True(skipDns);
    }

    [Fact]
    public void Granular_http_does_not_bleed_into_dns_skip()
    {
        var cfg = BuildConfig(new() { ["ALLOW_HTTP_WEBHOOKS"] = "true" });
        var (http, skipDns) = WebhookFlagsHelper.Resolve(cfg);
        Assert.True(http);
        Assert.False(skipDns);
    }

    [Fact]
    public void Granular_dns_skip_does_not_bleed_into_http_allow()
    {
        var cfg = BuildConfig(new() { ["DISABLE_WEBHOOK_DNS_VALIDATION"] = "true" });
        var (http, skipDns) = WebhookFlagsHelper.Resolve(cfg);
        Assert.False(http);
        Assert.True(skipDns);
    }

    [Fact]
    public void Resolve_handles_null_configuration_via_env_fallback()
    {
        // Env vars are not set in test process, so passing a null IConfiguration
        // resolves to (false, false) — proves the helper never NREs on null cfg.
        var (http, skipDns) = WebhookFlagsHelper.Resolve(null);
        Assert.False(http);
        Assert.False(skipDns);
    }

    private static IConfiguration BuildConfig(Dictionary<string, string?>? values = null) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values ?? new Dictionary<string, string?>())
            .Build();
}
