using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

// SSRF blocklist regression tests. The boilerplate's WebhookUrlValidator
// descends from ACP_OracleBot v0.7 and is the canonical SSRF guard for any
// bot built on this boilerplate. Test asserts the full set of ranges the
// audit (F7 + F8) demands stay blocked — adding a new clone-specific allow
// flag would need a paired test here so the ranges can't silently regress.
public class WebhookUrlValidatorTests
{
    private const bool ProdFlags_AllowHttp = false;
    private const bool ProdFlags_SkipDns   = false;

    [Theory]
    [InlineData("http://example.com/cb",                "must use https://")]
    [InlineData("ftp://example.com/cb",                 "must use https://")]
    [InlineData("",                                     "webhookUrl required")]
    [InlineData("not-a-url",                            "absolute URI")]
    public void Rejects_bad_scheme_or_shape(string url, string reasonContains)
    {
        var r = WebhookUrlValidator.Validate(url, ProdFlags_AllowHttp, ProdFlags_SkipDns);
        Assert.False(r.Ok);
        Assert.Contains(reasonContains, r.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://127.0.0.1/cb",          "loopback")]
    [InlineData("https://10.0.0.5/cb",           "rfc1918")]
    [InlineData("https://10.255.255.255/cb",     "rfc1918")]
    [InlineData("https://172.16.0.1/cb",         "rfc1918")]
    [InlineData("https://172.31.255.255/cb",     "rfc1918")]
    [InlineData("https://192.168.1.1/cb",        "rfc1918")]
    [InlineData("https://169.254.169.254/cb",    "link-local")] // AWS/GCP/Azure metadata
    [InlineData("https://100.64.0.1/cb",         "cgnat")]
    [InlineData("https://0.0.0.0/cb",            "unspecified")]
    [InlineData("https://224.0.0.1/cb",          "multicast")]
    [InlineData("https://240.0.0.1/cb",          "reserved")]
    [InlineData("https://192.0.2.1/cb",          "docs")]
    [InlineData("https://198.51.100.1/cb",       "docs")]
    [InlineData("https://203.0.113.1/cb",        "docs")]
    [InlineData("https://198.18.0.1/cb",         "benchmark")]
    // F7 additions:
    [InlineData("https://192.0.0.1/cb",          "iana")]                  // 192.0.0.0/24 IETF protocol assignments
    [InlineData("https://192.0.0.250/cb",        "iana")]                  // same range, upper end
    [InlineData("https://192.88.99.1/cb",        "6to4 anycast")]          // 6to4 anycast relay (deprecated RFC 7526)
    public void Rejects_blocked_ipv4_literals(string url, string reasonContains)
    {
        var r = WebhookUrlValidator.Validate(url, ProdFlags_AllowHttp, ProdFlags_SkipDns);
        Assert.False(r.Ok);
        Assert.Contains(reasonContains, r.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://[::1]/cb",                       "loopback")]
    [InlineData("https://[fe80::1]/cb",                   "link-local")]
    [InlineData("https://[fc00::1]/cb",                   "unique-local")]
    [InlineData("https://[ff02::1]/cb",                   "multicast")]
    [InlineData("https://[::ffff:127.0.0.1]/cb",          "loopback")]
    [InlineData("https://[2001:db8::1]/cb",               "documentation")]
    // F7 additions:
    [InlineData("https://[2002::1]/cb",                   "6to4")]         // 6to4 IPv6 prefix
    [InlineData("https://[2002:c000:0204::]/cb",          "6to4")]         // 6to4 wrapping a public IPv4
    [InlineData("https://[2001::1]/cb",                   "teredo")]       // Teredo prefix
    public void Rejects_blocked_ipv6_literals(string url, string reasonContains)
    {
        var r = WebhookUrlValidator.Validate(url, ProdFlags_AllowHttp, ProdFlags_SkipDns);
        Assert.False(r.Ok);
        Assert.Contains(reasonContains, r.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_localhost_hostname()
    {
        // "localhost" resolves to 127.0.0.1 / ::1 — both are blocked.
        var r = WebhookUrlValidator.Validate("https://localhost/cb", ProdFlags_AllowHttp, ProdFlags_SkipDns);
        Assert.False(r.Ok);
        Assert.Contains("loopback", r.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Accepts_public_https_ip_literal()
    {
        // 1.1.1.1 (Cloudflare) — clearly public; should pass.
        var r = WebhookUrlValidator.Validate("https://1.1.1.1/cb", ProdFlags_AllowHttp, ProdFlags_SkipDns);
        Assert.True(r.Ok, r.Error);
    }

    [Fact]
    public void AllowHttp_flag_permits_http_scheme_but_still_blocks_private_ips()
    {
        // Local-test mode: http allowed, DNS check still applies.
        var ok = WebhookUrlValidator.Validate("http://1.1.1.1/cb", allowHttp: true, skipDnsValidation: false);
        Assert.True(ok.Ok, ok.Error);

        var blocked = WebhookUrlValidator.Validate("http://10.0.0.1/cb", allowHttp: true, skipDnsValidation: false);
        Assert.False(blocked.Ok);
        Assert.Contains("rfc1918", blocked.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SkipDns_flag_bypasses_only_dns_check_not_scheme()
    {
        // Tests-only escape hatch. Lets `https://stubhost.test/cb` pass
        // without DNS resolution, but does NOT relax the scheme check.
        var ok = WebhookUrlValidator.Validate("https://stubhost.test/cb", allowHttp: false, skipDnsValidation: true);
        Assert.True(ok.Ok, ok.Error);

        var blocked = WebhookUrlValidator.Validate("http://stubhost.test/cb", allowHttp: false, skipDnsValidation: true);
        Assert.False(blocked.Ok);
        Assert.Contains("must use https", blocked.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Legacy_single_flag_overload_routes_to_both_flags()
    {
        // Legacy ALLOW_INSECURE_WEBHOOKS=true behaviour — sets BOTH flags.
        var ok = WebhookUrlValidator.Validate("http://stubhost.test/cb", allowInsecure: true);
        Assert.True(ok.Ok, ok.Error);
    }
}
