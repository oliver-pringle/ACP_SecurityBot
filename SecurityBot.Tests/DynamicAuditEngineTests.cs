using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests;

public class DynamicAuditEngineTests
{
    private sealed class FakeFetcher : IProbeFetcher
    {
        public int MaxRateLimitProbes => 5;
        public Dictionary<string, ProbeResponse> Canned = new();
        public List<string> Fetched = new();
        public Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)
        {
            Fetched.Add(label);
            if (Canned.TryGetValue(label, out var r)) return Task.FromResult(r);
            return Task.FromResult(new ProbeResponse(label, url, 0,
                new Dictionary<string, string>(), "", false));
        }
    }

    [Fact]
    public async Task ScanAsync_runs_all_checks_and_produces_a_report()
    {
        var fetcher = new FakeFetcher();
        fetcher.Canned["health"] = new ProbeResponse("health", "https://x.example/health", 200,
            new Dictionary<string, string> { ["X-Frame-Options"] = "DENY" }, "{}", true);

        var checks = new IProbeCheck[]
        {
            new SecurityHeadersCheck(),
            new TlsTransportCheck(),
        };
        var engine = new DynamicAuditEngine(fetcher, checks, corpusVersion: "test-1");

        var report = await engine.ScanAsync(
            new ScanTarget(AgentAddress: "0xabc", BaseUrl: "https://x.example", ResolvedVia: "baseUrl"),
            default);

        Assert.Equal("AUDITED", report.Verdict);
        Assert.Equal(2, report.Findings.Count);
        Assert.InRange(report.Score, 0, 100);
        Assert.Contains("health", fetcher.Fetched);
    }

    [Fact]
    public async Task ScanAsync_probes_each_label_at_most_the_budget()
    {
        var fetcher = new FakeFetcher();
        var engine = new DynamicAuditEngine(fetcher, new IProbeCheck[] { new SecurityHeadersCheck() }, "test-1");
        await engine.ScanAsync(new ScanTarget(null, "https://x.example", "baseUrl"), default);
        Assert.True(fetcher.Fetched.Count <= ProbeClient.MaxRequestsPerScan);
    }
}
