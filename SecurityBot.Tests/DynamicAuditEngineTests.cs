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
    public async Task ScanAsync_when_nothing_reachable_is_NOT_AUDITABLE_not_a_perfect_score()
    {
        // Fetcher with NO canned responses => every probe Reached=false => every
        // check abstains (NotObservable) => observableCount 0. A resolvable-but-
        // unreachable target must be reported honestly as NOT_AUDITABLE, never as a
        // misleading 100/A "AUDITED" (we never actually saw the surface).
        var fetcher = new FakeFetcher();
        var checks = new IProbeCheck[] { new SecurityHeadersCheck(), new TlsTransportCheck() };
        var engine = new DynamicAuditEngine(fetcher, checks, corpusVersion: "test-1");

        var report = await engine.ScanAsync(
            new ScanTarget(AgentAddress: "0xabc", BaseUrl: "https://unreachable.example", ResolvedVia: "baseUrl"),
            default);

        Assert.Equal(0, report.ObservableCount);
        Assert.Equal("NOT_AUDITABLE", report.Verdict);
    }

    [Fact]
    public async Task ScanAsync_probes_each_label_at_most_the_budget()
    {
        var fetcher = new FakeFetcher();
        var engine = new DynamicAuditEngine(fetcher, new IProbeCheck[] { new SecurityHeadersCheck() }, "test-1");
        await engine.ScanAsync(new ScanTarget(null, "https://x.example", "baseUrl"), default);
        Assert.True(fetcher.Fetched.Count <= ProbeClient.MaxRequestsPerScan);
    }

    // --- per-scan budget reset (2026-06-10): ProbeClient is a SINGLETON whose
    // MaxRequestsPerScan counter was never reset between scans, so after ~25 cumulative
    // probes (a couple of scans, or the background WatchWorker) EVERY probe short-
    // circuited to reached=false and EVERY agent read NOT_AUDITABLE. The engine now
    // calls IProbeFetcher.BeginScan() at the top of every scan. ---

    private sealed class SpyFetcher : IProbeFetcher
    {
        public int BeginScanCalls;
        public int MaxRateLimitProbes => 5;
        public void BeginScan() => Interlocked.Increment(ref BeginScanCalls);
        public Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)
            => Task.FromResult(new ProbeResponse(label, url, 200,
                new Dictionary<string, string>(), "{}", true));
    }

    [Fact]
    public async Task ScanAsync_calls_BeginScan_once_per_scan()
    {
        var fetcher = new SpyFetcher();
        var engine = new DynamicAuditEngine(fetcher, new IProbeCheck[] { new SecurityHeadersCheck() }, "test-1");
        var target = new ScanTarget(null, "https://x.example", "baseUrl");

        await engine.ScanAsync(target, default);
        await engine.ScanAsync(target, default);

        Assert.Equal(2, fetcher.BeginScanCalls);
    }

    // Mimics ProbeClient's real per-instance lifetime budget: reached until a cap, then
    // reached=false; BeginScan() resets it. Reproduces the singleton-budget bug.
    private sealed class BudgetedFakeFetcher : IProbeFetcher
    {
        private readonly int _cap;
        private int _count;
        public BudgetedFakeFetcher(int cap) => _cap = cap;
        public int MaxRateLimitProbes => 5;
        public void BeginScan() => Interlocked.Exchange(ref _count, 0);
        public Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _count) > _cap)
                return Task.FromResult(new ProbeResponse(label, url, 0,
                    new Dictionary<string, string>(), "", false));
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-Frame-Options"] = "DENY",
                ["Content-Security-Policy"] = "default-src 'none'",
                ["X-Content-Type-Options"] = "nosniff",
            };
            return Task.FromResult(new ProbeResponse(label, url, 200, headers, "{}", true));
        }
    }

    [Fact]
    public async Task ScanAsync_back_to_back_both_audit_because_budget_resets_per_scan()
    {
        // cap = the exact probe count of a no-resource scan (health, root, paid_unauth,
        // malformed, + 5 rate-limit-burst = 9). Scan 1 fills it exactly; a SHARED
        // lifetime budget would leave scan 2 starting already over cap -> all probes
        // reached=false -> NOT_AUDITABLE. Both must AUDIT, proving the per-scan reset.
        var fetcher = new BudgetedFakeFetcher(cap: 9);
        var engine = new DynamicAuditEngine(fetcher, new IProbeCheck[] { new SecurityHeadersCheck() }, "test-1");
        var target = new ScanTarget(null, "https://x.example", "baseUrl");

        var first = await engine.ScanAsync(target, default);
        var second = await engine.ScanAsync(target, default);

        Assert.Equal("AUDITED", first.Verdict);
        Assert.Equal("AUDITED", second.Verdict);
    }
}
