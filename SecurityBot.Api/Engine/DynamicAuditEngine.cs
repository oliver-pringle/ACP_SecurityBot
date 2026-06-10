using Microsoft.Extensions.Logging;
using SecurityBot.Api.Services;

namespace SecurityBot.Api.Engine;

// What to audit: a base URL (already SSRF-classified at connect time by ProbeClient)
// plus optional context (the agent address it was resolved from, how it was resolved,
// and any Resource URLs the marketplace advertised for that agent).
public sealed record ScanTarget(
    string? AgentAddress,
    string BaseUrl,
    string ResolvedVia,
    IReadOnlyList<string>? ResourceUrls = null);

// The assembled, honest audit report. Score is from observable findings only;
// ObservableCount / TotalPatterns make the "what could we actually see" denominator explicit.
public sealed record ScanReport(
    string? AgentAddress, string BaseUrl, string ResolvedVia,
    DateTime ScannedAtUtc, int Score, string Grade,
    int ObservableCount, int TotalPatterns,
    IReadOnlyList<Finding> Findings, string Summary, string Verdict);

// Orchestrates a single scan: probe the target ONCE into a shared ProbeContext, run
// every registered check over those shared responses, score, and assemble a report.
// The fetch seam (IProbeFetcher) is injected so the whole pipeline is unit-testable
// with a fake fetcher and zero network.
public sealed class DynamicAuditEngine
{
    // The full SecurityBot pattern catalogue size — the denominator for "patterns
    // this bot knows about", used to frame how many were externally OBSERVABLE in any
    // given scan. Kept in lockstep with Data/catalogue/patterns.json (P1-P64 + P31-TLS
    // + B1-B9 = 74). Was a stale 48 (P1-P31 era) which under-reported the denominator
    // on every persisted scan.
    private const int TotalPatternCount = 74;

    // Cap on advertised Resource URLs we will probe, to stay well within the
    // per-scan request budget regardless of how many the marketplace lists.
    private const int MaxResourceProbes = 6;

    // Small inter-request delay during the rate-limit burst so it is a real bounded
    // burst rather than an instantaneous flood; kept short so the unit suite stays fast.
    private static readonly TimeSpan RateLimitBurstDelay = TimeSpan.FromMilliseconds(20);

    private readonly IProbeFetcher _fetcher;
    private readonly IReadOnlyList<IProbeCheck> _checks;
    private readonly string _corpusVersion;
    private readonly ILogger<DynamicAuditEngine>? _logger;

    public DynamicAuditEngine(
        IProbeFetcher fetcher, IEnumerable<IProbeCheck> checks, string corpusVersion,
        ILogger<DynamicAuditEngine>? logger = null)
    {
        _fetcher = fetcher;
        _checks = checks.ToList();
        _corpusVersion = corpusVersion;
        _logger = logger;
    }

    public async Task<ScanReport> ScanAsync(ScanTarget target, CancellationToken ct)
    {
        // Reset the fetcher's per-scan request budget. ProbeClient is a singleton; without
        // this its MaxRequestsPerScan cap accumulates across scans + the WatchWorker and
        // permanently exhausts (every probe -> reached=false -> NOT_AUDITABLE for all).
        _fetcher.BeginScan();

        var baseUrl = target.BaseUrl.TrimEnd('/');
        var responses = new List<ProbeResponse>();

        // 1a. Fixed label set -- one GET each.
        var healthUrl = $"{baseUrl}/health";
        var health = await _fetcher.FetchAsync("health", healthUrl, ct).ConfigureAwait(false);
        responses.Add(health);

        responses.Add(await _fetcher.FetchAsync("root", $"{baseUrl}/", ct).ConfigureAwait(false));

        // 1b. Advertised Resource URLs (capped). Resolve relative/path-only forms
        // against the base URL; pass absolute URLs through unchanged.
        var resourceUrls = target.ResourceUrls ?? Array.Empty<string>();
        var resourceCount = Math.Min(resourceUrls.Count, MaxResourceProbes);
        for (var i = 0; i < resourceCount; i++)
        {
            var resolved = ResolveResourceUrl(baseUrl, resourceUrls[i]);
            responses.Add(await _fetcher.FetchAsync($"resource_{i}", resolved, ct).ConfigureAwait(false));
        }

        responses.Add(await _fetcher.FetchAsync(
            "paid_unauth", $"{baseUrl}/v1/internal/scan", ct).ConfigureAwait(false));

        responses.Add(await _fetcher.FetchAsync(
            "malformed", $"{baseUrl}/v1/__securitybot_probe__?x=%ff", ct).ConfigureAwait(false));

        // 1c. Bounded rate-limit burst against /health. Synthesize one
        // 'ratelimit_probe' response from the burst result so RateLimitHintCheck has
        // a single label to read.
        var ratelimitProbe = await RunRateLimitBurstAsync(baseUrl, healthUrl, ct).ConfigureAwait(false);
        responses.Add(ratelimitProbe);

        // 2. Shared context.
        var ctx = new ProbeContext(target.BaseUrl, responses);

        // 3. Run every check in order.
        var findings = new List<Finding>(_checks.Count);
        foreach (var check in _checks)
            findings.Add(await check.RunAsync(ctx, ct).ConfigureAwait(false));

        // 4. How many patterns could we actually observe?
        var observableCount = findings.Count(f =>
            f.Verdict is Verdict.Present or Verdict.Partial or Verdict.Pass);

        // If NOTHING was externally observable — every probe failed to connect, so
        // every check abstained — the target was resolvable but UNREACHABLE. That is
        // not a clean bill of health: emitting 100/A here would falsely imply we
        // audited a surface we never actually saw. Report it honestly as
        // NOT_AUDITABLE (no meaningful score). Downstream (Metabot TheSecurityBotClient)
        // maps this verdict to status=not_auditable + null score, exactly like an
        // unresolvable target; the scan endpoint + WatchWorker skip persistence for it.
        if (observableCount == 0)
        {
            // Diagnostic (low-noise: fires ONLY on the NOT_AUDITABLE outcome we are
            // debugging). Per-probe label:status:Reached lets an operator see WHY
            // nothing was observable — every probe unreached (network/timeout/SSRF-
            // blocked) vs reached-but-all-checks-abstained. WARNING level so it
            // surfaces regardless of the configured minimum log level.
            _logger?.LogWarning(
                "[scan-diag] NOT_AUDITABLE base={Base} via={Via} probes=[{Probes}]",
                target.BaseUrl, target.ResolvedVia,
                string.Join(" ", responses.Select(r => $"{r.Label}:{r.StatusCode}:{(r.Reached ? "R" : "x")}")));
            return new ScanReport(
                target.AgentAddress, target.BaseUrl, target.ResolvedVia,
                DateTime.UtcNow, Score: 0, Grade: "N/A",
                ObservableCount: 0, TotalPatternCount, findings,
                Summary: $"No externally observable surface was reachable; " +
                         $"{findings.Count} patterns abstained. NOT_AUDITABLE.",
                Verdict: "NOT_AUDITABLE");
        }

        // 5. Score from observable findings only, then assemble the report.
        var (score, grade) = ScoreCalculator.Compute(findings);
        var summary =
            $"Audited {observableCount} patterns externally; {findings.Count} findings; " +
            $"score {score}/100 (grade {grade}).";

        return new ScanReport(
            target.AgentAddress, target.BaseUrl, target.ResolvedVia,
            DateTime.UtcNow, score, grade, observableCount, TotalPatternCount,
            findings, summary, "AUDITED");
    }

    // Resolve a resource URL: absolute http(s) URLs are used as-is; anything else is
    // treated as a path relative to the base URL.
    private static string ResolveResourceUrl(string baseUrl, string resourceUrl)
    {
        if (resourceUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            resourceUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return resourceUrl;

        var path = resourceUrl.StartsWith('/') ? resourceUrl : "/" + resourceUrl;
        return baseUrl + path;
    }

    // Fire up to MaxRateLimitProbes GETs at /health with a tiny inter-request delay,
    // then collapse the burst into a single synthesized 'ratelimit_probe' response:
    //   - 429 seen in the burst  -> reached:true, status 429 (target rate-limits)
    //   - else any reached        -> reached:true, status 200 (no limit observed)
    //   - nothing reached         -> reached:false (could not observe)
    private async Task<ProbeResponse> RunRateLimitBurstAsync(string baseUrl, string healthUrl, CancellationToken ct)
    {
        var url = $"{baseUrl}/v1/resources/__rl__"; // label url is cosmetic for the synthesized response
        var probes = Math.Max(1, _fetcher.MaxRateLimitProbes);

        var sawReached = false;
        var saw429 = false;

        for (var i = 0; i < probes; i++)
        {
            if (i > 0) await Task.Delay(RateLimitBurstDelay, ct).ConfigureAwait(false);
            var r = await _fetcher.FetchAsync("health", healthUrl, ct).ConfigureAwait(false);
            if (r.Reached) sawReached = true;
            if (r.StatusCode == 429) { saw429 = true; break; }
        }

        var emptyHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (saw429)
            return new ProbeResponse("ratelimit_probe", url, 429, emptyHeaders, "", true);
        if (sawReached)
            return new ProbeResponse("ratelimit_probe", url, 200, emptyHeaders, "", true);
        return new ProbeResponse("ratelimit_probe", url, 0, emptyHeaders, "", false);
    }
}
