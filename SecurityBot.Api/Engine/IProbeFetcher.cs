namespace SecurityBot.Api.Engine;

public interface IProbeFetcher
{
    Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct);
    int MaxRateLimitProbes { get; }

    // Reset the per-scan request budget. The engine MUST call this at the start of
    // every scan: ProbeClient is a singleton, so its request counter would otherwise
    // accumulate across scans (and across the background WatchWorker sharing the same
    // instance) and permanently exhaust the MaxRequestsPerScan budget — after which
    // every probe returns reached=false and EVERY agent reads NOT_AUDITABLE. Default
    // no-op for budget-less fetchers (test fakes).
    void BeginScan() { }
}
