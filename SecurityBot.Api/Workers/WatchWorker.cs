using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;

namespace SecurityBot.Api.Workers;

// Pure diff between two scans of the same target. A finding is "open" when its
// verdict is Present or Partial (a posture gap we could externally observe);
// Pass / NotObservable / NotApplicable are not open. NewlyOpened is the set of
// pattern IDs that became open since the previous scan; NewlyClosed is the set
// that were open before and are no longer. The diff is by PatternId only — the
// watch tier signals "what changed", not the full finding bodies (those live in
// the persisted scan the buyer can pull separately).
public sealed record WatchDiffResult(IReadOnlyList<string> NewlyOpened, IReadOnlyList<string> NewlyClosed)
{
    public bool HasChanges => NewlyOpened.Count > 0 || NewlyClosed.Count > 0;
}

public static class WatchDiff
{
    private static bool IsOpen(Verdict v) => v is Verdict.Present or Verdict.Partial;

    public static WatchDiffResult Compute(IReadOnlyList<Finding> prev, IReadOnlyList<Finding> curr)
    {
        var prevOpen = prev.Where(f => IsOpen(f.Verdict)).Select(f => f.PatternId).ToHashSet();
        var currOpen = curr.Where(f => IsOpen(f.Verdict)).Select(f => f.PatternId).ToHashSet();
        var opened = currOpen.Where(id => !prevOpen.Contains(id)).OrderBy(x => x).ToList();
        var closed = prevOpen.Where(id => !currOpen.Contains(id)).OrderBy(x => x).ToList();
        return new WatchDiffResult(opened, closed);
    }
}

// The security_watch worker. Repurposed from BasicSubscriptionBot's
// TickSchedulerWorker: instead of pushing a fixed per-tick payload, each tick
// RE-SCANS the watched target (DynamicAuditEngine), DIFFs the fresh findings
// against the previous scan (WatchDiff), persists the new scan, and delivers a
// compact "what changed" payload — but ONLY when something actually changed, so
// a buyer watching a stable target isn't spammed with empty diffs.
//
// Single-replica: the UNIQUE(subscription_id, tick_number) constraint on
// subscription_runs is the idempotency guard; no atomic claim is taken (out of
// scope for v1).
public class WatchWorker : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);
    private const int BatchSize = 100;
    private const int MaxConcurrent = 8;

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<WatchWorker> _logger;

    public WatchWorker(IServiceScopeFactory scopes, ILogger<WatchWorker> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WatchWorker started, polling every {Interval}", PollInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await TickOnceAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "WatchWorker tick failed; continuing"); }
            try { await Task.Delay(PollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task TickOnceAsync(CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var subs = scope.ServiceProvider.GetRequiredService<SubscriptionRepository>();
        var runs = scope.ServiceProvider.GetRequiredService<SubscriptionRunRepository>();
        var engine = scope.ServiceProvider.GetRequiredService<DynamicAuditEngine>();
        var scans = scope.ServiceProvider.GetRequiredService<ScanRepository>();
        var webhookDeliverer = scope.ServiceProvider.GetRequiredService<WebhookDeliveryService>();
        var streamDeliverer = scope.ServiceProvider.GetRequiredService<InJobStreamDeliveryService>();

        var due = await subs.GetDueAsync(DateTime.UtcNow, BatchSize);
        if (due.Count == 0) return;
        _logger.LogInformation("Watch batch: {Count} due subscriptions", due.Count);

        var sem = new SemaphoreSlim(MaxConcurrent);
        var tasks = due.Select(async sub =>
        {
            await sem.WaitAsync(ct);
            try { await ProcessSubscriptionAsync(sub, runs, subs, engine, scans, webhookDeliverer, streamDeliverer, ct); }
            finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
    }

    private async Task ProcessSubscriptionAsync(
        Subscription sub,
        SubscriptionRunRepository runs,
        SubscriptionRepository subs,
        DynamicAuditEngine engine,
        ScanRepository scans,
        WebhookDeliveryService webhookDeliverer,
        InJobStreamDeliveryService streamDeliverer,
        CancellationToken ct)
    {
        var nextTickNumber = sub.TicksDelivered + 1;
        var nextRunAt = DateTime.UtcNow.AddSeconds(sub.IntervalSeconds);
        var completed = nextTickNumber >= sub.TicksPurchased;

        // Parse the watch target out of the requirement JSON the bind step stored.
        var (agentAddress, baseUrl) = ParseTarget(sub.RequirementJson);
        if (string.IsNullOrWhiteSpace(baseUrl) && string.IsNullOrWhiteSpace(agentAddress))
        {
            // A valid security_watch sub always carries at least one of
            // agentAddress / baseUrl (Task 11's bind enforces it). A row with
            // neither is malformed — advance the tick as a recorded failure so
            // the subscription doesn't spin on it every poll, and move on.
            _logger.LogWarning(
                "Watch sub {Id} has no agentAddress/baseUrl in requirement JSON; recording empty tick",
                sub.Id);
            var deadRunId = await runs.InsertPendingAsync(sub.Id, nextTickNumber, DateTime.UtcNow, "{}");
            await runs.MarkDeadAsync(deadRunId, attempts: 1, lastError: "no scan target in requirement JSON");
            await subs.RecordTickResultAsync(sub.Id, false, DateTime.UtcNow, nextRunAt, completed);
            return;
        }

        // baseUrl is required by the engine; if only an agentAddress was stored
        // (no resolved baseUrl), there is nothing to probe at this tier — Task 10's
        // MarketplaceTargetResolver will resolve agent -> baseUrl at bind time.
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            _logger.LogWarning(
                "Watch sub {Id} has agentAddress but no baseUrl to probe; recording empty tick",
                sub.Id);
            var deadRunId = await runs.InsertPendingAsync(sub.Id, nextTickNumber, DateTime.UtcNow, "{}");
            await runs.MarkDeadAsync(deadRunId, attempts: 1, lastError: "no baseUrl resolved for scan target");
            await subs.RecordTickResultAsync(sub.Id, false, DateTime.UtcNow, nextRunAt, completed);
            return;
        }

        // Re-scan the target, then diff against the previous scan's findings.
        var target = new ScanTarget(
            AgentAddress: string.IsNullOrWhiteSpace(agentAddress) ? null : agentAddress,
            BaseUrl: baseUrl!,
            ResolvedVia: string.IsNullOrWhiteSpace(agentAddress) ? "baseUrl" : "agentAddress");

        var prevFindings = await scans.GetMostRecentFindingsAsync(target.AgentAddress, target.BaseUrl);
        ScanReport report;
        try
        {
            report = await engine.ScanAsync(target, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Payload compute (scan) failed for sub {Id} tick {N}", sub.Id, nextTickNumber);
            // Audit (P53 clone-backport): advance next_run_at + record failure rather than letting
            // the scan exception propagate, else GetDueAsync re-selects the sub every poll forever
            // and the suspend backstop never engages.
            await subs.RecordTickResultAsync(sub.Id, false, DateTime.UtcNow, nextRunAt, completed);
            return;
        }
        var diff = WatchDiff.Compute(prevFindings, report.Findings);

        // Persist the fresh scan so the NEXT tick diffs against it (and so the
        // buyer can pull the full report out-of-band).
        var record = new ScanRecord(
            AgentAddress: report.AgentAddress,
            BaseUrl: report.BaseUrl,
            ResolvedVia: report.ResolvedVia,
            Score: report.Score,
            Grade: report.Grade,
            ObservableCount: report.ObservableCount,
            FindingCount: report.Findings.Count,
            Verdict: report.Verdict,
            CorpusVersion: report.ScannedAtUtc.ToString("yyyy-MM-dd"),
            ScannedAtUtc: report.ScannedAtUtc);
        await scans.InsertAsync(record, report.Findings);

        var payload = JsonSerializer.Serialize(new
        {
            subscriptionId = sub.Id,
            tickNumber     = nextTickNumber,
            scannedAt      = report.ScannedAtUtc.ToString("O"),
            score          = report.Score,
            grade          = report.Grade,
            newlyOpened    = diff.NewlyOpened,
            newlyClosed    = diff.NewlyClosed,
            hasChanges     = diff.HasChanges,
        });

        var runId = await runs.InsertPendingAsync(sub.Id, nextTickNumber, DateTime.UtcNow, payload);

        // No changes since the last tick: don't POST an empty diff to the buyer.
        // The tick still counts as delivered so the subscription advances on
        // schedule and completes on its final tick.
        if (!diff.HasChanges)
        {
            _logger.LogInformation(
                "Watch sub {Id} tick {N}: no changes, skipping delivery", sub.Id, nextTickNumber);
            await runs.MarkDeliveredAsync(runId, DateTime.UtcNow);
            await subs.RecordTickResultAsync(sub.Id, true, DateTime.UtcNow, nextRunAt, completed);
            return;
        }

        DeliveryResult result = sub.PushMode switch
        {
            "inJobStream" => await streamDeliverer.PushAsync(sub, nextTickNumber, payload, ct),
            _             => await webhookDeliverer.DeliverAsync(sub, nextTickNumber, payload, ct),
        };

        if (result.Ok)
        {
            await runs.MarkDeliveredAsync(runId, DateTime.UtcNow);
            await subs.RecordTickResultAsync(sub.Id, true, DateTime.UtcNow, nextRunAt, completed);

            if (completed && sub.PushMode == "inJobStream")
            {
                await FinaliseStreamAsync(sub, nextTickNumber, streamDeliverer, ct);
            }
        }
        else
        {
            await runs.MarkRetryingAsync(runId, attempts: 1, nextAttemptAt: DateTime.UtcNow.Add(RetryBackoff.DelayFor(1)), lastError: result.Error ?? "unknown");
            await subs.RecordTickResultAsync(sub.Id, false, DateTime.UtcNow, nextRunAt, completed);
            _logger.LogWarning("Delivery failed for sub {Id} tick {N} mode={Mode}: {Err}",
                sub.Id, nextTickNumber, sub.PushMode, result.Error);
        }
    }

    // Extract optional agentAddress + baseUrl from the subscription's stored
    // requirement JSON. Tolerant: a non-object / malformed body yields (null,
    // null) and the caller records an empty tick. Only string-valued fields are
    // honoured.
    private static (string? agentAddress, string? baseUrl) ParseTarget(string requirementJson)
    {
        if (string.IsNullOrWhiteSpace(requirementJson)) return (null, null);
        try
        {
            using var doc = JsonDocument.Parse(requirementJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return (null, null);
            string? agent = null, url = null;
            if (doc.RootElement.TryGetProperty("agentAddress", out var a) && a.ValueKind == JsonValueKind.String)
                agent = a.GetString();
            if (doc.RootElement.TryGetProperty("baseUrl", out var b) && b.ValueKind == JsonValueKind.String)
                url = b.GetString();
            return (agent, url);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }

    // For inJobStream subs only: when the final tick succeeds, push one last
    // structured "stream complete" receipt AND close the ACP job via submit so
    // the on-chain lifecycle terminates cleanly. The submit body satisfies the
    // offering's declared deliverableSchema for indexers expecting one
    // canonical deliverable per job.
    private async Task FinaliseStreamAsync(
        Subscription sub,
        int finalTickNumber,
        InJobStreamDeliveryService streamDeliverer,
        CancellationToken ct)
    {
        var finalReceipt = new
        {
            subscriptionId = sub.Id,
            ticksDelivered = finalTickNumber,
            deliveredAt    = DateTime.UtcNow.ToString("O"),
            streamSummary  = new
            {
                ticksPurchased = sub.TicksPurchased,
                createdAt      = sub.CreatedAt.ToString("O"),
            }
        };
        var json = JsonSerializer.Serialize(finalReceipt);
        var finaliseResult = await streamDeliverer.FinaliseAsync(sub, json, ct);
        if (!finaliseResult.Ok)
        {
            // The job is logically done from the bot's perspective — the
            // subscription row is already marked completed. Finalise failure
            // (transport drop, sidecar restart mid-finalise) leaves the ACP
            // job in TRANSACTION state on-chain; it will expire naturally on
            // its expiredAt. Log loudly so the operator can intervene.
            _logger.LogWarning(
                "Finalise failed for inJobStream sub {Id} jobId={JobId} chainId={ChainId}: {Err}. Job will expire on-chain naturally.",
                sub.Id, sub.StreamJobId, sub.StreamChainId, finaliseResult.Error);
        }
    }
}
