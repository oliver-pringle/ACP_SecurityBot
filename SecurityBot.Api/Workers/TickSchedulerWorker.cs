using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Services;

namespace SecurityBot.Api.Workers;

public class TickSchedulerWorker : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);
    private const int BatchSize = 100;
    private const int MaxConcurrent = 8;

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<TickSchedulerWorker> _logger;

    public TickSchedulerWorker(IServiceScopeFactory scopes, ILogger<TickSchedulerWorker> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("TickSchedulerWorker started, polling every {Interval}", PollInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await TickOnceAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "TickScheduler tick failed; continuing"); }
            try { await Task.Delay(PollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task TickOnceAsync(CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var subs = scope.ServiceProvider.GetRequiredService<SubscriptionRepository>();
        var runs = scope.ServiceProvider.GetRequiredService<SubscriptionRunRepository>();
        // TODO Task 9: replace TickExecutorService with the security-scan payload
        // compute (WatchWorker re-scan + diff). TickExecutorService was the echo
        // demo's per-tick payload producer and was deleted with the demo domain.
        // This worker is no longer registered in Program.cs (see TODO Task 9
        // there); the body is kept compiling so Task 9 can repurpose it in place.
        var webhookDeliverer = scope.ServiceProvider.GetRequiredService<WebhookDeliveryService>();
        var streamDeliverer = scope.ServiceProvider.GetRequiredService<InJobStreamDeliveryService>();

        var due = await subs.GetDueAsync(DateTime.UtcNow, BatchSize);
        if (due.Count == 0) return;
        _logger.LogInformation("Tick batch: {Count} due subscriptions", due.Count);

        var sem = new SemaphoreSlim(MaxConcurrent);
        var tasks = due.Select(async sub =>
        {
            await sem.WaitAsync(ct);
            try { await ProcessSubscriptionAsync(sub, runs, subs, webhookDeliverer, streamDeliverer, ct); }
            finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
    }

    private async Task ProcessSubscriptionAsync(
        Models.Subscription sub,
        SubscriptionRunRepository runs,
        SubscriptionRepository subs,
        WebhookDeliveryService webhookDeliverer,
        InJobStreamDeliveryService streamDeliverer,
        CancellationToken ct)
    {
        var nextTickNumber = sub.TicksDelivered + 1;
        // TODO Task 9: compute the real per-tick security-scan payload here.
        // The echo demo's TickExecutorService.ComputePayloadAsync was deleted
        // with the demo domain; emit an empty JSON object so the kept delivery
        // plumbing still compiles and round-trips until Task 9 wires the scan.
        string payload = "{}";

        var runId = await runs.InsertPendingAsync(sub.Id, nextTickNumber, DateTime.UtcNow, payload);

        DeliveryResult result = sub.PushMode switch
        {
            "inJobStream" => await streamDeliverer.PushAsync(sub, nextTickNumber, payload, ct),
            _             => await webhookDeliverer.DeliverAsync(sub, nextTickNumber, payload, ct),
        };

        var nextRunAt = DateTime.UtcNow.AddSeconds(sub.IntervalSeconds);
        var completed = nextTickNumber >= sub.TicksPurchased;

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

    // For inJobStream subs only: when the final tick succeeds, push one last
    // structured "stream complete" receipt AND close the ACP job via submit so
    // the on-chain lifecycle terminates cleanly. The submit body satisfies the
    // offering's declared deliverableSchema for indexers expecting one
    // canonical deliverable per job.
    private async Task FinaliseStreamAsync(
        Models.Subscription sub,
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
