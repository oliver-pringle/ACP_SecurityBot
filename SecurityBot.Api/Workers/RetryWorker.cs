using SecurityBot.Api.Data;
using SecurityBot.Api.Services;

namespace SecurityBot.Api.Workers;

public class RetryWorker : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private const int BatchSize = 100;
    private const int MaxConcurrent = 8;

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<RetryWorker> _logger;

    public RetryWorker(IServiceScopeFactory scopes, ILogger<RetryWorker> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("RetryWorker started, polling every {Interval}", PollInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await TickOnceAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "RetryWorker tick failed; continuing"); }
            try { await Task.Delay(PollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task TickOnceAsync(CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var runs = scope.ServiceProvider.GetRequiredService<SubscriptionRunRepository>();
        var subs = scope.ServiceProvider.GetRequiredService<SubscriptionRepository>();
        var webhookDeliverer = scope.ServiceProvider.GetRequiredService<WebhookDeliveryService>();
        var streamDeliverer = scope.ServiceProvider.GetRequiredService<InJobStreamDeliveryService>();

        var due = await runs.GetRetryDueAsync(DateTime.UtcNow, BatchSize);
        if (due.Count == 0) return;
        _logger.LogInformation("Retry batch: {Count} due runs", due.Count);

        var sem = new SemaphoreSlim(MaxConcurrent);
        var tasks = due.Select(async run =>
        {
            await sem.WaitAsync(ct);
            try { await ProcessRunAsync(run, runs, subs, webhookDeliverer, streamDeliverer, ct); }
            finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
    }

    private async Task ProcessRunAsync(
        Models.SubscriptionRun run,
        SubscriptionRunRepository runs,
        SubscriptionRepository subs,
        WebhookDeliveryService webhookDeliverer,
        InJobStreamDeliveryService streamDeliverer,
        CancellationToken ct)
    {
        var sub = await subs.GetByIdAsync(run.SubscriptionId);
        if (sub is null || sub.Status == "suspended")
        {
            // Don't retry against suspended subs; mark dead so they fall out of the queue
            await runs.MarkDeadAsync(run.Id, run.Attempts, "subscription suspended or missing");
            return;
        }

        DeliveryResult result = sub.PushMode switch
        {
            "inJobStream" => await streamDeliverer.PushAsync(sub, run.TickNumber, run.PayloadJson, ct),
            _             => await webhookDeliverer.DeliverAsync(sub, run.TickNumber, run.PayloadJson, ct),
        };

        if (result.Ok)
        {
            await runs.MarkDeliveredAsync(run.Id, DateTime.UtcNow);
            await subs.ResetConsecutiveFailuresAsync(sub.Id);
            return;
        }

        var nextAttempts = run.Attempts + 1;
        if (RetryBackoff.IsExhausted(nextAttempts))
        {
            await runs.MarkDeadAsync(run.Id, nextAttempts, result.Error ?? "max retries");
            _logger.LogWarning("Run {Id} for sub {Sub} mode={Mode} dead-lettered after {N} attempts",
                run.Id, sub.Id, sub.PushMode, nextAttempts);
        }
        else
        {
            await runs.MarkRetryingAsync(run.Id, nextAttempts, DateTime.UtcNow.Add(RetryBackoff.DelayFor(nextAttempts)), result.Error ?? "unknown");
        }
    }
}
