using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using Xunit;

namespace SecurityBot.Tests;

public class SubscriptionRunRepositoryTests
{
    private static async Task SeedSub(SubscriptionRepository repo, string id)
        => await repo.InsertAsync(new Subscription(
            id, $"job-{id}", "0x", "tick_echo", "{}", "https://x/cb", "sec",
            60, 5, 0, DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null,
            DateTime.UtcNow.AddSeconds(60), "active", 0,
            PushMode: "webhook", StreamChainId: null, StreamJobId: null));

    [Fact]
    public async Task Insert_then_query_returns_run()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var runs = new SubscriptionRunRepository(t.Db);
        await SeedSub(subs, "s1");

        var id = await runs.InsertPendingAsync("s1", tickNumber: 1, scheduledAt: DateTime.UtcNow, payloadJson: "{\"x\":1}");
        Assert.True(id > 0);

        var due = await runs.GetRetryDueAsync(DateTime.UtcNow.AddSeconds(60), limit: 10);
        Assert.Empty(due); // pending status, not retrying
    }

    [Fact]
    public async Task MarkDelivered_sets_status_and_records_time()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var runs = new SubscriptionRunRepository(t.Db);
        await SeedSub(subs, "s2");
        var id = await runs.InsertPendingAsync("s2", 1, DateTime.UtcNow, "{}");

        await runs.MarkDeliveredAsync(id, DateTime.UtcNow);
        var run = await runs.GetByIdAsync(id);
        Assert.Equal("delivered", run!.DeliveryStatus);
    }

    [Fact]
    public async Task MarkRetrying_schedules_next_attempt_and_appears_in_GetRetryDue()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var runs = new SubscriptionRunRepository(t.Db);
        await SeedSub(subs, "s3");
        var id = await runs.InsertPendingAsync("s3", 1, DateTime.UtcNow, "{}");

        var nextAttempt = DateTime.UtcNow.AddSeconds(-5); // already due
        await runs.MarkRetryingAsync(id, attempts: 1, nextAttemptAt: nextAttempt, lastError: "503");

        var due = await runs.GetRetryDueAsync(DateTime.UtcNow, limit: 10);
        Assert.Single(due);
        Assert.Equal(id, due[0].Id);
        Assert.Equal(1, due[0].Attempts);
    }

    [Fact]
    public async Task MarkDead_sets_status_dead_and_excludes_from_retry_due()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var runs = new SubscriptionRunRepository(t.Db);
        await SeedSub(subs, "s4");
        var id = await runs.InsertPendingAsync("s4", 1, DateTime.UtcNow, "{}");
        await runs.MarkRetryingAsync(id, 4, DateTime.UtcNow.AddSeconds(-5), "boom");

        await runs.MarkDeadAsync(id, attempts: 5, lastError: "max retries");
        var due = await runs.GetRetryDueAsync(DateTime.UtcNow, 10);
        Assert.Empty(due);

        var run = await runs.GetByIdAsync(id);
        Assert.Equal("dead", run!.DeliveryStatus);
    }
}
