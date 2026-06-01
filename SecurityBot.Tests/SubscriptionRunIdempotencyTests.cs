using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using Xunit;

namespace SecurityBot.Tests;

// Audit (P59 clone-backport): the scheduler/retry path can re-enter the same
// (subscription_id, tick_number) — a single-replica re-poll after a partial
// crash, or a retry that re-derives the same tick. A plain INSERT throws on the
// UNIQUE(subscription_id, tick_number) constraint and the worker tick dies;
// last_insert_rowid() also returns 0/stale on an ignored insert. The fix makes
// InsertPendingAsync idempotent: INSERT OR IGNORE + explicit SELECT id by
// (sub,tick), so a duplicate returns the original run id.
public class SubscriptionRunIdempotencyTests
{
    private static async Task SeedSub(SubscriptionRepository repo, string id)
        => await repo.InsertAsync(new Subscription(
            id, $"job-{id}", "0x", "security_watch", "{}", "https://x/cb", "sec",
            60, 5, 0, DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null,
            DateTime.UtcNow.AddSeconds(60), "active", 0,
            PushMode: "webhook", StreamChainId: null, StreamJobId: null));

    [Fact]
    public async Task InsertPending_is_idempotent_on_duplicate_sub_tick()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var runs = new SubscriptionRunRepository(t.Db);
        await SeedSub(subs, "s1");

        var id1 = await runs.InsertPendingAsync("s1", 1, DateTime.UtcNow, "{}");
        var id2 = await runs.InsertPendingAsync("s1", 1, DateTime.UtcNow, "{}");

        Assert.True(id1 > 0);
        Assert.Equal(id1, id2);
    }

    [Fact]
    public async Task Distinct_ticks_get_distinct_run_ids()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var runs = new SubscriptionRunRepository(t.Db);
        await SeedSub(subs, "s1");

        var id1 = await runs.InsertPendingAsync("s1", 1, DateTime.UtcNow, "{}");
        var id2 = await runs.InsertPendingAsync("s1", 2, DateTime.UtcNow, "{}");

        Assert.NotEqual(id1, id2);
    }
}
