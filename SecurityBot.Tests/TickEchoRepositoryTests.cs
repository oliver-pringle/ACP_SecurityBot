using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using Xunit;

namespace SecurityBot.Tests;

public class TickEchoRepositoryTests
{
    private static async Task SeedSub(SubscriptionRepository repo, string id)
        => await repo.InsertAsync(new Subscription(
            id, $"job-{id}", "0x", "tick_echo", "{}", "https://x/cb", "sec",
            60, 5, 0, DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null,
            DateTime.UtcNow.AddSeconds(60), "active", 0,
            PushMode: "webhook", StreamChainId: null, StreamJobId: null));

    [Fact]
    public async Task Insert_then_get_returns_state()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var repo = new TickEchoRepository(t.Db);
        await SeedSub(subs, "te-1");

        await repo.InsertAsync("te-1", "ping");
        var s = await repo.GetAsync("te-1");

        Assert.NotNull(s);
        Assert.Equal("ping", s!.Message);
    }

    [Fact]
    public async Task Get_missing_returns_null()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new TickEchoRepository(t.Db);
        Assert.Null(await repo.GetAsync("nope"));
    }
}
