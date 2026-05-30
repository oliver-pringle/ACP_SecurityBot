using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

public class TickExecutorTests
{
    private static async Task SeedSub(SubscriptionRepository repo, TickEchoRepository te, string id, string msg)
    {
        await repo.InsertAsync(new Subscription(
            id, $"job-{id}", "0x", "tick_echo", "{}", "https://x/cb", "sec",
            60, 5, 0, DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null,
            DateTime.UtcNow.AddSeconds(60), "active", 0,
            PushMode: "webhook", StreamChainId: null, StreamJobId: null));
        await te.InsertAsync(id, msg);
    }

    [Fact]
    public async Task Compute_tick_echo_returns_payload_with_message_and_tick_metadata()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var te = new TickEchoRepository(t.Db);
        await SeedSub(subs, te, "x", "ping");

        var executor = new TickExecutorService(te);
        var sub = (await subs.GetByIdAsync("x"))!;

        var json = await executor.ComputePayloadAsync(sub, tickNumber: 3);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("x", root.GetProperty("subscriptionId").GetString());
        Assert.Equal(3, root.GetProperty("tick").GetInt32());
        Assert.Equal(5, root.GetProperty("totalTicks").GetInt32());
        Assert.Equal("ping", root.GetProperty("message").GetString());
        Assert.True(root.TryGetProperty("deliveredAt", out _));
    }

    [Fact]
    public async Task Compute_unknown_offering_throws()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var executor = new TickExecutorService(new TickEchoRepository(t.Db));
        var sub = new Subscription(
            "x", "j", "0x", "unknown_offering", "{}", "https://x", "s",
            60, 5, 0, DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null,
            DateTime.UtcNow.AddSeconds(60), "active", 0,
            PushMode: "webhook", StreamChainId: null, StreamJobId: null);

        await Assert.ThrowsAsync<InvalidOperationException>(() => executor.ComputePayloadAsync(sub, 1));
    }

    // Audit F3 regression — TickExecutorService used to handle only "tick_echo".
    // SubscriptionService accepts BOTH "tick_echo" and "tick_stream_echo", so
    // every stream-mode subscription threw at compute time and ran forever as
    // a stuck row. Make sure both names route to the same payload shape.
    [Fact]
    public async Task Compute_tick_stream_echo_returns_payload_with_message_and_tick_metadata()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var te = new TickEchoRepository(t.Db);

        // Stream-mode sub: no webhook fields, has StreamChainId + StreamJobId.
        await subs.InsertAsync(new Subscription(
            "stream-x", "job-stream-x", "0x", "tick_stream_echo", "{}",
            WebhookUrl: null, WebhookSecret: null,
            IntervalSeconds: 60, TicksPurchased: 5, TicksDelivered: 0,
            CreatedAt: DateTime.UtcNow, ExpiresAt: DateTime.UtcNow.AddHours(1),
            LastRunAt: null, NextRunAt: DateTime.UtcNow.AddSeconds(60),
            Status: "active", ConsecutiveFailures: 0,
            PushMode: "inJobStream", StreamChainId: 8453, StreamJobId: "0xabc"));
        await te.InsertAsync("stream-x", "stream-message");

        var executor = new TickExecutorService(te);
        var sub = (await subs.GetByIdAsync("stream-x"))!;

        var json = await executor.ComputePayloadAsync(sub, tickNumber: 2);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("stream-x",       root.GetProperty("subscriptionId").GetString());
        Assert.Equal(2,                root.GetProperty("tick").GetInt32());
        Assert.Equal(5,                root.GetProperty("totalTicks").GetInt32());
        Assert.Equal("stream-message", root.GetProperty("message").GetString());
        Assert.True(root.TryGetProperty("deliveredAt", out _));
    }
}
