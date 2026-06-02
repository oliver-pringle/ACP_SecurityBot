using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

// security_watch bind path. Unlike the boilerplate echo demo, security_watch
// carries a SCAN TARGET (agentAddress and/or baseUrl). The bind step must
// resolve that target to a concrete probeable baseUrl and persist it into the
// stored requirement, so WatchWorker.ParseTarget finds a baseUrl to re-scan
// each tick. An agent with no externally-auditable surface must be rejected at
// bind (before the DB write) rather than accepted into a sub that dead-ticks.
public class SecurityWatchSubscriptionTests
{
    private static IConfiguration InsecureConfig() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ALLOW_INSECURE_WEBHOOKS"] = "true" })
            .Build();

    private static CreateSubscriptionRequest WatchReq(
        string agentAddress = "0xecf9773b50f01f3a97b087a6ecdf12a71afc558c",
        string webhook = "https://buyer.test/cb",
        int interval = 3600,
        int ticks = 12)
        => new(
            JobId: "job-sw",
            BuyerAgent: "0xbuyer",
            OfferingName: "security_watch",
            Requirement: new Dictionary<string, object>
            {
                ["agentAddress"]    = agentAddress,
                ["webhookUrl"]      = webhook,
                ["intervalSeconds"] = interval,
                ["ticks"]           = ticks
            });

    [Fact]
    public async Task Create_security_watch_resolves_agentAddress_and_persists_baseUrl()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var resolver = FakeTargetResolver.Auditable("https://api.acp-metabot.dev/securitybot");
        var svc = new SubscriptionService(subs, resolver, InsecureConfig());

        var resp = await svc.CreateAsync(WatchReq());

        // The resolved baseUrl MUST be persisted into the stored requirement so
        // WatchWorker.ParseTarget has a probeable target every tick.
        var row = await subs.GetByIdAsync(resp.SubscriptionId);
        Assert.NotNull(row);
        Assert.Equal("security_watch", row!.OfferingName);
        using var doc = JsonDocument.Parse(row.RequirementJson);
        Assert.True(doc.RootElement.TryGetProperty("baseUrl", out var b), "requirement JSON must carry the resolved baseUrl");
        Assert.Equal("https://api.acp-metabot.dev/securitybot", b.GetString());

        // The resolver was invoked with the buyer's agentAddress.
        Assert.Equal(1, resolver.Calls);
        Assert.Equal("0xecf9773b50f01f3a97b087a6ecdf12a71afc558c", resolver.LastAgentAddress);
    }

    [Fact]
    public async Task Create_security_watch_rejects_unauditable_target_with_no_orphan_row()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var svc = new SubscriptionService(
            subs,
            FakeTargetResolver.NotAuditable("agent exposes no externally-auditable surface"),
            InsecureConfig());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(WatchReq()));
        Assert.Contains("auditable", ex.Message);

        // Fail-fast BEFORE the first DB write — no orphan subscription row.
        var due = await subs.GetDueAsync(DateTime.UtcNow.AddDays(365), limit: 100);
        Assert.Empty(due);
    }

    [Fact]
    public async Task Create_security_watch_honours_explicit_baseUrl()
    {
        // When the buyer supplies baseUrl directly, the resolver short-circuits
        // to it (ResolvedVia "baseUrl"); the bind still persists the normalised
        // baseUrl for the worker.
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var resolver = FakeTargetResolver.Auditable("https://target.example.com");
        var svc = new SubscriptionService(subs, resolver, InsecureConfig());

        var req = new CreateSubscriptionRequest(
            JobId: "job-sw2",
            BuyerAgent: "0xbuyer",
            OfferingName: "security_watch",
            Requirement: new Dictionary<string, object>
            {
                ["baseUrl"]         = "https://target.example.com/v1/resources/x",
                ["webhookUrl"]      = "https://buyer.test/cb",
                ["intervalSeconds"] = 3600,
                ["ticks"]           = 1
            });

        var resp = await svc.CreateAsync(req);
        var row = await subs.GetByIdAsync(resp.SubscriptionId);
        Assert.NotNull(row);
        using var doc = JsonDocument.Parse(row!.RequirementJson);
        Assert.Equal("https://target.example.com", doc.RootElement.GetProperty("baseUrl").GetString());
        Assert.Equal("https://target.example.com/v1/resources/x", resolver.LastBaseUrl);
    }
}
