using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

// P60: configurable active-subscription quota (global + per-buyer), enforced
// BEFORE the first DB write in SubscriptionService.CreateAsync and mapped to
// HTTP 429 by the create-subscription route. These tests construct the service
// with an in-memory IConfiguration that sets the caps via the
// "Subscriptions:MaxActive*" cfg keys + ALLOW_INSECURE_WEBHOOKS=true so the
// `https://buyer.test/cb` webhook passes the SSRF guard in CI.
public class SubscriptionLimitTests
{
    private static IConfiguration Cfg(int? global = null, int? perBuyer = null)
    {
        var dict = new Dictionary<string, string?>
        {
            ["ALLOW_INSECURE_WEBHOOKS"] = "true",
        };
        if (global is not null)   dict["Subscriptions:MaxActiveGlobal"]   = global.Value.ToString();
        if (perBuyer is not null) dict["Subscriptions:MaxActivePerBuyer"] = perBuyer.Value.ToString();
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    private static CreateSubscriptionRequest Req(string buyer, string jobId)
        => new(
            JobId: jobId,
            BuyerAgent: buyer,
            OfferingName: "tick_echo",
            Requirement: new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["webhookUrl"]      = "https://buyer.test/cb",
                ["intervalSeconds"] = 60,
                ["ticks"]           = 1
            });

    [Fact]
    public async Task PerBuyer_cap_blocks_the_Nplus1th_create_for_that_buyer()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        // global high enough not to interfere; per-buyer cap = 2.
        var svc = new SubscriptionService(new SubscriptionRepository(t.Db), Cfg(global: 1000, perBuyer: 2));

        // First two creates succeed (proves the Req is valid).
        await svc.CreateAsync(Req("0xbuyerA", "jobA-1"));
        await svc.CreateAsync(Req("0xbuyerA", "jobA-2"));

        // Third (N+1) for the same buyer is blocked.
        var ex = await Assert.ThrowsAsync<SubscriptionLimitException>(
            () => svc.CreateAsync(Req("0xbuyerA", "jobA-3")));
        Assert.Contains("per-buyer", ex.Message);
    }

    [Fact]
    public async Task PerBuyer_cap_does_not_affect_a_different_buyer()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = new SubscriptionService(new SubscriptionRepository(t.Db), Cfg(global: 1000, perBuyer: 2));

        await svc.CreateAsync(Req("0xbuyerA", "jobA-1"));
        await svc.CreateAsync(Req("0xbuyerA", "jobA-2"));
        // buyerA is at its cap, but a DIFFERENT buyer is unaffected.
        var resp = await svc.CreateAsync(Req("0xbuyerB", "jobB-1"));
        Assert.False(string.IsNullOrEmpty(resp.SubscriptionId));
    }

    [Fact]
    public async Task PerBuyer_cap_counts_case_insensitively()
    {
        // EVM addresses are case-insensitive; an attacker must not bypass the
        // per-buyer cap by varying case. COLLATE NOCASE on CountActiveByBuyer.
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = new SubscriptionService(new SubscriptionRepository(t.Db), Cfg(global: 1000, perBuyer: 2));

        await svc.CreateAsync(Req("0xAbCdEf", "job-1"));
        await svc.CreateAsync(Req("0xabcdef", "job-2"));

        var ex = await Assert.ThrowsAsync<SubscriptionLimitException>(
            () => svc.CreateAsync(Req("0XABCDEF", "job-3")));
        Assert.Contains("per-buyer", ex.Message);
    }

    [Fact]
    public async Task Global_cap_blocks_the_Nplus1th_create_across_buyers()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        // global cap = 2; per-buyer high enough not to interfere.
        var svc = new SubscriptionService(new SubscriptionRepository(t.Db), Cfg(global: 2, perBuyer: 1000));

        await svc.CreateAsync(Req("0xbuyerA", "job-1"));
        await svc.CreateAsync(Req("0xbuyerB", "job-2"));

        // Third across ANY buyer hits the global cap.
        var ex = await Assert.ThrowsAsync<SubscriptionLimitException>(
            () => svc.CreateAsync(Req("0xbuyerC", "job-3")));
        Assert.Contains("global", ex.Message);
    }

    [Fact]
    public async Task Zero_cap_means_unlimited()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        // 0 = unlimited for both dimensions.
        var svc = new SubscriptionService(new SubscriptionRepository(t.Db), Cfg(global: 0, perBuyer: 0));

        for (int i = 0; i < 12; i++)
            await svc.CreateAsync(Req("0xbuyerA", $"job-{i}"));

        // No throw — all 12 (well past the default per-buyer 10 / global 500)
        // created because both caps are 0.
        var subs = new SubscriptionRepository(t.Db);
        Assert.Equal(12, await subs.CountActiveAsync());
    }
}
