using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

public class SubscriptionServiceTests
{
    // ALLOW_INSECURE_WEBHOOKS=true bypasses the SSRF guard so tests can use
    // `https://buyer.test/cb` (doesn't resolve in CI). Production must leave it unset.
    private static IConfiguration InsecureConfig() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ALLOW_INSECURE_WEBHOOKS"] = "true" })
            .Build();

    private static SubscriptionService NewSvc(TestDb t) =>
        new(new SubscriptionRepository(t.Db), new TickEchoRepository(t.Db), InsecureConfig());

    private static CreateSubscriptionRequest TickEchoReq(int ticks, int interval, string webhook = "https://buyer.test/cb")
        => new(
            JobId: "job-x",
            BuyerAgent: "0xbuyer",
            OfferingName: "tick_echo",
            Requirement: new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["webhookUrl"]      = webhook,
                ["intervalSeconds"] = interval,
                ["ticks"]           = ticks
            }
        );

    [Fact]
    public async Task Create_tick_echo_inserts_subscription_and_state_and_returns_secret()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var resp = await svc.CreateAsync(TickEchoReq(ticks: 5, interval: 60));

        Assert.False(string.IsNullOrEmpty(resp.SubscriptionId));
        Assert.NotNull(resp.WebhookSecret);
        Assert.Equal(64, resp.WebhookSecret!.Length);  // 32 bytes hex = 64 chars
        Assert.Equal(5, resp.TicksPurchased);
        Assert.Equal(60, resp.IntervalSeconds);
        Assert.Equal("webhook", resp.PushMode);
    }

    [Fact]
    public async Task Create_persists_message_to_tick_echo_state()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var te = new TickEchoRepository(t.Db);
        var svc = new SubscriptionService(subs, te, InsecureConfig());

        var resp = await svc.CreateAsync(TickEchoReq(3, 60));
        var state = await te.GetAsync(resp.SubscriptionId);
        Assert.NotNull(state);
        Assert.Equal("ping", state!.Message);
    }

    [Fact]
    public async Task Create_rejects_unknown_offering()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var bad = new CreateSubscriptionRequest(
            "j", "0x", "unknown",
            new Dictionary<string, object>
            {
                ["webhookUrl"] = "https://x/cb",
                ["intervalSeconds"] = 60,
                ["ticks"] = 1
            });

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(bad));
    }

    [Fact]
    public async Task Create_unknown_offering_does_not_leave_orphan_row()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var svc = new SubscriptionService(subs, new TickEchoRepository(t.Db), InsecureConfig());

        var bad = new CreateSubscriptionRequest(
            "j", "0x", "unknown",
            new Dictionary<string, object>
            {
                ["webhookUrl"] = "https://x/cb",
                ["intervalSeconds"] = 60,
                ["ticks"] = 1
            });

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(bad));

        // Verify NO subscription rows were created
        var due = await subs.GetDueAsync(DateTime.UtcNow.AddDays(365), limit: 100);
        Assert.Empty(due);
    }

    // --- Bounds & SSRF coverage ---

    [Theory]
    [InlineData(59)]      // below MinIntervalSeconds
    [InlineData(86_401)]  // above MaxIntervalSeconds
    public async Task Create_rejects_interval_outside_bounds(int interval)
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.CreateAsync(TickEchoReq(ticks: 1, interval: interval)));
        Assert.Contains("intervalSeconds must be", ex.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10_001)]
    public async Task Create_rejects_ticks_outside_bounds(int ticks)
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.CreateAsync(TickEchoReq(ticks: ticks, interval: 60)));
        Assert.Contains("ticks must be", ex.Message);
    }

    [Fact]
    public async Task Create_rejects_window_beyond_90_days()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        // 86400s * 100 ticks = 100 days > MaxFutureWindow
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.CreateAsync(TickEchoReq(ticks: 100, interval: 86_400)));
        Assert.Contains("90 days", ex.Message);
    }

    [Theory]
    [InlineData("http://buyer.test/cb")]           // plain http with insecure NOT allowed
    [InlineData("https://127.0.0.1/cb")]           // loopback literal
    [InlineData("https://169.254.169.254/cb")]     // cloud metadata
    [InlineData("https://10.0.0.5/cb")]            // rfc1918
    [InlineData("https://192.168.1.1/cb")]         // rfc1918
    [InlineData("ftp://buyer.test/cb")]            // wrong scheme
    [InlineData("not-a-url")]                      // invalid uri
    public async Task Create_rejects_unsafe_webhook_url(string url)
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        // Force SSRF guard ON for this test by NOT passing the insecure config.
        var svc = new SubscriptionService(
            new SubscriptionRepository(t.Db),
            new TickEchoRepository(t.Db));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.CreateAsync(TickEchoReq(ticks: 1, interval: 60, webhook: url)));
    }

    // ---------------- inJobStream PushMode coverage ----------------

    private static CreateSubscriptionRequest TickStreamReq(
        int ticks, int interval,
        int? streamChainId = 84532,
        string? streamJobId = "12345")
        => new(
            JobId: "job-x",
            BuyerAgent: "0xbuyer",
            OfferingName: "tick_stream_echo",
            Requirement: new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["intervalSeconds"] = interval,
                ["ticks"]           = ticks
            },
            PushMode: "inJobStream",
            StreamChainId: streamChainId,
            StreamJobId: streamJobId
        );

    [Fact]
    public async Task Create_inJobStream_omits_webhook_secret_and_returns_pushMode()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var resp = await svc.CreateAsync(TickStreamReq(ticks: 5, interval: 60));

        Assert.False(string.IsNullOrEmpty(resp.SubscriptionId));
        Assert.Null(resp.WebhookSecret);
        Assert.Equal("inJobStream", resp.PushMode);
        Assert.Equal(5, resp.TicksPurchased);
    }

    [Fact]
    public async Task Create_inJobStream_persists_chainId_and_jobId_on_row()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var subs = new SubscriptionRepository(t.Db);
        var svc = new SubscriptionService(subs, new TickEchoRepository(t.Db), InsecureConfig());

        var resp = await svc.CreateAsync(TickStreamReq(ticks: 3, interval: 60, streamChainId: 8453, streamJobId: "0xabc"));
        var row = await subs.GetByIdAsync(resp.SubscriptionId);

        Assert.NotNull(row);
        Assert.Equal("inJobStream", row!.PushMode);
        Assert.Equal(8453, row.StreamChainId);
        Assert.Equal("0xabc", row.StreamJobId);
        Assert.Null(row.WebhookUrl);
        Assert.Null(row.WebhookSecret);
    }

    [Fact]
    public async Task Create_inJobStream_does_not_require_webhookUrl_in_requirement()
    {
        // The schema for tick_stream_echo doesn't even ask for webhookUrl — confirm
        // SubscriptionService accepts the request without one.
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var resp = await svc.CreateAsync(TickStreamReq(ticks: 1, interval: 60));
        Assert.Equal("inJobStream", resp.PushMode);
    }

    [Fact]
    public async Task Create_inJobStream_requires_streamChainId()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var bad = TickStreamReq(ticks: 1, interval: 60, streamChainId: null);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(bad));
        Assert.Contains("streamChainId", ex.Message);
    }

    [Fact]
    public async Task Create_inJobStream_requires_streamJobId()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var bad = TickStreamReq(ticks: 1, interval: 60, streamJobId: "");
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(bad));
        Assert.Contains("streamJobId", ex.Message);
    }

    [Fact]
    public async Task Create_inJobStream_enforces_4hr_window_cap_not_90day()
    {
        // 60s × 300 = 18000s = 5h > MaxStreamWindow(4h) but < MaxFutureWindow(90d)
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.CreateAsync(TickStreamReq(ticks: 300, interval: 60)));
        Assert.Contains("inJobStream cap", ex.Message);
    }

    [Fact]
    public async Task Create_rejects_unknown_pushMode()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var bad = new CreateSubscriptionRequest(
            "job-x", "0xbuyer", "tick_echo",
            new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["webhookUrl"]      = "https://x/cb",
                ["intervalSeconds"] = 60,
                ["ticks"]           = 1
            },
            PushMode: "bogus");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(bad));
        Assert.Contains("pushMode", ex.Message);
    }

    [Fact]
    public async Task Create_tick_echo_with_null_pushMode_defaults_to_webhook()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var resp = await svc.CreateAsync(TickEchoReq(ticks: 1, interval: 60));
        Assert.Equal("webhook", resp.PushMode);
        Assert.NotNull(resp.WebhookSecret);
    }

    // ---------------- F9 field length caps ----------------

    [Fact]
    public async Task Create_rejects_overlong_jobId()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var req = new CreateSubscriptionRequest(
            JobId: new string('j', SubscriptionService.MaxJobIdLength + 1),
            BuyerAgent: "0xbuyer",
            OfferingName: "tick_echo",
            Requirement: new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["webhookUrl"]      = "https://buyer.test/cb",
                ["intervalSeconds"] = 60,
                ["ticks"]           = 1
            });
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(req));
        Assert.Contains("jobId", ex.Message);
    }

    [Fact]
    public async Task Create_rejects_overlong_buyerAgent()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var req = new CreateSubscriptionRequest(
            JobId: "job-x",
            BuyerAgent: new string('b', SubscriptionService.MaxBuyerAgentLength + 1),
            OfferingName: "tick_echo",
            Requirement: new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["webhookUrl"]      = "https://buyer.test/cb",
                ["intervalSeconds"] = 60,
                ["ticks"]           = 1
            });
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(req));
        Assert.Contains("buyerAgent", ex.Message);
    }

    [Fact]
    public async Task Create_rejects_overlong_offeringName()
    {
        // Caught BEFORE the known-offering whitelist check so the error
        // surfaces as the cap violation, not "unknown offering".
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var req = new CreateSubscriptionRequest(
            JobId: "job-x",
            BuyerAgent: "0xbuyer",
            OfferingName: new string('o', SubscriptionService.MaxOfferingNameLength + 1),
            Requirement: new Dictionary<string, object>
            {
                ["message"]         = "ping",
                ["webhookUrl"]      = "https://buyer.test/cb",
                ["intervalSeconds"] = 60,
                ["ticks"]           = 1
            });
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(req));
        Assert.Contains("offeringName", ex.Message);
    }

    [Fact]
    public async Task Create_rejects_overlong_streamJobId()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var bad = TickStreamReq(
            ticks: 1, interval: 60,
            streamChainId: 8453,
            streamJobId: new string('s', SubscriptionService.MaxStreamJobIdLength + 1));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(bad));
        Assert.Contains("streamJobId", ex.Message);
    }

    [Fact]
    public async Task Create_rejects_overlong_webhookUrl()
    {
        // The cap (2048) is well below Kestrel's body limit so build a URL
        // just over the field cap.
        var longUrl = "https://buyer.example/" + new string('a', SubscriptionService.MaxWebhookUrlLength);
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var svc = NewSvc(t);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.CreateAsync(TickEchoReq(ticks: 1, interval: 60, webhook: longUrl)));
        Assert.Contains("webhookUrl", ex.Message);
    }
}
