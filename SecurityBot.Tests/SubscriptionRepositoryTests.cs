using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

public class SubscriptionRepositoryTests
{
    private static Subscription Sample(string id, DateTime nextRun, string status = "active")
        => new(
            Id: id,
            JobId: $"job-{id}",
            BuyerAgent: "0xbuyer",
            OfferingName: "tick_echo",
            RequirementJson: "{}",
            WebhookUrl: "https://buyer.test/cb",
            WebhookSecret: "deadbeef",
            IntervalSeconds: 60,
            TicksPurchased: 5,
            TicksDelivered: 0,
            CreatedAt: DateTime.UtcNow,
            ExpiresAt: DateTime.UtcNow.AddHours(1),
            LastRunAt: null,
            NextRunAt: nextRun,
            Status: status,
            ConsecutiveFailures: 0,
            PushMode: "webhook",
            StreamChainId: null,
            StreamJobId: null
        );

    [Fact]
    public async Task Insert_then_get_returns_subscription()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);

        var s = Sample("sub-1", DateTime.UtcNow.AddSeconds(60));
        await repo.InsertAsync(s);

        var fetched = await repo.GetByIdAsync("sub-1");
        Assert.NotNull(fetched);
        Assert.Equal("0xbuyer", fetched!.BuyerAgent);
        Assert.Equal(5, fetched.TicksPurchased);
    }

    [Fact]
    public async Task GetDue_returns_only_active_with_past_next_run()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);

        await repo.InsertAsync(Sample("due-active", DateTime.UtcNow.AddSeconds(-10), "active"));
        await repo.InsertAsync(Sample("not-due", DateTime.UtcNow.AddSeconds(60), "active"));
        await repo.InsertAsync(Sample("suspended", DateTime.UtcNow.AddSeconds(-10), "suspended"));

        var due = await repo.GetDueAsync(DateTime.UtcNow, limit: 10);
        Assert.Single(due);
        Assert.Equal("due-active", due[0].Id);
    }

    [Fact]
    public async Task RecordTickResult_advances_ticks_and_resets_failures_on_success()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);

        var s = Sample("sub-2", DateTime.UtcNow.AddSeconds(-1));
        await repo.InsertAsync(s);

        var nextRun = DateTime.UtcNow.AddSeconds(60);
        await repo.RecordTickResultAsync("sub-2", succeeded: true, lastRunAt: DateTime.UtcNow, nextRunAt: nextRun, completedSubscription: false);

        var f = await repo.GetByIdAsync("sub-2");
        Assert.Equal(1, f!.TicksDelivered);
        Assert.Equal(0, f.ConsecutiveFailures);
        Assert.Equal("active", f.Status);
    }

    [Fact]
    public async Task RecordTickResult_marks_completed_when_completedSubscription_true()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);

        await repo.InsertAsync(Sample("sub-3", DateTime.UtcNow.AddSeconds(-1)) with { TicksPurchased = 1 });
        await repo.RecordTickResultAsync("sub-3", succeeded: true, lastRunAt: DateTime.UtcNow, nextRunAt: DateTime.UtcNow.AddSeconds(60), completedSubscription: true);

        var f = await repo.GetByIdAsync("sub-3");
        Assert.Equal("completed", f!.Status);
    }

    [Fact]
    public async Task RecordTickResult_increments_failures_on_failure_and_can_suspend()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);

        await repo.InsertAsync(Sample("sub-4", DateTime.UtcNow.AddSeconds(-1)));

        await repo.RecordTickResultAsync("sub-4", false, DateTime.UtcNow, DateTime.UtcNow.AddSeconds(60), false);
        var after1 = await repo.GetByIdAsync("sub-4");
        Assert.Equal(1, after1!.ConsecutiveFailures);
        Assert.Equal("active", after1.Status);

        await repo.RecordTickResultAsync("sub-4", false, DateTime.UtcNow, DateTime.UtcNow.AddSeconds(60), false);
        await repo.RecordTickResultAsync("sub-4", false, DateTime.UtcNow, DateTime.UtcNow.AddSeconds(60), false);
        var after3 = await repo.GetByIdAsync("sub-4");
        Assert.Equal(3, after3!.ConsecutiveFailures);
        Assert.Equal("suspended", after3.Status);
    }

    [Fact]
    public async Task ResetConsecutiveFailures_zeros_the_counter()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);

        await repo.InsertAsync(Sample("sub-5", DateTime.UtcNow.AddSeconds(60)));
        await repo.RecordTickResultAsync("sub-5", false, DateTime.UtcNow, DateTime.UtcNow.AddSeconds(60), false);
        await repo.ResetConsecutiveFailuresAsync("sub-5");

        var f = await repo.GetByIdAsync("sub-5");
        Assert.Equal(0, f!.ConsecutiveFailures);
    }

    // ---------------- F3 webhook secret encryption at rest ----------------

    private static WebhookSecretCipher CipherWithKey()
    {
        var key = Convert.ToBase64String(new byte[32]
        {
            0x9b,0x71,0x4e,0x33,0xfa,0x21,0x18,0x4d,
            0x7e,0xca,0x60,0x05,0x29,0xab,0x9d,0x10,
            0x6c,0x88,0x4d,0x9f,0xb0,0x4c,0x33,0x07,
            0x12,0xff,0xa0,0x6e,0x55,0x1c,0xea,0x42
        });
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["WebhookSecretEncryptionKey"] = key })
            .Build();
        return new WebhookSecretCipher(cfg);
    }

    [Fact]
    public async Task Insert_with_cipher_encrypts_webhook_secret_on_disk_and_decrypts_on_read()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var cipher = CipherWithKey();
        var repo = new SubscriptionRepository(t.Db, cipher);

        await repo.InsertAsync(Sample("sub-enc", DateTime.UtcNow.AddSeconds(60)));

        // Disk shape: row contains the v1: envelope, NOT the plaintext.
        await using (var conn = t.Db.OpenConnection())
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT webhook_secret FROM subscriptions WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", "sub-enc");
            var stored = (string?)await cmd.ExecuteScalarAsync();
            Assert.NotNull(stored);
            Assert.StartsWith("v1:", stored);
            Assert.DoesNotContain("deadbeef", stored, StringComparison.Ordinal);
        }

        // Read shape: repo decrypts transparently — caller sees the original
        // plaintext "deadbeef" from the Sample() fixture.
        var fetched = await repo.GetByIdAsync("sub-enc");
        Assert.Equal("deadbeef", fetched!.WebhookSecret);
    }

    [Fact]
    public async Task Read_passes_through_legacy_plaintext_row_when_cipher_enabled()
    {
        // Lazy-migration contract: a row inserted without the cipher (legacy
        // plaintext on disk) must be readable verbatim once the cipher is
        // enabled, until a write re-encrypts it.
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var noCipherRepo = new SubscriptionRepository(t.Db);
        await noCipherRepo.InsertAsync(Sample("sub-legacy", DateTime.UtcNow.AddSeconds(60)));

        // Verify the row is on disk as plaintext.
        await using (var conn = t.Db.OpenConnection())
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT webhook_secret FROM subscriptions WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", "sub-legacy");
            var stored = (string?)await cmd.ExecuteScalarAsync();
            Assert.Equal("deadbeef", stored);
        }

        // Read through the cipher repo: legacy plaintext passes through.
        var cipherRepo = new SubscriptionRepository(t.Db, CipherWithKey());
        var fetched = await cipherRepo.GetByIdAsync("sub-legacy");
        Assert.Equal("deadbeef", fetched!.WebhookSecret);
    }

    [Fact]
    public async Task Insert_without_cipher_writes_plaintext_for_dev_compat()
    {
        // The no-arg legacy constructor (used by tests / dev clones) writes
        // plaintext. Tests covered everywhere else; this just locks the
        // contract so a refactor that flips the default behaviour gets caught.
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new SubscriptionRepository(t.Db);
        await repo.InsertAsync(Sample("sub-plain", DateTime.UtcNow.AddSeconds(60)));

        await using var conn = t.Db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT webhook_secret FROM subscriptions WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", "sub-plain");
        var stored = (string?)await cmd.ExecuteScalarAsync();
        Assert.Equal("deadbeef", stored);
    }
}
