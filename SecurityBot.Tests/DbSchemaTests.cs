using SecurityBot.Api.Data;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

public class DbSchemaTests
{
    [Fact]
    public async Task InitializeSchema_creates_subscription_tables()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();

        var names = new HashSet<string>();
        await using var conn = t.Db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            names.Add(reader.GetString(0));
        }

        Assert.Contains("subscriptions", names);
        Assert.Contains("subscription_runs", names);
    }

    [Fact]
    public async Task InitializeSchema_is_idempotent()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        await t.Db.InitializeSchemaAsync(); // second call must not throw
    }

    [Fact]
    public async Task InitializeSchema_creates_scan_tables()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var names = new HashSet<string>();
        await using var conn = t.Db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table'";
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync()) names.Add(reader.GetString(0));
        Assert.Contains("scans", names);
        Assert.Contains("scan_findings", names);
        Assert.Contains("email_log", names);
    }
}
