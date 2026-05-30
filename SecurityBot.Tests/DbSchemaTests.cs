using SecurityBot.Api.Data;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

public class DbSchemaTests
{
    [Fact]
    public async Task InitializeSchema_creates_all_four_tables()
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
        Assert.Contains("tick_echo_state", names);
        Assert.Contains("echo_records", names);
    }

    [Fact]
    public async Task InitializeSchema_is_idempotent()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        await t.Db.InitializeSchemaAsync(); // second call must not throw
    }
}
