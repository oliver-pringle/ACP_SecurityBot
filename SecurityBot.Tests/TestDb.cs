using SecurityBot.Api.Data;
using Microsoft.Extensions.Configuration;

namespace SecurityBot.Tests;

public sealed class TestDb : IAsyncDisposable
{
    public Db Db { get; }
    private readonly string _path;

    private TestDb(Db db, string path)
    {
        Db = db;
        _path = path;
    }

    public static TestDb New()
    {
        var path = Path.Combine(Path.GetTempPath(), $"bsb-test-{Guid.NewGuid():N}.db");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Sqlite"] = $"Data Source={path};Cache=Shared"
            })
            .Build();
        return new TestDb(new Db(config), path);
    }

    public ValueTask DisposeAsync()
    {
        try { File.Delete(_path); } catch { /* test cleanup; ignore */ }
        return ValueTask.CompletedTask;
    }
}
