using SecurityBot.Api.Data;
using Xunit;

namespace SecurityBot.Tests;

public class EchoRepositoryTests
{
    [Fact]
    public async Task Insert_then_get_returns_record()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new EchoRepository(t.Db);

        var inserted = await repo.InsertAsync("hello");
        var fetched = await repo.GetAsync(inserted.Id);

        Assert.NotNull(fetched);
        Assert.Equal("hello", fetched!.Message);
        Assert.Equal(inserted.Id, fetched.Id);
    }

    [Fact]
    public async Task Get_missing_returns_null()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new EchoRepository(t.Db);

        Assert.Null(await repo.GetAsync(999));
    }
}
