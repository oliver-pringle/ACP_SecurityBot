using SecurityBot.Api.Data;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Models;
using Xunit;

namespace SecurityBot.Tests;

public class ScanRepositoryTests
{
    [Fact]
    public async Task Insert_then_GetMostRecent_round_trips_scan_and_findings()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new ScanRepository(t.Db);

        var findings = new[]
        {
            new Finding("P31", "Missing headers", Severity.Low, Verdict.Present, "no CSP", "P31"),
            new Finding("P9", "Disclosure", Severity.High, Verdict.Pass, "clean", "P9"),
        };
        var rec = new ScanRecord(
            AgentAddress: "0xabc",
            BaseUrl: "https://x.example",
            ResolvedVia: "baseUrl",
            Score: 82, Grade: "B",
            ObservableCount: 2, FindingCount: 2,
            Verdict: "AUDITED",
            CorpusVersion: "2026-05-30",
            ScannedAtUtc: DateTime.UtcNow);

        var id = await repo.InsertAsync(rec, findings);
        Assert.True(id > 0);

        var got = await repo.GetMostRecentByAgentAsync("0xabc");
        Assert.NotNull(got);
        Assert.Equal(82, got!.Score);
        Assert.Equal("B", got.Grade);
        Assert.Equal(2, got.FindingCount);
    }

    [Fact]
    public async Task GetMostRecentByAgent_returns_null_when_absent()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new ScanRepository(t.Db);
        Assert.Null(await repo.GetMostRecentByAgentAsync("0xnope"));
    }
}
