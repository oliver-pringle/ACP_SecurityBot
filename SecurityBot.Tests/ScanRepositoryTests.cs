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

    [Fact]
    public async Task GetMostRecentFindings_hydrates_findings_of_latest_scan()
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
        await repo.InsertAsync(rec, findings);

        var got = await repo.GetMostRecentFindingsAsync("0xabc", "https://x.example");
        Assert.Equal(2, got.Count);
        var p31 = Assert.Single(got, f => f.PatternId == "P31");
        Assert.Equal(Verdict.Present, p31.Verdict);
        Assert.Equal(Severity.Low, p31.Severity);
        Assert.Equal("no CSP", p31.Evidence);
        var p9 = Assert.Single(got, f => f.PatternId == "P9");
        Assert.Equal(Verdict.Pass, p9.Verdict);
        Assert.Equal(Severity.High, p9.Severity);
        Assert.Equal("clean", p9.Evidence);
    }

    [Fact]
    public async Task GetMostRecentFindings_falls_back_to_base_url_when_agent_null()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new ScanRepository(t.Db);

        var findings = new[]
        {
            new Finding("P10", "Raw dump", Severity.Medium, Verdict.Partial, "leaks", "P10"),
        };
        var rec = new ScanRecord(
            AgentAddress: null,
            BaseUrl: "https://noagent.example",
            ResolvedVia: "baseUrl",
            Score: 70, Grade: "C",
            ObservableCount: 1, FindingCount: 1,
            Verdict: "AUDITED",
            CorpusVersion: "2026-05-30",
            ScannedAtUtc: DateTime.UtcNow);
        await repo.InsertAsync(rec, findings);

        var got = await repo.GetMostRecentFindingsAsync(null, "https://noagent.example");
        var only = Assert.Single(got);
        Assert.Equal("P10", only.PatternId);
        Assert.Equal(Verdict.Partial, only.Verdict);
    }

    [Fact]
    public async Task GetMostRecentFindings_returns_empty_when_no_prior_scan()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new ScanRepository(t.Db);
        var got = await repo.GetMostRecentFindingsAsync("0xnone", "https://never.example");
        Assert.Empty(got);
    }
}
