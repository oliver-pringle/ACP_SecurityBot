using SecurityBot.Api.Engine;
using SecurityBot.Api.Workers;
using Xunit;

namespace SecurityBot.Tests;

public class WatchDiffTests
{
    private static Finding F(string id, Verdict v) => new(id, id, Severity.Medium, v, "e", id);

    [Fact]
    public void Diff_reports_newly_opened_findings()
    {
        var prev = new[] { F("P31", Verdict.Pass) };
        var curr = new[] { F("P31", Verdict.Present), F("P9", Verdict.Present) };
        var diff = WatchDiff.Compute(prev, curr);
        Assert.Contains("P31", diff.NewlyOpened);
        Assert.Contains("P9", diff.NewlyOpened);
    }

    [Fact]
    public void Diff_reports_newly_closed_findings()
    {
        var prev = new[] { F("P31", Verdict.Present) };
        var curr = new[] { F("P31", Verdict.Pass) };
        var diff = WatchDiff.Compute(prev, curr);
        Assert.Contains("P31", diff.NewlyClosed);
    }

    [Fact]
    public void Diff_is_empty_when_unchanged()
    {
        var prev = new[] { F("P31", Verdict.Present) };
        var curr = new[] { F("P31", Verdict.Present) };
        var diff = WatchDiff.Compute(prev, curr);
        Assert.Empty(diff.NewlyOpened);
        Assert.Empty(diff.NewlyClosed);
        Assert.False(diff.HasChanges);
    }
}
