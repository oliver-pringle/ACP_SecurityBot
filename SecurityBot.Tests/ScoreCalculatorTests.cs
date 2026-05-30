using SecurityBot.Api.Engine;
using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

public class ScoreCalculatorTests
{
    private static Finding F(Severity sev, Verdict v) =>
        new("PX", "t", sev, v, "e", "PX");

    [Fact]
    public void All_pass_scores_100_grade_A()
    {
        var (score, grade) = ScoreCalculator.Compute(new[]
        {
            F(Severity.High, Verdict.Pass),
            F(Severity.Low, Verdict.Pass),
        });
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }

    [Fact]
    public void NotObservable_and_NotApplicable_are_excluded_from_denominator()
    {
        var (score, _) = ScoreCalculator.Compute(new[]
        {
            F(Severity.High, Verdict.Pass),
            F(Severity.High, Verdict.NotObservable),
            F(Severity.Low, Verdict.NotApplicable),
        });
        Assert.Equal(100, score);
    }

    [Fact]
    public void A_present_high_severity_finding_drops_the_score_below_a_present_low()
    {
        var (highScore, _) = ScoreCalculator.Compute(new[] { F(Severity.High, Verdict.Present), F(Severity.Low, Verdict.Pass) });
        var (lowScore, _)  = ScoreCalculator.Compute(new[] { F(Severity.Low, Verdict.Present),  F(Severity.Low, Verdict.Pass) });
        Assert.True(highScore < lowScore);
    }

    [Fact]
    public void Compute_is_deterministic()
    {
        var fs = new[] { F(Severity.Medium, Verdict.Present), F(Severity.Low, Verdict.Pass) };
        Assert.Equal(ScoreCalculator.Compute(fs), ScoreCalculator.Compute(fs));
    }

    [Fact]
    public void No_observable_findings_scores_100_NA()
    {
        var (score, grade) = ScoreCalculator.Compute(new[] { F(Severity.High, Verdict.NotObservable) });
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }
}
