using SecurityBot.Api.Engine;
using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

public class ScoreCalculatorTests
{
    private static Finding F(Severity sev, Verdict v) =>
        new("PX", "t", sev, v, "e", "PX");

    private static Finding F(string patternId, Severity sev, Verdict v) =>
        new(patternId, "t", sev, v, "e", patternId);

    [Fact]
    public void All_pass_scores_100_grade_A()
    {
        // 8+ observable checks with auth passing → coverage high, grade A allowed
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass), // auth check passes
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        Assert.Equal(100, result.Score);
        Assert.Equal("A", result.Grade);
        Assert.Equal(CoverageBand.High, result.Coverage);
    }

    [Fact]
    public void NotObservable_non_auth_excluded_from_denominator()
    {
        // Non-auth NotObservable checks are excluded from scoring
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass), // auth passes
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.NotObservable), // excluded
            F("P43", Severity.Low, Verdict.NotApplicable), // excluded
        });
        Assert.Equal(100, result.Score);
        Assert.Equal(6, result.AuditedPatternIds.Count);
    }

    [Fact]
    public void A_present_high_severity_finding_drops_the_score_below_a_present_low()
    {
        // With 8 observable checks each (passing auth + extras), compare High vs Low Present
        var highResult = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.High, Verdict.Present), // High Present
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        var lowResult = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Low, Verdict.Present), // Low Present
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        Assert.True(highResult.Score < lowResult.Score);
    }

    [Fact]
    public void Compute_is_deterministic()
    {
        var fs = new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Medium, Verdict.Present),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
        };
        var r1 = ScoreCalculator.Compute(fs);
        var r2 = ScoreCalculator.Compute(fs);
        Assert.Equal(r1.Score, r2.Score);
        Assert.Equal(r1.Grade, r2.Grade);
        Assert.Equal(r1.Coverage, r2.Coverage);
    }

    // === NEW TESTS: R19 §2 recalibration ===

    [Fact]
    public void Auth_NotObservable_applies_half_weight_penalty()
    {
        // When auth check (P1/P18) is NotObservable, it should apply a half-weight
        // penalty instead of being excluded — so score drops and coverage is low.
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.NotObservable), // auth NOT observable
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        // Half of High (25) = 12.5, rounded penalty means score < 100
        Assert.True(result.Score < 100, "Auth NotObservable should penalize score");
        Assert.Equal(CoverageBand.Low, result.Coverage);
    }

    [Fact]
    public void Auth_NotObservable_caps_grade_at_C()
    {
        // Even with good passes elsewhere, auth NotObservable caps grade at C
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.NotObservable),
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        // Grade should be capped at C due to low coverage (auth NotObservable)
        Assert.True(result.Grade is "C" or "D" or "F",
            $"Expected grade C or worse due to auth NotObservable, got {result.Grade}");
    }

    [Fact]
    public void Low_observable_count_caps_grade_at_C()
    {
        // Fewer than 6 observable checks caps grade at C even if all pass
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            // Only 5 observable — below threshold of 6
        });
        Assert.Equal(CoverageBand.Low, result.Coverage);
        Assert.True(result.Grade is "C" or "D" or "F",
            $"Expected grade C or worse due to low coverage, got {result.Grade}");
    }

    [Fact]
    public void High_Present_caps_grade_at_B()
    {
        // A High-severity Present finding caps grade at B regardless of score
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.High, Verdict.Present), // High Present
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        Assert.True(result.Grade is "B" or "C" or "D" or "F",
            $"High Present should cap grade at B, got {result.Grade}");
    }

    [Fact]
    public void Critical_Present_caps_grade_at_D()
    {
        // A Critical-severity Present finding caps grade at D regardless of score
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Critical, Verdict.Present), // Critical Present
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        Assert.True(result.Grade is "D" or "F",
            $"Critical Present should cap grade at D, got {result.Grade}");
    }

    [Fact]
    public void Coverage_high_requires_8_observable_and_auth_observable()
    {
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            F("P43", Severity.Low, Verdict.Pass),
        });
        Assert.Equal(CoverageBand.High, result.Coverage);
        Assert.Equal(8, result.AuditedPatternIds.Count);
    }

    [Fact]
    public void Coverage_medium_between_6_and_8_with_auth_observable()
    {
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.Pass),
            F("P30", Severity.Medium, Verdict.Pass),
            F("P31", Severity.Medium, Verdict.Pass),
            F("P32", Severity.Low, Verdict.Pass),
            F("P42", Severity.Low, Verdict.Pass),
            // 7 observable — between 6 and 8
        });
        Assert.Equal(CoverageBand.Medium, result.Coverage);
    }

    [Fact]
    public void AuditedPatternIds_returns_observable_pattern_ids()
    {
        var result = ScoreCalculator.Compute(new[]
        {
            F("P1/P18", Severity.High, Verdict.Pass),
            F("P10", Severity.Medium, Verdict.Pass),
            F("P15", Severity.Low, Verdict.NotObservable), // excluded
            F("P30", Severity.Medium, Verdict.Pass),
        });
        Assert.Contains("P1/P18", result.AuditedPatternIds);
        Assert.Contains("P10", result.AuditedPatternIds);
        Assert.Contains("P30", result.AuditedPatternIds);
        Assert.DoesNotContain("P15", result.AuditedPatternIds);
        Assert.Equal(3, result.AuditedPatternIds.Count);
    }

    [Fact]
    public void No_observable_findings_returns_low_coverage()
    {
        // When nothing is observable, coverage is low
        var result = ScoreCalculator.Compute(new[] { F("PX", Severity.High, Verdict.NotObservable) });
        Assert.Equal(100, result.Score);
        Assert.Equal(CoverageBand.Low, result.Coverage);
        Assert.Empty(result.AuditedPatternIds);
    }
}
