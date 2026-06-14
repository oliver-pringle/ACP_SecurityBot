using SecurityBot.Api.Engine;

namespace SecurityBot.Api.Services;

// Coverage bands: how many externally observable checks ran.
public enum CoverageBand { High, Medium, Low }

// Rich score result including coverage metadata for honest audit framing.
public sealed record ScoreResult(
    int Score,
    string Grade,
    CoverageBand Coverage,
    IReadOnlyList<string> AuditedPatternIds);

// Deterministic 0-100 from OBSERVABLE findings, with coverage-aware grading.
//
// Key changes (R19 §2 recalibration):
//  1. Coverage-gated grade: observableCount < 6 OR High-severity auth check
//     NotObservable → max grade C, coverage=Low.
//  2. Half-weight penalty for unverifiable High-severity auth: when P1/P18
//     returns NotObservable, apply 12.5 pts (half of High=25) instead of
//     excluding it. Unverified auth is not the same as passed auth.
//  3. Severity-weighted grade floor: any High Present → max B; any Critical
//     Present → max D — independent of how many Passes pad the denominator.
public static class ScoreCalculator
{
    // Pattern IDs for the High-severity auth posture check — these get
    // special handling when NotObservable (half-weight penalty).
    private static readonly HashSet<string> AuthPatternIds =
        new(StringComparer.OrdinalIgnoreCase) { "P1", "P18", "P1/P18" };

    // Minimum observable count to be considered a meaningful audit.
    private const int CoverageFloorThreshold = 6;

    // Observable count at which coverage is considered "high".
    private const int CoverageHighThreshold = 8;

    private static int Weight(Severity s) => s switch
    {
        Severity.Critical => 40,
        Severity.High     => 25,
        Severity.Medium   => 12,
        Severity.Low      => 5,
        _                 => 1, // Info
    };

    public static ScoreResult Compute(IReadOnlyList<Finding> findings)
    {
        var observable = findings
            .Where(f => f.Verdict is Verdict.Present or Verdict.Partial or Verdict.Pass)
            .ToList();

        // Collect audited pattern IDs (observable checks that ran).
        var auditedPatternIds = observable
            .Select(f => f.PatternId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Check auth check status — is the High-severity P1/P18 NotObservable?
        var authFinding = findings.FirstOrDefault(f => AuthPatternIds.Contains(f.PatternId));
        var authNotObservable = authFinding is not null &&
            authFinding.Verdict is Verdict.NotObservable or Verdict.NotApplicable;

        // Determine coverage band.
        var observableCount = observable.Count;
        CoverageBand coverage;
        if (observableCount < CoverageFloorThreshold || authNotObservable)
            coverage = CoverageBand.Low;
        else if (observableCount >= CoverageHighThreshold)
            coverage = CoverageBand.High;
        else
            coverage = CoverageBand.Medium;

        // If nothing observable, still return a result (NOT_AUDITABLE is handled
        // upstream in DynamicAuditEngine; this path covers edge cases).
        if (observableCount == 0 && !authNotObservable)
            return new ScoreResult(100, "A", CoverageBand.Low, auditedPatternIds);

        // Base penalty calculation from observable findings.
        int maxPenalty = observable.Sum(f => Weight(f.Severity));
        int penalty = observable.Sum(f => f.Verdict switch
        {
            Verdict.Present => Weight(f.Severity),
            Verdict.Partial => Weight(f.Severity) / 2,
            _ => 0,
        });

        // Half-weight penalty for NotObservable High-severity auth check.
        // "Couldn't verify auth" is not the same as "auth passed".
        if (authNotObservable)
        {
            int halfHighWeight = Weight(Severity.High) / 2; // 12
            maxPenalty += halfHighWeight;
            penalty += halfHighWeight;
        }

        int score = maxPenalty == 0 ? 100 : (int)Math.Round(100.0 * (maxPenalty - penalty) / maxPenalty);
        score = Math.Clamp(score, 0, 100);

        // Compute base grade from score.
        var grade = GradeFromScore(score);

        // Apply severity-weighted grade floors.
        var hasCriticalPresent = observable.Any(f =>
            f.Severity == Severity.Critical && f.Verdict == Verdict.Present);
        var hasHighPresent = observable.Any(f =>
            f.Severity == Severity.High && f.Verdict == Verdict.Present);

        if (hasCriticalPresent && CompareGrade(grade, "D") < 0)
            grade = "D"; // Critical Present → max D
        if (hasHighPresent && CompareGrade(grade, "B") < 0)
            grade = "B"; // High Present → max B

        // Apply coverage-gated grade cap: low coverage → max C.
        if (coverage == CoverageBand.Low && CompareGrade(grade, "C") < 0)
            grade = "C";

        return new ScoreResult(score, grade, coverage, auditedPatternIds);
    }

    // Legacy overload for callers that only need score/grade tuple.
    public static (int score, string grade) ComputeSimple(IReadOnlyList<Finding> findings)
    {
        var result = Compute(findings);
        return (result.Score, result.Grade);
    }

    private static string GradeFromScore(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _     => "F",
    };

    // Compare grades: returns <0 if a is better (earlier in A/B/C/D/F), 0 if equal, >0 if worse.
    private static int CompareGrade(string a, string b) =>
        GradeOrdinal(a).CompareTo(GradeOrdinal(b));

    private static int GradeOrdinal(string g) => g switch
    {
        "A" => 0,
        "B" => 1,
        "C" => 2,
        "D" => 3,
        "F" => 4,
        _ => 5,
    };
}
