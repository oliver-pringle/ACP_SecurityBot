using SecurityBot.Api.Engine;

namespace SecurityBot.Api.Services;

// Deterministic 0-100 from OBSERVABLE findings only. A "Present" finding
// costs its severity weight; "Partial" costs half. Pass costs nothing.
// NotObservable / NotApplicable are excluded from the denominator so a
// target is never punished for what we could not externally verify.
public static class ScoreCalculator
{
    private static int Weight(Severity s) => s switch
    {
        Severity.Critical => 40,
        Severity.High     => 25,
        Severity.Medium   => 12,
        Severity.Low      => 5,
        _                 => 1, // Info
    };

    public static (int score, string grade) Compute(IReadOnlyList<Finding> findings)
    {
        var observable = findings
            .Where(f => f.Verdict is Verdict.Present or Verdict.Partial or Verdict.Pass)
            .ToList();

        if (observable.Count == 0) return (100, "A");

        int maxPenalty = observable.Sum(f => Weight(f.Severity));
        int penalty = observable.Sum(f => f.Verdict switch
        {
            Verdict.Present => Weight(f.Severity),
            Verdict.Partial => Weight(f.Severity) / 2,
            _ => 0,
        });

        int score = maxPenalty == 0 ? 100 : (int)Math.Round(100.0 * (maxPenalty - penalty) / maxPenalty);
        score = Math.Clamp(score, 0, 100);
        return (score, Grade(score));
    }

    private static string Grade(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _     => "F",
    };
}
