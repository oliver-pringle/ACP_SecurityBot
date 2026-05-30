using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P38 (observable variant): a passive scan cannot know when data SHOULD be synthetic,
// but it CAN catch the HIGH-PRECISION tells of an incomplete / stub deployment leaking
// into a served response: an unfilled `REPLACE_WITH_...` config placeholder, a literal
// `0xSTUB` stand-in, a `TODO_...` token, or lorem-ipsum filler. Deliberately NARROW -
// descriptive words like "synthetic"/"placeholder" and a bare zero-address are EXCLUDED
// because they occur in legitimate content (a security catalogue describes "synthetic"
// patterns; a zero-address is a valid burn/unset value), which would false-positive on
// SecurityBot's own patternCatalogue Resource. Reads only existing probes.
public sealed partial class StubDataCheck : IProbeCheck
{
    public string PatternId => "P38";
    public string Title => "Stub / placeholder data leaked into a served response";

    // Distinctive, low-false-positive stub markers (structural, not ordinary prose).
    [GeneratedRegex(
        @"(REPLACE_WITH_[A-Z0-9_]+|\b0xSTUB\b|\bTODO_[A-Z0-9_]+|lorem ipsum)",
        RegexOptions.IgnoreCase)]
    private static partial Regex StubMarkerRegex();

    private static readonly string[] InspectPrefixes = { "resource", "root", "paid_unauth" };

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var bodies = ctx.All
            .Where(r => r.Reached &&
                        InspectPrefixes.Any(p => r.Label.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (bodies.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.NotObservable,
                "no inspectable response body was reached, so stub markers could not be observed",
                PatternId));
        }

        foreach (var r in bodies)
        {
            var m = StubMarkerRegex().Match(r.Body ?? string.Empty);
            if (m.Success)
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Medium, Verdict.Present,
                    Trunc($"response '{r.Label}' contains a stub/placeholder marker: {m.Value}"),
                    PatternId));
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Medium, Verdict.Pass,
            "no stub / placeholder markers found in reached response bodies", PatternId));
    }

    private static string Trunc(string s) => s.Length <= 140 ? s : s[..140];
}
