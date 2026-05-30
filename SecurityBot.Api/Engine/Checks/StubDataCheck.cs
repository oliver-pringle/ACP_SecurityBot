using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P38 (observable variant): a passive scan cannot know when data SHOULD be synthetic,
// but it CAN catch the unmistakable tells of an incomplete / stub deployment leaking
// into a served response: an unfilled `REPLACE_WITH_...` config placeholder, the
// zero address used as a stand-in value, obvious stub calldata, or literal
// STUB/SYNTHETIC/PLACEHOLDER/TODO/lorem-ipsum markers. These are high-confidence (the
// tokens are distinctive, not ordinary English) so the false-positive rate stays low.
// Inspects reached resource / root / paid-unauth bodies. Reads only existing probes.
public sealed partial class StubDataCheck : IProbeCheck
{
    public string PatternId => "P38";
    public string Title => "Stub / placeholder data leaked into a served response";

    // Distinctive, low-false-positive stub markers.
    [GeneratedRegex(
        @"(REPLACE_WITH_[A-Z0-9_]+|0x0{40}\b|0xab(cd)+\b|\bSYNTHETIC\b|\bPLACEHOLDER\b|\b0xSTUB\b|\bTODO_[A-Z0-9_]+|lorem ipsum)",
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
