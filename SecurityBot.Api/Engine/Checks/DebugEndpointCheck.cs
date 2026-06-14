using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P1-Debug: production endpoints should not expose debug/diagnostic paths or include
// debug markers in their responses. Common tells: "/debug", "/metrics" (unauthenticated),
// "debug":true in JSON, "stack", "trace" fields in error responses. This complements
// AuthPostureCheck (P1/P18) by catching debug surfaces that ARE reachable without auth.
// A debug endpoint that answers 200 with diagnostic content is a dev-mode posture leak.
public sealed partial class DebugEndpointCheck : IProbeCheck
{
    public string PatternId => "P1-Debug";
    public string Title => "Debug/diagnostic surface exposed";

    // High-precision debug markers in JSON bodies. Matches:
    //   "debug": true / "debug":true
    //   "trace": "..."
    //   "stackTrace": "..."
    //   "diagnostics": {...}
    [GeneratedRegex(
        @"""(debug|diagnostics|stackTrace|debugMode)""\s*:\s*(true|""|\{)",
        RegexOptions.IgnoreCase)]
    private static partial Regex DebugMarkerRegex();

    // Debug path in URL.
    [GeneratedRegex(@"/(debug|_debug|__debug__|trace|profiler|phpinfo|elmah|diagnostics)(/|$|\?)", RegexOptions.IgnoreCase)]
    private static partial Regex DebugPathRegex();

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var reached = ctx.All
            .Where(r => r.Reached &&
                        !r.Label.Equals("ratelimit_probe", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (reached.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.High, Verdict.NotObservable,
                "no response was reached, so debug exposure could not be observed",
                PatternId));
        }

        foreach (var r in reached)
        {
            // Check if URL is a known debug path and endpoint responded successfully.
            if (DebugPathRegex().IsMatch(r.Url) && r.StatusCode >= 200 && r.StatusCode < 300)
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.High, Verdict.Present,
                    Trunc($"debug endpoint '{r.Url}' responds with status {r.StatusCode}"),
                    PatternId));
            }

            // Check for debug markers in response body.
            var body = r.Body ?? string.Empty;
            var m = DebugMarkerRegex().Match(body);
            if (m.Success)
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Medium, Verdict.Present,
                    Trunc($"response '{r.Label}' contains debug marker: {m.Value}"),
                    PatternId));
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.High, Verdict.Pass,
            "no debug/diagnostic surface exposure detected",
            PatternId));
    }

    private static string Trunc(string s) => s.Length <= 140 ? s : s[..140];
}
