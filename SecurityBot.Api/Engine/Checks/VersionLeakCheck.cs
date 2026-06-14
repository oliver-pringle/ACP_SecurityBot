using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P43-Body: extends the P43 server-banner header check to response BODIES. Version
// strings in JSON (e.g. "version":"1.2.3", "dotnetVersion", "nodeVersion", "sdk":"0.0.6")
// leak the exact build of dependencies an attacker can cross-reference with CVE
// databases. Distinct from the header check: the header scanner catches Server/X-Powered-By;
// this catches JSON-embedded version disclosure. Deliberately narrow patterns to avoid
// false positives on business-logic version fields ("apiVersion":"v2", etc.).
public sealed partial class VersionLeakCheck : IProbeCheck
{
    public string PatternId => "P43-Body";
    public string Title => "Response body discloses framework/runtime version";

    // High-precision patterns for framework/runtime version disclosure in JSON bodies.
    // Matches:
    //   "dotnetVersion": "10.0.0"
    //   "nodeVersion": "22.1.0"
    //   "sdkVersion": "0.0.6"
    //   "runtimeVersion": "..."
    //   "frameworkVersion": "..."
    //   "aspnetVersion": "..."
    //   "netVersion": "..."
    // Excludes generic "version" (too many false positives on API versions).
    [GeneratedRegex(
        @"""(dotnet|node|sdk|runtime|framework|aspnet|net|kestrel|express|fastify|nest)Version""\s*:\s*""[0-9]+\.[0-9]+",
        RegexOptions.IgnoreCase)]
    private static partial Regex FrameworkVersionRegex();

    // Matches semver-ish strings paired with known framework keys.
    // "server": "node/22.1.0"
    // "runtime": "dotnet/10.0.0"
    [GeneratedRegex(
        @"""(server|runtime|engine)""\s*:\s*""[a-zA-Z]+/[0-9]+\.[0-9]+",
        RegexOptions.IgnoreCase)]
    private static partial Regex SlashVersionRegex();

    private static readonly string[] InspectPrefixes = { "resource", "root", "health" };

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var bodies = ctx.All
            .Where(r => r.Reached &&
                        InspectPrefixes.Any(p => r.Label.StartsWith(p, StringComparison.OrdinalIgnoreCase)) &&
                        IsJson(r))
            .ToList();

        if (bodies.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.NotObservable,
                "no JSON response body was reached, so version leak could not be observed",
                PatternId));
        }

        foreach (var r in bodies)
        {
            var body = r.Body ?? string.Empty;

            var m = FrameworkVersionRegex().Match(body);
            if (m.Success)
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Low, Verdict.Present,
                    Trunc($"response '{r.Label}' discloses framework version: {m.Value}"),
                    PatternId));
            }

            var s = SlashVersionRegex().Match(body);
            if (s.Success)
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Low, Verdict.Present,
                    Trunc($"response '{r.Label}' discloses runtime version: {s.Value}"),
                    PatternId));
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Pass,
            "no framework/runtime version disclosure found in reached response bodies",
            PatternId));
    }

    private static bool IsJson(ProbeResponse r)
        => r.Headers.TryGetValue("Content-Type", out var ct)
           && ct.Contains("application/json", StringComparison.OrdinalIgnoreCase);

    private static string Trunc(string s) => s.Length <= 140 ? s : s[..140];
}
