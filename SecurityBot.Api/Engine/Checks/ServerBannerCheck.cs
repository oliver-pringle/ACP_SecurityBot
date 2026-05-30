using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P43: verbose Server / X-Powered-By / X-AspNet(Mvc)-Version response headers disclose
// the framework and often its exact version, handing an attacker a CVE shortlist.
// Production APIs should suppress them (Kestrel `AddServerHeader=false`, strip
// X-Powered-By at the edge). We flag:
//   - X-Powered-By / X-AspNet-Version / X-AspNetMvc-Version : ANY value (pure app-tier leak)
//   - Server : only when it names an app/framework stack or carries a version number
//     (so a bare reverse-proxy banner like "Server: cloudflare" / "Server: Caddy" with no
//     version is not a false positive, but "nginx/1.25.1" or "Kestrel" / "Microsoft-IIS/10.0" is).
// Reads only the existing probe responses (no extra request).
public sealed partial class ServerBannerCheck : IProbeCheck
{
    public string PatternId => "P43";
    public string Title => "Verbose server / framework banner headers";

    // Server values that reveal an app/framework stack or a version number.
    [GeneratedRegex(@"(kestrel|microsoft-iis|asp\.net|express|gunicorn|werkzeug|jetty|tomcat|/\d+\.\d+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex RevealingServerRegex();

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var reached = ctx.All
            .Where(r => r.Reached &&
                        !r.Label.Equals("ratelimit_probe", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (reached.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.NotObservable,
                "no response was reached, so banner headers could not be observed", PatternId));
        }

        foreach (var r in reached)
        {
            foreach (var h in new[] { "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version" })
            {
                var v = Header(r, h);
                if (!string.IsNullOrWhiteSpace(v))
                    return Present($"response '{r.Label}' leaks {h}: {Trunc(v!)}");
            }

            var server = Header(r, "Server");
            if (!string.IsNullOrWhiteSpace(server) && RevealingServerRegex().IsMatch(server!))
                return Present($"response '{r.Label}' leaks Server: {Trunc(server!)}");
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Pass,
            "no revealing Server / X-Powered-By / framework-version headers on reached responses",
            PatternId));
    }

    private Task<Finding> Present(string evidence) => Task.FromResult(new Finding(
        PatternId, Title, Severity.Low, Verdict.Present, evidence, PatternId));

    private static string? Header(ProbeResponse r, string name)
    {
        foreach (var kv in r.Headers)
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value?.Trim();
        return null;
    }

    private static string Trunc(string s) => s.Length <= 80 ? s : s[..80];
}
