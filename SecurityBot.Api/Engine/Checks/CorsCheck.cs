namespace SecurityBot.Api.Engine.Checks;

// P42: a wildcard CORS policy (Access-Control-Allow-Origin: *) lets ANY web origin
// read the agent's API responses from a victim's browser. Combined with
// Access-Control-Allow-Credentials: true it is an outright credential-exfiltration
// hole (the browser will attach the victim's cookies/credentials to the cross-origin
// read). We flag a wildcard ACAO on any reached response; the credentialed variant is
// escalated to High. Reads only the existing probe responses (no extra request).
public sealed class CorsCheck : IProbeCheck
{
    public string PatternId => "P42";
    public string Title => "Permissive CORS policy";

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var reached = ctx.All
            .Where(r => r.Reached &&
                        !r.Label.Equals("ratelimit_probe", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (reached.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.NotObservable,
                "no response was reached, so the CORS policy could not be observed", PatternId));
        }

        foreach (var r in reached)
        {
            var acao = Header(r, "Access-Control-Allow-Origin");
            if (acao == "*")
            {
                var credentialed = string.Equals(
                    Header(r, "Access-Control-Allow-Credentials"), "true",
                    StringComparison.OrdinalIgnoreCase);
                var severity = credentialed ? Severity.High : Severity.Medium;
                var note = credentialed
                    ? "wildcard Access-Control-Allow-Origin: * WITH Access-Control-Allow-Credentials: true (cross-origin credential exfiltration)"
                    : "wildcard Access-Control-Allow-Origin: *";
                return Task.FromResult(new Finding(
                    PatternId, Title, severity, Verdict.Present,
                    $"response '{r.Label}' returns {note}", PatternId));
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Medium, Verdict.Pass,
            "no wildcard Access-Control-Allow-Origin on any reached response", PatternId));
    }

    // HTTP header names are case-insensitive; look up defensively regardless of how the
    // server cased them.
    private static string? Header(ProbeResponse r, string name)
    {
        foreach (var kv in r.Headers)
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value?.Trim();
        return null;
    }
}
