namespace SecurityBot.Api.Engine.Checks;

// P21-Hint: an endpoint that includes X-Response-Time, X-Runtime, or Server-Timing headers
// discloses internal processing duration. While not inherently a vulnerability, it helps
// attackers profile slow paths (timing side-channels, DoS amplification targets). This is
// an observable hint toward P21 (missing resilience policy / timeout) — a slow-leaking
// header suggests the backend has no timeout and is willing to advertise how long it ran.
// Borderline Low severity: information disclosure, not a direct exploit.
public sealed class TimingHeaderCheck : IProbeCheck
{
    public string PatternId => "P21-Hint";
    public string Title => "Response discloses server-side timing";

    private static readonly string[] TimingHeaders =
    {
        "X-Response-Time",
        "X-Runtime",
        "X-Request-Duration",
        "Server-Timing",
        "X-Elapsed",
        "X-Process-Time",
    };

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
                "no response was reached, so timing headers could not be observed",
                PatternId));
        }

        foreach (var r in reached)
        {
            foreach (var timingHeader in TimingHeaders)
            {
                if (HeaderExists(r, timingHeader))
                {
                    var value = GetHeader(r, timingHeader) ?? "";
                    return Task.FromResult(new Finding(
                        PatternId, Title, Severity.Low, Verdict.Present,
                        Trunc($"response '{r.Label}' discloses timing via {timingHeader}: {value}"),
                        PatternId));
                }
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Pass,
            "no timing disclosure headers found on any reached response",
            PatternId));
    }

    private static bool HeaderExists(ProbeResponse r, string name)
    {
        foreach (var kv in r.Headers)
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static string? GetHeader(ProbeResponse r, string name)
    {
        foreach (var kv in r.Headers)
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value?.Trim();
        return null;
    }

    private static string Trunc(string s) => s.Length <= 140 ? s : s[..140];
}
