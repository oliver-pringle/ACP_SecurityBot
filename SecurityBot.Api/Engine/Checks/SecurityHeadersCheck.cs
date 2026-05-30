namespace SecurityBot.Api.Engine.Checks;

// P31: every-response middleware should emit X-Frame-Options, Content-Security-Policy,
// X-Content-Type-Options. We inspect every REACHED response; if any reached response is
// missing one of the three, the posture is incomplete -> Present.
public sealed class SecurityHeadersCheck : IProbeCheck
{
    public string PatternId => "P31";
    public string Title => "Security response headers";

    private static readonly string[] Required =
    {
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-Content-Type-Options",
    };

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        // Exclude the synthetic 'ratelimit_probe' - it is NOT a real fetched
        // HTTP response. DynamicAuditEngine.RunRateLimitBurstAsync collapses the
        // burst into one summary response with EMPTY headers and an empty body,
        // so including it here would make EVERY scan (even of a perfectly
        // hardened target, and SecurityBot's own surface) trip a false P31
        // Present. We only judge headers on genuinely-fetched responses.
        var reached = ctx.All
            .Where(r => r.Reached &&
                        !r.Label.Equals("ratelimit_probe", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (reached.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.NotObservable,
                "no response was reached, so security headers could not be observed",
                PatternId));
        }

        foreach (var r in reached)
        {
            var missing = Required.Where(h => !r.Headers.ContainsKey(h)).ToList();
            if (missing.Count > 0)
            {
                var evidence = Truncate(
                    $"missing [{string.Join(", ", missing)}] on response '{r.Label}'");
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Low, Verdict.Present, evidence, PatternId));
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Pass,
            "all reached responses carry X-Frame-Options, Content-Security-Policy, X-Content-Type-Options",
            PatternId));
    }

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200];
}
