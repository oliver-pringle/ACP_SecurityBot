namespace SecurityBot.Api.Engine.Checks;

// P1/P18: a paid offering endpoint must not answer without auth. The engine probes a paid
// endpoint with no X-API-Key and labels the response "paid_unauth". A 200 is a missing-auth
// finding; a 401/403 proves the gate works; anything else (404/400/...) tells us nothing.
public sealed class AuthPostureCheck : IProbeCheck
{
    public string PatternId => "P1/P18";
    public string Title => "Paid endpoint auth posture";

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        if (!ctx.TryGet("paid_unauth", out var r) || r is null || !r.Reached)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.High, Verdict.NotObservable,
                "the unauthenticated paid-endpoint probe was not reached",
                PatternId));
        }

        if (r.StatusCode == 200)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.High, Verdict.Present,
                "paid endpoint answered 200 without auth (status 200 on paid_unauth)",
                PatternId));
        }

        if (r.StatusCode is 401 or 403)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.High, Verdict.Pass,
                $"paid endpoint rejected unauthenticated request (status {r.StatusCode})",
                PatternId));
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.High, Verdict.NotObservable,
            $"unauthenticated paid probe returned status {r.StatusCode}; auth posture cannot be concluded",
            PatternId));
    }
}
