namespace SecurityBot.Api.Engine.Checks;

// P15/P19: rate limiting. The engine performs a bounded repeat-GET burst and synthesizes a
// single "ratelimit_probe" response: 429 if a limiter ever responded, else 200. An observed
// 429 passes; a 200 within a few requests is NOT proof of a missing limiter, so we return
// Partial (never Present here).
public sealed class RateLimitHintCheck : IProbeCheck
{
    public string PatternId => "P15/P19";
    public string Title => "Rate-limit hint";

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        if (!ctx.TryGet("ratelimit_probe", out var r) || r is null || !r.Reached)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.NotObservable,
                "the rate-limit burst probe was not reached, so a limiter could not be observed",
                PatternId));
        }

        if (r.StatusCode == 429)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.Pass,
                "rate limiter observed (status 429 within bounded probe)",
                PatternId));
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Partial,
            "no rate-limit response within bounded probe; a limiter may still exist",
            PatternId));
    }
}
