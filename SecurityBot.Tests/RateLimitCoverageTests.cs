using SecurityBot.Api.Middleware;
using Xunit;

namespace SecurityBot.Tests;

// P52 drift-guard: the RateLimitMiddleware throttles only paths matched by
// HeavyPathPrefixes (via StartsWith). If a heavy/write/compute endpoint is
// added to Program.cs but its prefix is never added here — or the prefix is
// spelled with a different separator than the real route (kebab-vs-underscore)
// — StartsWith returns false and the endpoint is silently UNTHROTTLED. This
// test pins RateLimitMiddleware.IsHeavyPath against the bot's ACTUAL mapped
// routes so any future drift fails the build.
//
// Heavy routes (must throttle) — every POST + every GET that hits SQLite /
// the probe engine / an external fetch, taken verbatim from Program.cs:
//   POST /subscriptions            (SubscriptionService writes a row)
//   GET  /subscriptions/{id}       (SubscriptionRepository hits SQLite)
//   POST /v1/internal/scan         (resolver + probe fan-out + SQLite + email)
//
// Free routes (must NOT throttle) — pure liveness + the public free
// /v1/resources/* introspection surface (whitelisted alongside /health by
// both the auth and the security-header middleware):
//   GET  /health
//   GET  /v1/resources/patternCatalogue
//   GET  /v1/resources/auditByAgent
//   GET  /v1/resources/offerings
public class RateLimitCoverageTests
{
    [Theory]
    [InlineData("/subscriptions")]                  // POST create-subscription
    [InlineData("/subscriptions/abc123")]           // GET subscription view (SQLite)
    [InlineData("/v1/internal/scan")]               // POST paid scan — heaviest endpoint
    public void Heavy_routes_are_throttled(string path)
    {
        Assert.True(
            RateLimitMiddleware.IsHeavyPath(path),
            $"HEAVY route '{path}' is NOT covered by any HeavyPathPrefixes entry — it is " +
            "silently unthrottled (P52). Add its prefix stem to HeavyPathPrefixes.");
    }

    [Theory]
    [InlineData("/health")]
    [InlineData("/v1/resources/patternCatalogue")]
    [InlineData("/v1/resources/auditByAgent")]
    [InlineData("/v1/resources/offerings")]
    public void Free_routes_are_not_throttled(string path)
    {
        Assert.False(
            RateLimitMiddleware.IsHeavyPath(path),
            $"FREE route '{path}' must stay exempt from rate limiting — it is meant for " +
            "unauthenticated liveness / orchestrator pre-flight introspection.");
    }
}
