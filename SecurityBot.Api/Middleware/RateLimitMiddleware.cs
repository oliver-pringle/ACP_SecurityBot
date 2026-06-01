using System.Collections.Concurrent;

namespace SecurityBot.Api.Middleware;

/// Two-bucket sliding-window rate limit on heavy / write endpoints. Closes
/// audit finding #9 ("no rate limiting"). Placed BEFORE the auth middleware
/// so unauthenticated floods are also throttled.
///
///   1. Per-X-API-Key bucket — 600 req/min default. Defends against a
///      runaway loop in a legitimate cross-bot consumer (the boilerplate
///      ships single-key only, but downstream bots cloning this often add
///      per-consumer keys).
///   2. Per-client-IP bucket — 60 req/min default. Defends against an
///      attacker who has stolen the API key but is still bound to one IP
///      per session.
///
/// Either bucket exceeding capacity yields a 429. The /health and
/// /v1/resources/* surfaces are exempt — they're meant for unauthenticated
/// liveness probes / orchestrator pre-flight introspection.
///
/// Ported from ACP_OracleBot v0.7 RateLimitMiddleware (commit a2d3731
/// 2026-05-24), which in turn descends from ACP_ChainlinkBot 2026-05-22.
/// Heavy-path list trimmed to what the boilerplate exposes — clones add
/// their own paths to HeavyPathPrefixes alongside their domain endpoints.
public sealed class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly int             _apiKeyCapacity;
    private readonly int             _ipCapacity;
    private readonly TimeSpan        _window;

    private readonly ConcurrentDictionary<string, (DateTime WindowStart, int Count)> _apiKeyBuckets = new();
    private readonly ConcurrentDictionary<string, (DateTime WindowStart, int Count)> _ipBuckets     = new();

    private long _tickCounter;
    private const int EvictEveryNTicks = 256;

    // Path prefixes that count as "heavy" — write paths or compute fan-out.
    // /health and /v1/resources/* are excluded by NOT being listed here.
    // Every entry MUST be covered by RateLimitCoverageTests; adding a heavy
    // route to Program.cs without extending this list (or with a kebab-vs-
    // underscore mismatch) is the P52 drift those tests fail the build on.
    private static readonly string[] HeavyPathPrefixes =
    {
        "/subscriptions",    // POST /subscriptions writes a row; GET /subscriptions/{id} hits SQLite
        "/v1/internal/",     // POST /v1/internal/scan — resolver + probe fan-out + SQLite persist + email
    };

    public RateLimitMiddleware(RequestDelegate next, IConfiguration cfg)
    {
        _next = next;
        _apiKeyCapacity = cfg.GetValue("RateLimit:HeavyEndpointCapPerApiKey", 600);
        _ipCapacity     = cfg.GetValue("RateLimit:HeavyEndpointCapPerIp",      60);
        _window         = TimeSpan.FromMinutes(1);
    }

    // Public + static so the RateLimitCoverageTests can assert every real
    // heavy route literal is covered and the free surfaces (/health,
    // /v1/resources/*) are NOT — a build-breaking guard against P52 drift
    // (a heavy endpoint added without its prefix => silently unthrottled,
    // or a kebab/underscore naming mismatch => StartsWith returns false).
    public static bool IsHeavyPath(string path)
    {
        foreach (var prefix in HeavyPathPrefixes)
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var path = ctx.Request.Path.Value ?? "";

        if (!IsHeavyPath(path))
        {
            await _next(ctx);
            return;
        }

        // API-key bucket. Key is hashed to keep buckets keyed by identity without
        // logging the bearer in dictionary state.
        if (ctx.Request.Headers.TryGetValue("X-API-Key", out var keyHeader) &&
            !string.IsNullOrEmpty(keyHeader.ToString()))
        {
            var keyHash = HashForBucket(keyHeader.ToString());
            if (!TryReserve(_apiKeyBuckets, keyHash, _apiKeyCapacity))
            {
                await Write429(ctx, $"rate limit exceeded; {_apiKeyCapacity} req/min per X-API-Key on heavy endpoints");
                return;
            }
        }

        var ip = ResolveClientIp(ctx);
        if (!TryReserve(_ipBuckets, ip, _ipCapacity))
        {
            await Write429(ctx, $"rate limit exceeded; {_ipCapacity} req/min per client IP on heavy endpoints");
            return;
        }

        MaybeEvict();
        await _next(ctx);
    }

    private bool TryReserve(
        ConcurrentDictionary<string, (DateTime WindowStart, int Count)> buckets,
        string key,
        int capacity)
    {
        var now = DateTime.UtcNow;
        var bucket = buckets.AddOrUpdate(key,
            _ => (now, 1),
            (_, b) => now - b.WindowStart > _window ? (now, 1) : (b.WindowStart, b.Count + 1));
        return bucket.Count <= capacity;
    }

    private void MaybeEvict()
    {
        if ((Interlocked.Increment(ref _tickCounter) % EvictEveryNTicks) != 0) return;
        var cutoff = DateTime.UtcNow - _window - _window;
        foreach (var kvp in _apiKeyBuckets)
            if (kvp.Value.WindowStart < cutoff) _apiKeyBuckets.TryRemove(kvp.Key, out _);
        foreach (var kvp in _ipBuckets)
            if (kvp.Value.WindowStart < cutoff) _ipBuckets.TryRemove(kvp.Key, out _);
    }

    private static async Task Write429(HttpContext ctx, string message)
    {
        ctx.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await ctx.Response.WriteAsJsonAsync(new { error = message });
    }

    // Stable string hash of an X-API-Key for bucket keying. SHA-256 truncated
    // to 16 bytes hex — enough collision resistance for in-memory buckets,
    // doesn't expose the key in dictionary state for any heap dump diagnostic.
    private static string HashForBucket(string raw)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes, 0, 16);
    }

    // Post-UseForwardedHeaders RemoteIpAddress. The boilerplate does NOT wire
    // UseForwardedHeaders by default (single-container deploys speak directly
    // to Kestrel via the docker bridge) — clones that put themselves behind
    // Caddy MUST add UseForwardedHeaders + TRUSTED_PROXY_NETWORKS in Program.cs
    // BEFORE this middleware, otherwise rate-limit buckets are keyed by the
    // proxy IP. See ACP_OracleBot/Program.cs for the canonical wiring.
    private static string ResolveClientIp(HttpContext ctx)
        => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
