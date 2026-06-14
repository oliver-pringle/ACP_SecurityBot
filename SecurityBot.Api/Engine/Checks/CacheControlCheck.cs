using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P31-Cache: sensitive endpoints (paid/internal paths, non-Resource paths) must emit
// Cache-Control: no-store to prevent proxies/browsers caching authenticated responses.
// Public Resources (/v1/resources/*) and /health are allowed to be cached. This is a
// sub-pattern of P31 (security response headers) focused on cache hygiene.
public sealed partial class CacheControlCheck : IProbeCheck
{
    public string PatternId => "P31-Cache";
    public string Title => "Missing Cache-Control: no-store on sensitive endpoint";

    // Paths that SHOULD be cacheable - don't flag them.
    [GeneratedRegex(@"^/v1/resources/|^/health$", RegexOptions.IgnoreCase)]
    private static partial Regex CacheablePaths();

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var sensitiveResponses = ctx.All
            .Where(r => r.Reached &&
                        !r.Label.Equals("ratelimit_probe", StringComparison.OrdinalIgnoreCase) &&
                        !IsCacheablePath(r.Url))
            .ToList();

        if (sensitiveResponses.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.NotObservable,
                "no sensitive (non-Resource) endpoint was reached, so cache control could not be observed",
                PatternId));
        }

        foreach (var r in sensitiveResponses)
        {
            var cacheControl = Header(r, "Cache-Control");
            if (string.IsNullOrEmpty(cacheControl))
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Low, Verdict.Present,
                    Trunc($"sensitive response '{r.Label}' has no Cache-Control header"),
                    PatternId));
            }

            if (!cacheControl.Contains("no-store", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new Finding(
                    PatternId, Title, Severity.Low, Verdict.Present,
                    Trunc($"sensitive response '{r.Label}' has Cache-Control '{cacheControl}' without no-store"),
                    PatternId));
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Pass,
            "all sensitive responses carry Cache-Control: no-store",
            PatternId));
    }

    private static bool IsCacheablePath(string url)
    {
        try
        {
            var uri = new Uri(url);
            return CacheablePaths().IsMatch(uri.AbsolutePath);
        }
        catch
        {
            return false;
        }
    }

    private static string? Header(ProbeResponse r, string name)
    {
        foreach (var kv in r.Headers)
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value?.Trim();
        return null;
    }

    private static string Trunc(string s) => s.Length <= 140 ? s : s[..140];
}
