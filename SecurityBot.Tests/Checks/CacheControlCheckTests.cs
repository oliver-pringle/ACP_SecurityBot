using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests.Checks;

public class CacheControlCheckTests
{
    private static readonly IReadOnlyDictionary<string, string> BaseHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
        };

    private static ProbeResponse Resp(
        string label, int status, string url, bool noStore = false)
    {
        var headers = new Dictionary<string, string>(BaseHeaders, StringComparer.OrdinalIgnoreCase);
        if (noStore)
            headers["Cache-Control"] = "no-store";
        return new ProbeResponse(label, url, status, headers, "{}", Reached: true);
    }

    [Fact]
    public async Task Pass_when_sensitive_endpoint_has_no_store()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("root", 404, "https://x.example/", noStore: true),
            Resp("paid_unauth", 401, "https://x.example/v1/internal/scan", noStore: true),
        });

        var check = new CacheControlCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task Present_when_sensitive_endpoint_missing_no_store()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("root", 404, "https://x.example/", noStore: false),
        });

        var check = new CacheControlCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("no Cache-Control header", result.Evidence);
    }

    [Fact]
    public async Task Present_when_cache_control_lacks_no_store()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Cache-Control"] = "max-age=3600",
        };
        var ctx = new ProbeContext("https://x.example", new[]
        {
            new ProbeResponse("malformed", "https://x.example/v1/__probe__", 500, headers, "{}", true),
        });

        var check = new CacheControlCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("without no-store", result.Evidence);
    }

    [Fact]
    public async Task Ignores_resource_paths_and_health()
    {
        // Resource paths and /health are cacheable - should not be flagged even without no-store.
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", 200, "https://x.example/health"),
            Resp("resource_0", 200, "https://x.example/v1/resources/test"),
        });

        var check = new CacheControlCheck();
        var result = await check.RunAsync(ctx, default);

        // No sensitive endpoints reached, so NotObservable
        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_sensitive_endpoints_reached()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", 200, "https://x.example/health"),
        });

        var check = new CacheControlCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }
}
