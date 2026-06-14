using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests.Checks;

public class DebugEndpointCheckTests
{
    private static readonly IReadOnlyDictionary<string, string> JsonHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
        };

    private static ProbeResponse Resp(string label, string url, int status, string body)
        => new(label, url, status, JsonHeaders, body, Reached: true);

    [Fact]
    public async Task Pass_when_no_debug_surface()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", "https://x.example/health", 200, "{\"status\":\"ok\"}"),
            Resp("root", "https://x.example/", 404, "{\"error\":\"NOT_FOUND\"}"),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task Present_when_debug_path_responds_200()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("debug", "https://x.example/debug", 200, "{\"info\":\"debug data\"}"),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("/debug", result.Evidence);
    }

    [Fact]
    public async Task Present_when_diagnostics_path_responds()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("diag", "https://x.example/diagnostics/", 200, "{}"),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
    }

    [Fact]
    public async Task Present_when_debug_marker_in_body()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", "https://x.example/health", 200, "{\"status\":\"ok\",\"debug\":true}"),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("debug", result.Evidence);
    }

    [Fact]
    public async Task Present_when_stackTrace_in_body()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("error", "https://x.example/error", 500,
                "{\"error\":\"fail\",\"stackTrace\":\"at System.Something...\"}"),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
    }

    [Fact]
    public async Task Pass_when_debug_path_returns_404()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("debug", "https://x.example/debug", 404, "{\"error\":\"NOT_FOUND\"}"),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        // Debug path 404 = not exposed = pass
        Assert.Equal(Verdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_responses()
    {
        var ctx = new ProbeContext("https://x.example", Array.Empty<ProbeResponse>());

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }

    [Fact]
    public async Task Ignores_ratelimit_probe()
    {
        var empty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ctx = new ProbeContext("https://x.example", new[]
        {
            new ProbeResponse("ratelimit_probe", "https://x.example/__rl__", 429, empty, "", true),
        });

        var check = new DebugEndpointCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }
}
