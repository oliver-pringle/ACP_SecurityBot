using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests.Checks;

public class VersionLeakCheckTests
{
    private static readonly IReadOnlyDictionary<string, string> JsonHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
        };

    private static ProbeResponse JsonResp(string label, string url, string body)
        => new(label, url, 200, JsonHeaders, body, Reached: true);

    [Fact]
    public async Task Pass_when_no_version_leak()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            JsonResp("health", "https://x.example/health", "{\"status\":\"ok\"}"),
            JsonResp("resource_0", "https://x.example/v1/resources/test", "{\"name\":\"test\"}"),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task Present_when_dotnetVersion_leaked()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            JsonResp("health", "https://x.example/health", "{\"status\":\"ok\",\"dotnetVersion\":\"10.0.0\"}"),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("dotnetVersion", result.Evidence);
    }

    [Fact]
    public async Task Present_when_nodeVersion_leaked()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            JsonResp("resource_0", "https://x.example/v1/resources/info",
                "{\"nodeVersion\": \"22.1.0\"}"),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("nodeVersion", result.Evidence);
    }

    [Fact]
    public async Task Present_when_sdkVersion_leaked()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            JsonResp("health", "https://x.example/health",
                "{\"sdkVersion\":\"0.0.6\"}"),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
    }

    [Fact]
    public async Task Present_when_slash_version_format_leaked()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            JsonResp("health", "https://x.example/health",
                "{\"server\":\"node/22.1.0\"}"),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("runtime version", result.Evidence);
    }

    [Fact]
    public async Task Ignores_generic_version_field()
    {
        // Generic "version" or "apiVersion" should NOT trigger a finding
        var ctx = new ProbeContext("https://x.example", new[]
        {
            JsonResp("health", "https://x.example/health",
                "{\"version\":\"1.2.3\",\"apiVersion\":\"v2\"}"),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_json_responses()
    {
        var textHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "text/plain",
        };
        var ctx = new ProbeContext("https://x.example", new[]
        {
            new ProbeResponse("health", "https://x.example/health", 200, textHeaders, "OK", true),
        });

        var check = new VersionLeakCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }
}
