using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests.Checks;

public class TimingHeaderCheckTests
{
    private static readonly IReadOnlyDictionary<string, string> BaseHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
        };

    private static ProbeResponse Resp(string label, string url, IDictionary<string, string>? extraHeaders = null)
    {
        var headers = new Dictionary<string, string>(BaseHeaders, StringComparer.OrdinalIgnoreCase);
        if (extraHeaders != null)
        {
            foreach (var kv in extraHeaders)
                headers[kv.Key] = kv.Value;
        }
        return new ProbeResponse(label, url, 200, headers, "{}", Reached: true);
    }

    [Fact]
    public async Task Pass_when_no_timing_headers()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", "https://x.example/health"),
            Resp("root", "https://x.example/"),
        });

        var check = new TimingHeaderCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task Present_when_X_Response_Time_present()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", "https://x.example/health", new Dictionary<string, string>
            {
                ["X-Response-Time"] = "42ms"
            }),
        });

        var check = new TimingHeaderCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("X-Response-Time", result.Evidence);
    }

    [Fact]
    public async Task Present_when_Server_Timing_present()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("health", "https://x.example/health", new Dictionary<string, string>
            {
                ["Server-Timing"] = "db;dur=53, app;dur=47"
            }),
        });

        var check = new TimingHeaderCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
        Assert.Contains("Server-Timing", result.Evidence);
    }

    [Fact]
    public async Task Present_when_X_Runtime_present()
    {
        var ctx = new ProbeContext("https://x.example", new[]
        {
            Resp("root", "https://x.example/", new Dictionary<string, string>
            {
                ["X-Runtime"] = "0.045"
            }),
        });

        var check = new TimingHeaderCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.Present, result.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_no_responses_reached()
    {
        var ctx = new ProbeContext("https://x.example", Array.Empty<ProbeResponse>());

        var check = new TimingHeaderCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }

    [Fact]
    public async Task Ignores_ratelimit_probe_synthetic_response()
    {
        var empty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ctx = new ProbeContext("https://x.example", new[]
        {
            new ProbeResponse("ratelimit_probe", "https://x.example/__rl__", 429, empty, "", true),
        });

        var check = new TimingHeaderCheck();
        var result = await check.RunAsync(ctx, default);

        Assert.Equal(Verdict.NotObservable, result.Verdict);
    }
}
