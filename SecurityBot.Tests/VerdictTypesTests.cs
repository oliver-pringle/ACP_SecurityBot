using SecurityBot.Api.Engine;
using Xunit;

namespace SecurityBot.Tests;

public class VerdictTypesTests
{
    [Fact]
    public void Finding_round_trips_its_fields()
    {
        var f = new Finding(
            PatternId: "P31",
            Title: "Missing security headers",
            Severity: Severity.Low,
            Verdict: Verdict.Present,
            Evidence: "no X-Frame-Options on /health",
            FixRef: "P31");

        Assert.Equal("P31", f.PatternId);
        Assert.Equal(Severity.Low, f.Severity);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal("P31", f.FixRef);
    }

    [Fact]
    public void ProbeContext_exposes_responses_by_label()
    {
        var resp = new ProbeResponse(
            Label: "health",
            Url: "https://x.example/health",
            StatusCode: 200,
            Headers: new Dictionary<string, string> { ["X-Frame-Options"] = "DENY" },
            Body: "{}",
            Reached: true);
        var ctx = new ProbeContext("https://x.example", new[] { resp });

        Assert.True(ctx.TryGet("health", out var got));
        Assert.Equal(200, got!.StatusCode);
        Assert.False(ctx.TryGet("missing", out _));
    }
}
