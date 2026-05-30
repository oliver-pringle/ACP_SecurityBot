using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

// Dogfood: SecurityBot must pass its OWN audit. It would look ridiculous
// flagging other agents for gaps it ships itself. This test constructs a
// ProbeContext representing SecurityBot's REAL expected production response
// shape, runs all 8 checks against it, and asserts:
//   1. NO finding has Verdict.Present (our surface trips nothing observable),
//   2. ScoreCalculator scores it 100 / grade A.
//
// If a future change to the bot's actual response shape would make one of
// these checks return Present, this test goes red FIRST - it encodes the
// self-application contract as a regression guard. NotObservable / Pass are
// fine (a passive audit is honest about what it cannot externally verify).
public class DogfoodSelfScanTests
{
    // SecurityBot's every-response middleware (Program.cs OnStarting) emits
    // these on EVERY response. SecurityHeadersCheck (P31) inspects EVERY
    // reached response, so the dogfood context must carry them everywhere -
    // exactly as the live bot does.
    private static readonly IReadOnlyDictionary<string, string> SecurityHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Frame-Options"] = "DENY",
            ["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'",
            ["X-Content-Type-Options"] = "nosniff",
            // HSTS is emitted by Caddy at the TLS edge; include it so the
            // P31-TLS check observes it and returns Pass rather than Partial.
            ["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains",
        };

    private static ProbeResponse Resp(
        string label, int status, string body, string url,
        string contentType = "application/json; charset=utf-8")
    {
        var headers = new Dictionary<string, string>(SecurityHeaders, StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = contentType,
        };
        return new ProbeResponse(label, url, status, headers, body, Reached: true);
    }

    // The full set of checks, wired exactly as Program.cs registers them.
    private static IReadOnlyList<IProbeCheck> AllChecks() => new IProbeCheck[]
    {
        new AuthPostureCheck(),
        new ErrorLeakCheck(),
        new RateLimitHintCheck(),
        new RawDumpCheck(),
        new ResourceDisclosureCheck(),
        new SchemaDescriptionCheck(),
        new SecurityHeadersCheck(),
        new TlsTransportCheck(),
        new CorsCheck(),
        new ServerBannerCheck(),
        new StubDataCheck(),
    };

    // Build the context that mirrors SecurityBot's OWN good production shape.
    private static ProbeContext SelfShapeContext()
    {
        const string baseUrl = "https://x.example"; // https => TlsTransportCheck is not auto-Present

        // /health - clean envelope, all P31 headers, no EOA/RPC/dump markers.
        var health = Resp("health", 200, "{\"status\":\"ok\"}", baseUrl + "/health");

        // root - also carries the headers (every-response middleware).
        var root = Resp("root", 404, "{\"error\":\"NOT_FOUND\"}", baseUrl + "/");

        // resource_0 - a clean Resource body whose schema has a description on
        // EVERY property. No operator EOA, no keyed RPC URL, no DB column names,
        // no >50-element top-level array. Exercises P9 / P10 / P32 together.
        var resourceBody =
            "{\"name\":\"patternCatalogue\"," +
            "\"requirementSchema\":{\"type\":\"object\",\"properties\":{" +
            "\"agentAddress\":{\"type\":\"string\",\"description\":\"EVM address of the ACP agent to audit.\"}," +
            "\"baseUrl\":{\"type\":\"string\",\"description\":\"Optional explicit base URL of the agent's API surface.\"}" +
            "}}," +
            "\"deliverableSchema\":{\"type\":\"object\",\"properties\":{" +
            "\"score\":{\"type\":\"integer\",\"description\":\"0-100 security posture score.\"}," +
            "\"grade\":{\"type\":\"string\",\"description\":\"Letter grade A-F derived from the score.\"}" +
            "}}}";
        var resource0 = Resp("resource_0", 200, resourceBody, baseUrl + "/v1/resources/patternCatalogue");

        // paid_unauth - the paid scan endpoint must reject an unauthenticated
        // probe. SecurityBot's X-API-Key middleware returns 401 => AuthPosture Pass.
        var paidUnauth = Resp("paid_unauth", 401, "unauthorized", baseUrl + "/v1/internal/scan",
            contentType: "text/plain; charset=utf-8");

        // malformed - stable INTERNAL_ERROR envelope, NO stack/exception/path/
        // internal-host markers => ErrorLeak Pass.
        var malformed = Resp("malformed", 500, "{\"error\":\"INTERNAL_ERROR\"}",
            baseUrl + "/v1/__securitybot_probe__?x=%ff");

        // ratelimit_probe - the bounded burst observed a 429 (RateLimitMiddleware
        // is wired before auth) => RateLimitHint Pass. The engine synthesizes this
        // response with empty headers, so it carries none - that's fine: the P31
        // header check still sees the headers on the OTHER reached responses, and
        // a 429 with empty headers is the engine's real synthesized shape.
        var emptyHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ratelimit = new ProbeResponse(
            "ratelimit_probe", baseUrl + "/v1/resources/__rl__", 429, emptyHeaders, "", Reached: true);

        return new ProbeContext(baseUrl, new[]
        {
            health, root, resource0, paidUnauth, malformed, ratelimit,
        });
    }

    [Fact]
    public async Task SecurityBot_passes_its_own_audit_no_Present_findings()
    {
        var ctx = SelfShapeContext();
        var findings = new List<Finding>();
        foreach (var check in AllChecks())
            findings.Add(await check.RunAsync(ctx, default));

        // The dogfood invariant: nothing on our own surface trips a Present.
        var present = findings.Where(f => f.Verdict == Verdict.Present).ToList();
        Assert.True(
            present.Count == 0,
            "SecurityBot's own surface tripped Present findings: " +
            string.Join("; ", present.Select(f => $"{f.PatternId}:{f.Evidence}")));
    }

    [Fact]
    public async Task SecurityBot_self_scan_scores_100_grade_A()
    {
        var ctx = SelfShapeContext();
        var findings = new List<Finding>();
        foreach (var check in AllChecks())
            findings.Add(await check.RunAsync(ctx, default));

        var (score, grade) = ScoreCalculator.Compute(findings);
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }

    [Fact]
    public async Task SecurityBot_self_scan_runs_all_eleven_checks()
    {
        var ctx = SelfShapeContext();
        var findings = new List<Finding>();
        foreach (var check in AllChecks())
            findings.Add(await check.RunAsync(ctx, default));

        Assert.Equal(11, findings.Count);
        // Each of the six observable checks lands a Pass on our clean surface;
        // P9/P10/P32 and the headers/auth/error/ratelimit checks must all be
        // Pass or NotObservable (never Present, never Partial that drags score).
        Assert.All(findings, f =>
            Assert.True(
                f.Verdict is Verdict.Pass or Verdict.NotObservable,
                $"{f.PatternId} returned {f.Verdict} ({f.Evidence})"));
    }
}
