using System.Net;
using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SecurityBot.Tests;

// Endpoint-wiring tests for the two free public Resources:
//   GET /v1/resources/patternCatalogue  (no DB, no secrets)
//   GET /v1/resources/auditByAgent      (reads ScanRepository)
//
// Both MUST be reachable WITHOUT the X-API-Key header (the middleware whitelists
// /v1/resources/* alongside /health). auditByAgent is summary-only: it returns
// per-severity counts + score/grade but NEVER raw evidence or the scanned URL
// (P9/P10 self-application) — the no-leak assertions below pin that contract.
public class ResourceEndpointTests
{
    private const string TestApiKey = "test-internal-key";

    // A WebApplicationFactory with NO DI fakes — patternCatalogue needs none and
    // auditByAgent reads the real ScanRepository against a fresh (empty) temp DB.
    // The internal API key IS configured so the middleware is in key-required
    // mode; the Resources tests deliberately send NO key to prove the bypass.
    private sealed class ResourceFactory : WebApplicationFactory<Program>
    {
        public string DbPath { get; } =
            Path.Combine(Path.GetTempPath(), $"securitybot-resource-test-{Guid.NewGuid():N}.db");

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(cfg =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sqlite"] = $"Data Source={DbPath};Cache=Shared",
                    ["ApiKey"] = TestApiKey,
                    ["ASPNETCORE_ENVIRONMENT"] = "Development",
                });
            });
            return base.CreateHost(builder);
        }
    }

    [Fact]
    public async Task PatternCatalogue_returns_81_entries()
    {
        using var factory = new ResourceFactory();
        // NO X-API-Key header — the Resource is public.
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/v1/resources/patternCatalogue");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("patterns", out var patterns));
        Assert.Equal(JsonValueKind.Array, patterns.ValueKind);
        // 2026-06-14: P1-P64 + B1-B9 (74) + P65-P68 + B10-B12 (ChainlinkBot audit) = 81.
        Assert.Equal(81, patterns.GetArrayLength());
        // count field mirrors the array length.
        Assert.Equal(81, root.GetProperty("count").GetInt32());
    }

    [Fact]
    public async Task AuditByAgent_returns_found_false_when_no_scan()
    {
        using var factory = new ResourceFactory();
        // NO X-API-Key header — the Resource is public.
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/v1/resources/auditByAgent?agentAddress=0xabc");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.False(doc.RootElement.GetProperty("found").GetBoolean());

        // P9/P10 self-application — this public resource never leaks raw evidence
        // strings or the scanned base URL.
        Assert.DoesNotContain("evidence", body);
        Assert.DoesNotContain("base_url", body);
    }

    [Fact]
    public async Task AuditByAgent_returns_summary_without_evidence_or_url_when_scan_exists()
    {
        using var factory = new ResourceFactory();
        // Seed a scan via the registered ScanRepository so the found==true path
        // is exercised against a real persisted row.
        var scans = factory.Services.GetRequiredService<ScanRepository>();
        var findings = new[]
        {
            new Finding("P31", "Missing headers", Severity.High, Verdict.Present, "no CSP", "P31"),
            new Finding("P9", "Disclosure", Severity.Low, Verdict.Present, "leaks", "P9"),
            new Finding("P10", "Raw dump", Severity.Medium, Verdict.Pass, "clean", "P10"),
        };
        var rec = new ScanRecord(
            AgentAddress: "0xfeed",
            BaseUrl: "https://secret.example/internal",
            ResolvedVia: "agentAddress",
            Score: 71, Grade: "C",
            ObservableCount: 3, FindingCount: 3,
            Verdict: "AUDITED",
            CorpusVersion: "2026-05-30",
            ScannedAtUtc: DateTime.UtcNow);
        await scans.InsertAsync(rec, findings);

        // NO X-API-Key header — the Resource is public.
        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/v1/resources/auditByAgent?agentAddress=0xfeed");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        Assert.True(root.GetProperty("found").GetBoolean());
        Assert.Equal(71, root.GetProperty("score").GetInt32());
        Assert.Equal("C", root.GetProperty("grade").GetString());

        // Per-severity counts present — only OPEN findings (Pass excluded).
        var counts = root.GetProperty("severityCounts");
        Assert.Equal(1, counts.GetProperty("High").GetInt32());
        Assert.Equal(1, counts.GetProperty("Low").GetInt32());
        Assert.False(counts.TryGetProperty("Medium", out _)); // the Pass is excluded

        // P9/P10 self-application — no raw evidence, no scanned URL leak. The
        // scanned base URL "secret.example/internal" must not appear anywhere.
        Assert.DoesNotContain("evidence", body);
        Assert.DoesNotContain("base_url", body);
        Assert.DoesNotContain("baseUrl", body);
        Assert.DoesNotContain("secret.example", body);
        Assert.DoesNotContain("no CSP", body);
    }
}
