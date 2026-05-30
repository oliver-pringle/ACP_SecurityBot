using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Resolution;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SecurityBot.Tests;

// Endpoint-wiring tests for POST /v1/internal/scan. These assert the
// request-in -> deliverable-out contract, NOT the engine internals (covered by
// DynamicAuditEngineTests). The host is made hermetic two ways:
//   - ITargetResolver is replaced with a fake returning a fixed Auditable
//     target, so no marketplace HTTP fires.
//   - IProbeFetcher is replaced with a fake returning reached:false for every
//     probe, so the real ProbeClient never touches the network. The 8 checks
//     all return NotObservable against unreached probes, so the scan completes
//     deterministically and writes a real scan row to a temp SQLite file.
public class ScanEndpointTests
{
    private const string TestApiKey = "test-internal-key";

    // A WebApplicationFactory that overrides DI for hermetic, network-free runs.
    private sealed class ScanFactory : WebApplicationFactory<Program>
    {
        protected override IHost CreateHost(IHostBuilder builder)
        {
            // Point the SQLite connection at a throwaway temp file + set the
            // internal API key BEFORE the app builds (Program reads both from
            // configuration / env). Env environment stays the default "Production"
            // unless overridden; the API-key middleware is active and we send the
            // key on every request below.
            var dbPath = Path.Combine(Path.GetTempPath(), $"securitybot-scan-test-{Guid.NewGuid():N}.db");
            builder.ConfigureHostConfiguration(cfg =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sqlite"] = $"Data Source={dbPath};Cache=Shared",
                    ["ApiKey"] = TestApiKey,
                    // Keep the bot in Development so the non-Dev boot guards
                    // (webhook cipher requirement etc.) don't fire in-test.
                    ["ASPNETCORE_ENVIRONMENT"] = "Development",
                });
            });

            builder.ConfigureServices(services =>
            {
                // Fake resolver: every request resolves to the same Auditable
                // target regardless of input (the second test posts {} and relies
                // on the REAL resolver returning NOT_AUDITABLE, so that test uses a
                // different factory below).
                services.RemoveAll<ITargetResolver>();
                services.AddSingleton<ITargetResolver>(new FakeResolver(auditable: true));

                // Fake fetcher: reached:false for everything -> no network.
                services.RemoveAll<IProbeFetcher>();
                services.AddSingleton<IProbeFetcher>(new FakeFetcher());
            });

            return base.CreateHost(builder);
        }
    }

    // Variant factory whose resolver always returns NOT_AUDITABLE, to exercise
    // the non-auditable deliverable branch deterministically.
    private sealed class NotAuditableFactory : WebApplicationFactory<Program>
    {
        protected override IHost CreateHost(IHostBuilder builder)
        {
            var dbPath = Path.Combine(Path.GetTempPath(), $"securitybot-scan-test-{Guid.NewGuid():N}.db");
            builder.ConfigureHostConfiguration(cfg =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sqlite"] = $"Data Source={dbPath};Cache=Shared",
                    ["ApiKey"] = TestApiKey,
                    ["ASPNETCORE_ENVIRONMENT"] = "Development",
                });
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<ITargetResolver>();
                services.AddSingleton<ITargetResolver>(new FakeResolver(auditable: false));
                services.RemoveAll<IProbeFetcher>();
                services.AddSingleton<IProbeFetcher>(new FakeFetcher());
            });
            return base.CreateHost(builder);
        }
    }

    private sealed class FakeResolver : ITargetResolver
    {
        private readonly bool _auditable;
        public FakeResolver(bool auditable) => _auditable = auditable;

        public Task<ResolvedTarget> ResolveAsync(string? agentAddress, string? baseUrl, CancellationToken ct)
            => Task.FromResult(_auditable
                ? new ResolvedTarget(true, "https://x.example", "baseUrl", Array.Empty<string>(), null)
                : new ResolvedTarget(false, null, "none", Array.Empty<string>(),
                    "agentAddress or baseUrl is required"));
    }

    private sealed class FakeFetcher : IProbeFetcher
    {
        public int MaxRateLimitProbes => 1;

        public Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)
            => Task.FromResult(new ProbeResponse(
                label, url, 0,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                string.Empty, false));
    }

    private static HttpClient Authed(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", TestApiKey);
        return client;
    }

    [Fact]
    public async Task Auditable_scan_returns_deliverable_without_email_delivery()
    {
        using var factory = new ScanFactory();
        using var client = Authed(factory);

        var resp = await client.PostAsJsonAsync("/v1/internal/scan", new { baseUrl = "https://x.example" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;

        // Deliverable contract fields all present.
        Assert.True(root.TryGetProperty("score", out _));
        Assert.True(root.TryGetProperty("grade", out _));
        Assert.True(root.TryGetProperty("findings", out var findings));
        Assert.Equal(JsonValueKind.Array, findings.ValueKind);
        Assert.True(root.TryGetProperty("observableCount", out _));
        Assert.True(root.TryGetProperty("totalPatterns", out _));
        Assert.True(root.TryGetProperty("resolvedVia", out _));
        Assert.True(root.TryGetProperty("summary", out _));
        Assert.True(root.TryGetProperty("verdict", out _));

        // emailReport was not set -> no _emailDelivery key.
        Assert.False(root.TryGetProperty("_emailDelivery", out _));

        // Severity / Verdict in each finding must be STRINGS, not ints.
        foreach (var f in findings.EnumerateArray())
        {
            Assert.Equal(JsonValueKind.String, f.GetProperty("severity").ValueKind);
            Assert.Equal(JsonValueKind.String, f.GetProperty("verdict").ValueKind);
        }
    }

    [Fact]
    public async Task Neither_target_provided_returns_not_auditable()
    {
        using var factory = new NotAuditableFactory();
        using var client = Authed(factory);

        var resp = await client.PostAsJsonAsync("/v1/internal/scan", new { });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("NOT_AUDITABLE", doc.RootElement.GetProperty("verdict").GetString());
    }
}
