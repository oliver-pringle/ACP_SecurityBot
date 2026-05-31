using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SecurityBot.Tests;

// GET /v1/resources/offerings — the free introspection Resource the website's
// admin "run console" (BotRunController) reads to discover each offering's
// requirementSchema + the internal self-test path. Must be public (whitelisted
// alongside /health by the X-API-Key middleware). Mirrors acp-v2/src/offerings/*.
public class OfferingsResourceTests
{
    private sealed class Factory : WebApplicationFactory<Program>
    {
        public string DbPath { get; } =
            Path.Combine(Path.GetTempPath(), $"securitybot-offerings-test-{Guid.NewGuid():N}.db");

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(cfg =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Sqlite"] = $"Data Source={DbPath};Cache=Shared",
                    ["ApiKey"] = "test-internal-key",
                    ["ASPNETCORE_ENVIRONMENT"] = "Development",
                }));
            return base.CreateHost(builder);
        }
    }

    [Fact]
    public async Task Offerings_is_public_and_describes_scan_and_watch()
    {
        using var factory = new Factory();
        using var client = factory.CreateClient(); // NO X-API-Key — must be public

        var resp = await client.GetAsync("/v1/resources/offerings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.True(root.GetProperty("supported").GetBoolean());

        var offerings = root.GetProperty("offerings");
        Assert.Equal(JsonValueKind.Array, offerings.ValueKind);

        JsonElement scan = default, watch = default;
        bool foundScan = false, foundWatch = false;
        foreach (var o in offerings.EnumerateArray())
        {
            var name = o.GetProperty("name").GetString();
            if (name == "security_scan") { scan = o; foundScan = true; }
            if (name == "security_watch") { watch = o; foundWatch = true; }
        }
        Assert.True(foundScan, "security_scan present");
        Assert.True(foundWatch, "security_watch present");

        // security_scan is runnable via the internal self-test path + carries a schema.
        Assert.Equal("/v1/internal/scan", scan.GetProperty("internalPath").GetString());
        Assert.Equal(JsonValueKind.Object, scan.GetProperty("requirementSchema").ValueKind);

        // security_watch is a subscription -> not runnable (internalPath null).
        Assert.Equal(JsonValueKind.Null, watch.GetProperty("internalPath").ValueKind);
    }
}
