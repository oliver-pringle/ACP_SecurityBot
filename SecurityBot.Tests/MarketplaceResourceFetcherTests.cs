using System.Text.Json;
using SecurityBot.Api.Resolution;
using Xunit;

namespace SecurityBot.Tests;

// Pins the LIVE V2 marketplace agent shape confirmed 2026-05-30 against
// api.acp.virtuals.io/agents/wallet/<addr>:
//   { "data": { ..., "resources": [ { "name": ..., "url": "<absolute>" }, ... ] } }
// If Virtuals changes this shape, ExtractResourceUrls stops returning URLs and every
// agentAddress scan silently degrades to NOT_AUDITABLE — this test catches that.
public class MarketplaceResourceFetcherTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void Extracts_urls_from_live_data_resources_shape()
    {
        var json = """
        {
          "data": {
            "id": "019e7852-a08b-7f65-9ee4-20444e03e5e4",
            "name": "TheSecurityBot",
            "walletAddress": "0xa42b7122126245858c3cb0dcd0e4c151f3ea48d5",
            "resources": [
              { "id": 1, "name": "auditByAgent",     "url": "https://api.acp-metabot.dev/securitybot/v1/resources/auditByAgent" },
              { "id": 2, "name": "patternCatalogue", "url": "https://api.acp-metabot.dev/securitybot/v1/resources/patternCatalogue" }
            ]
          }
        }
        """;
        var urls = MarketplaceResourceFetcher.ExtractResourceUrls(Parse(json));
        Assert.Equal(2, urls.Count);
        Assert.Contains("https://api.acp-metabot.dev/securitybot/v1/resources/auditByAgent", urls);
        Assert.Contains("https://api.acp-metabot.dev/securitybot/v1/resources/patternCatalogue", urls);
    }

    [Fact]
    public void Returns_empty_when_no_resources_array()
    {
        var json = """{ "data": { "name": "x", "offerings": [] } }""";
        var urls = MarketplaceResourceFetcher.ExtractResourceUrls(Parse(json));
        Assert.Empty(urls);
    }

    [Fact]
    public void Skips_entries_without_a_url_string()
    {
        var json = """
        { "data": { "resources": [ { "name": "noUrl" }, { "name": "ok", "url": "https://h/securitybot/v1/resources/ok" } ] } }
        """;
        var urls = MarketplaceResourceFetcher.ExtractResourceUrls(Parse(json));
        Assert.Single(urls);
        Assert.Equal("https://h/securitybot/v1/resources/ok", urls[0]);
    }
}
