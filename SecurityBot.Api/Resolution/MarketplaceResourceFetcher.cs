using System.Text.Json;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("SecurityBot.Tests")]

namespace SecurityBot.Api.Resolution;

// Best-effort, NON-THROWING fetch of an ACP v2 agent's advertised Resource URLs
// from the Virtuals V2 marketplace, used by MarketplaceTargetResolver's fetch
// delegate. Any error (network, non-2xx, unexpected JSON shape, parse failure)
// resolves to an EMPTY list so the resolver yields NOT_AUDITABLE rather than
// throwing a 500 out of the paid scan endpoint.
//
// V2 marketplace shape CONFIRMED 2026-05-30 against api.acp.virtuals.io: the agent
// record is { data: { ..., resources: [ { id, name, url, ... }, ... ] } } where each
// `url` is a full ABSOLUTE URL (e.g. https://api.acp-metabot.dev/<slug>/v1/resources/<name>
// for a path-prefixed bot, or https://api.acp-metabot.dev/v1/resources/<name> for the apex).
// ExtractResourceUrls still walks data.resources[] / top-level / agent.resources[]
// defensively, but data.resources[] is the live shape; the resolver derives the bot's
// probeable base from these URLs (see MarketplaceTargetResolver).
public static class MarketplaceResourceFetcher
{
    // V2 BY-WALLET agent endpoint. CONFIRMED: GET /agents/wallet/<addr> returns 200 with
    // the agent record; the earlier /api/agents/<addr> path 404s (which silently made every
    // agentAddress scan resolve to NOT_AUDITABLE). Address appended as the path segment.
    // Kept here (not in config) deliberately for v1; promote to options if the host changes.
    private const string AgentEndpointBase = "https://api.acp.virtuals.io/agents/wallet/";

    public static async Task<IReadOnlyList<string>> FetchAsync(
        IHttpClientFactory factory,
        ILogger logger,
        string agentAddress,
        CancellationToken ct)
    {
        try
        {
            var client = factory.CreateClient("marketplace");
            var url = AgentEndpointBase + Uri.EscapeDataString(agentAddress);

            using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return Array.Empty<string>();

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct)
                .ConfigureAwait(false);

            return ExtractResourceUrls(doc.RootElement);
        }
        catch (Exception ex)
        {
            // Best-effort: log host-only (no agentAddress / no URL with embedded
            // keys) and degrade to empty list -> NOT_AUDITABLE.
            logger.LogDebug(ex, "Marketplace resource fetch failed; treating as no auditable surface.");
            return Array.Empty<string>();
        }
    }

    internal static IReadOnlyList<string> ExtractResourceUrls(JsonElement root)
    {
        // Try the resources array at a few plausible locations.
        if (TryGetResourcesArray(root, out var resources))
        {
            var urls = new List<string>();
            foreach (var entry in resources.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object &&
                    entry.TryGetProperty("url", out var urlProp) &&
                    urlProp.ValueKind == JsonValueKind.String)
                {
                    var u = urlProp.GetString();
                    if (!string.IsNullOrWhiteSpace(u))
                        urls.Add(u!);
                }
            }
            return urls;
        }
        return Array.Empty<string>();
    }

    private static bool TryGetResourcesArray(JsonElement root, out JsonElement resources)
    {
        // top-level resources[]
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("resources", out resources) &&
            resources.ValueKind == JsonValueKind.Array)
            return true;

        // data.resources[] or agent.resources[]
        foreach (var wrapper in new[] { "data", "agent" })
        {
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty(wrapper, out var inner) &&
                inner.ValueKind == JsonValueKind.Object &&
                inner.TryGetProperty("resources", out resources) &&
                resources.ValueKind == JsonValueKind.Array)
                return true;
        }

        resources = default;
        return false;
    }
}
