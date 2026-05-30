using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace SecurityBot.Api.Resolution;

// Best-effort, NON-THROWING fetch of an ACP v2 agent's advertised Resource URLs
// from the Virtuals V2 marketplace, used by MarketplaceTargetResolver's fetch
// delegate. Any error (network, non-2xx, unexpected JSON shape, parse failure)
// resolves to an EMPTY list so the resolver yields NOT_AUDITABLE rather than
// throwing a 500 out of the paid scan endpoint.
//
// TODO: confirm V2 marketplace resources[].url shape. The marketplace agent
// record shape is not pinned in this codebase yet; this reader walks several
// plausible locations (top-level resources[], data.resources[], agent.resources[])
// and pulls a "url" string off each entry. Tighten once the live shape is
// confirmed against api.acp.virtuals.io.
public static class MarketplaceResourceFetcher
{
    // V2 marketplace agent endpoint. Address is appended as the path segment.
    // Kept here (not in config) deliberately for v1; promote to options if the
    // host changes per-environment.
    private const string AgentEndpointBase = "https://api.acp.virtuals.io/api/agents/";

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

    private static IReadOnlyList<string> ExtractResourceUrls(JsonElement root)
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
