namespace SecurityBot.Api.Resolution;

// Turns a buyer's { agentAddress?, baseUrl? } into a probeable base URL.
//
// The actual marketplace HTTP call is abstracted behind a Func delegate so the
// resolution LOGIC is unit-tested without network. Only the delegate touches the
// network; in production it is wired to a small HttpClient GET against the
// Virtuals V2 marketplace agent endpoint (api.acp.virtuals.io) that parses the
// agent's registered resources[].url fields. That wiring lives in DI and is NOT
// part of this type's unit tests.
public sealed class MarketplaceTargetResolver : ITargetResolver
{
    private static readonly IReadOnlyList<string> Empty = Array.Empty<string>();

    private readonly Func<string, CancellationToken, Task<IReadOnlyList<string>>> _fetchResourceUrls;

    public MarketplaceTargetResolver(
        Func<string, CancellationToken, Task<IReadOnlyList<string>>> fetchResourceUrls)
    {
        _fetchResourceUrls = fetchResourceUrls
            ?? throw new ArgumentNullException(nameof(fetchResourceUrls));
    }

    public async Task<ResolvedTarget> ResolveAsync(string? agentAddress, string? baseUrl, CancellationToken ct)
    {
        // 1. Explicit baseUrl wins (and short-circuits the marketplace lookup).
        if (!string.IsNullOrWhiteSpace(baseUrl))
        {
            if (TryNormalizeBase(baseUrl, out var normalized))
            {
                return new ResolvedTarget(
                    Auditable: true,
                    BaseUrl: normalized,
                    ResolvedVia: "baseUrl",
                    ResourceUrls: Empty,
                    Reason: null);
            }

            return new ResolvedTarget(
                Auditable: false,
                BaseUrl: null,
                ResolvedVia: "baseUrl",
                ResourceUrls: Empty,
                Reason: "baseUrl must be an absolute http(s) URL");
        }

        // 2. Resolve from the marketplace by agentAddress.
        if (!string.IsNullOrWhiteSpace(agentAddress))
        {
            var urls = await _fetchResourceUrls(agentAddress, ct).ConfigureAwait(false)
                       ?? Empty;

            string? derivedBase = null;
            foreach (var url in urls)
            {
                if (TryNormalizeBase(url, out var normalized))
                {
                    derivedBase = normalized;
                    break;
                }
            }

            if (derivedBase is not null)
            {
                return new ResolvedTarget(
                    Auditable: true,
                    BaseUrl: derivedBase,
                    ResolvedVia: "marketplace",
                    ResourceUrls: urls,
                    Reason: null);
            }

            return new ResolvedTarget(
                Auditable: false,
                BaseUrl: null,
                ResolvedVia: "marketplace",
                ResourceUrls: urls,
                Reason: "agent exposes no externally-auditable surface (no registered resource URLs)");
        }

        // 3. Neither provided.
        return new ResolvedTarget(
            Auditable: false,
            BaseUrl: null,
            ResolvedVia: "none",
            ResourceUrls: Empty,
            Reason: "agentAddress or baseUrl is required");
    }

    // Parse an absolute http(s) URL and derive the bot's probeable BASE.
    //
    // A registered Resource URL looks like https://host/<prefix>/v1/resources/<name>, so we
    // strip the path at the first "/v1/" segment and keep everything before it:
    //   https://api.acp-metabot.dev/securitybot/v1/resources/auditByAgent
    //     -> https://api.acp-metabot.dev/securitybot   (path-prefixed bot: KEEP the prefix)
    //   https://api.acp-metabot.dev/v1/resources/sellerDiagnose
    //     -> https://api.acp-metabot.dev               (apex bot: no prefix)
    // Reducing to scheme://authority instead would drop the /<prefix> and probe the apex
    // gateway (TheMetaBot) instead of the target bot. A bare host or a non-/v1 URL keeps its
    // path as-is. Query/fragment are always dropped. The result is SSRF-safe to hand to the
    // engine: ProbeClient re-classifies every resolved IP at connect time (inverse pin).
    private static bool TryNormalizeBase(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value)) return false;

        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) return false;

        var path = u.AbsolutePath; // excludes query + fragment
        var v1 = path.IndexOf("/v1/", StringComparison.OrdinalIgnoreCase);
        var basePath = (v1 >= 0 ? path[..v1] : path).TrimEnd('/');

        normalized = $"{u.Scheme}://{u.Authority}{basePath}";
        return true;
    }
}
