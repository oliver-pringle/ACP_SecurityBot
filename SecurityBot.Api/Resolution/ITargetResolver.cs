namespace SecurityBot.Api.Resolution;

// The outcome of turning a buyer's { agentAddress?, baseUrl? } into a probeable
// base URL. When Auditable is false the scan is NOT_AUDITABLE - a normal outcome,
// not an error. Reason carries a buyer-facing explanation in that case.
public sealed record ResolvedTarget(
    bool Auditable,
    string? BaseUrl,
    string ResolvedVia,
    IReadOnlyList<string> ResourceUrls,
    string? Reason);

public interface ITargetResolver
{
    Task<ResolvedTarget> ResolveAsync(string? agentAddress, string? baseUrl, CancellationToken ct);
}
