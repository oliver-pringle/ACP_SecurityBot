using SecurityBot.Api.Resolution;

namespace SecurityBot.Tests;

// Test double for ITargetResolver: returns a fixed ResolvedTarget without any
// network call, and records the arguments it was invoked with so tests can
// assert the bind path threaded agentAddress/baseUrl through correctly.
internal sealed class FakeTargetResolver : ITargetResolver
{
    private readonly ResolvedTarget _result;

    public FakeTargetResolver(ResolvedTarget result) => _result = result;

    public int Calls { get; private set; }
    public string? LastAgentAddress { get; private set; }
    public string? LastBaseUrl { get; private set; }

    public Task<ResolvedTarget> ResolveAsync(string? agentAddress, string? baseUrl, CancellationToken ct)
    {
        Calls++;
        LastAgentAddress = agentAddress;
        LastBaseUrl = baseUrl;
        return Task.FromResult(_result);
    }

    // Resolves to an auditable surface (default: a path-prefixed bot base).
    public static FakeTargetResolver Auditable(string baseUrl = "https://api.acp-metabot.dev/securitybot") =>
        new(new ResolvedTarget(
            Auditable: true,
            BaseUrl: baseUrl,
            ResolvedVia: "marketplace",
            ResourceUrls: Array.Empty<string>(),
            Reason: null));

    // Resolves to NOT_AUDITABLE (agent has no externally-probeable surface).
    public static FakeTargetResolver NotAuditable(string reason = "agent exposes no externally-auditable surface (no registered resource URLs)") =>
        new(new ResolvedTarget(
            Auditable: false,
            BaseUrl: null,
            ResolvedVia: "marketplace",
            ResourceUrls: Array.Empty<string>(),
            Reason: reason));
}
