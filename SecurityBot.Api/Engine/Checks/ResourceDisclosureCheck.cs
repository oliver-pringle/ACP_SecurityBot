using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P9: free Resource bodies must not leak operator/owner EOAs or RPC URLs with embedded
// API keys. We inspect every reached response whose label starts with "resource".
public sealed partial class ResourceDisclosureCheck : IProbeCheck
{
    public string PatternId => "P9";
    public string Title => "Resource body discloses operator address or keyed RPC URL";

    // 0x + 40 hex paired with an operator/owner/deployer key.
    [GeneratedRegex(
        @"(operatorAddress|ownerAddress|operator|owner|deployer)[""'\s:]{0,8}(0x[0-9a-fA-F]{40})",
        RegexOptions.IgnoreCase)]
    private static partial Regex KeyedEoaRegex();

    // Alchemy / Infura keyed paths, or any url carrying ?key=/?apikey=/&apikey=.
    [GeneratedRegex(
        @"(alchemy\.com/v2/[^\s""'<>]+|infura\.io/v3/[^\s""'<>]+|[?&](apikey|key)=[^\s""'<>&]+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex KeyedRpcUrlRegex();

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var resources = ctx.All
            .Where(r => r.Reached && r.Label.StartsWith("resource", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (resources.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.High, Verdict.NotObservable,
                "no resource response was reached, so disclosure could not be observed",
                PatternId));
        }

        foreach (var r in resources)
        {
            var body = r.Body ?? string.Empty;

            var eoa = KeyedEoaRegex().Match(body);
            if (eoa.Success)
            {
                return Present($"resource '{r.Label}' discloses operator/owner EOA: {eoa.Value}");
            }

            var rpc = KeyedRpcUrlRegex().Match(body);
            if (rpc.Success)
            {
                return Present($"resource '{r.Label}' discloses keyed RPC URL: {rpc.Value}");
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.High, Verdict.Pass,
            "no operator EOA or keyed RPC URL found in reached resource bodies",
            PatternId));
    }

    private Task<Finding> Present(string snippet) => Task.FromResult(new Finding(
        PatternId, Title, Severity.High, Verdict.Present, Truncate(snippet), PatternId));

    private static string Truncate(string s) => s.Length <= 120 ? s : s[..120];
}
