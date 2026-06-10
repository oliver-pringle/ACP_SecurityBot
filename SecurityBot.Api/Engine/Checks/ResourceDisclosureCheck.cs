using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P9: free Resource bodies must not leak operator/owner EOAs, RPC URLs with embedded
// API keys, or any cloud / LLM / VCS credential or private-key block. We inspect every
// reached response whose label starts with "resource".
public sealed partial class ResourceDisclosureCheck : IProbeCheck
{
    public string PatternId => "P9";
    public string Title => "Resource body discloses operator address, keyed RPC URL, or credential";

    // 0x + 40 hex paired with an operator/owner/deployer key.
    [GeneratedRegex(
        @"(operatorAddress|ownerAddress|operator|owner|deployer)[""'\s:]{0,8}(0x[0-9a-fA-F]{40})",
        RegexOptions.IgnoreCase)]
    private static partial Regex KeyedEoaRegex();

    // Alchemy / Infura keyed paths, or any url carrying ?key=/?api[-_]key=/&apikey=.
    [GeneratedRegex(
        @"(alchemy\.com/v2/[^\s""'<>]+|infura\.io/v3/[^\s""'<>]+|[?&](apikey|api[_-]?key|key)=[^\s""'<>&]+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex KeyedRpcUrlRegex();

    // High-precision credential markers that P9 must also catch in a served body:
    //   - OpenAI (sk-… / sk-proj-…) and Anthropic (sk-ant-…) API keys
    //   - AWS access-key ids (AKIA + 16 upper-alnum)
    //   - GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_ + 30+; github_pat_ + 40+)
    //   - any PEM PRIVATE KEY header
    // Length floors keep these off ordinary prose; the live patternCatalogue Resource
    // carries none of these tokens (verified), so the dogfood self-scan stays clean.
    [GeneratedRegex(
        @"(sk-ant-[A-Za-z0-9_-]{16,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|-----BEGIN[A-Z ]{0,40}PRIVATE KEY-----)")]
    private static partial Regex CredentialRegex();

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

            var cred = CredentialRegex().Match(body);
            if (cred.Success)
            {
                // Mask the matched secret so the finding itself never re-leaks it.
                return Present($"resource '{r.Label}' discloses a credential/secret: {Mask(cred.Value)}");
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.High, Verdict.Pass,
            "no operator EOA, keyed RPC URL, or credential found in reached resource bodies",
            PatternId));
    }

    private Task<Finding> Present(string snippet) => Task.FromResult(new Finding(
        PatternId, Title, Severity.High, Verdict.Present, Truncate(snippet), PatternId));

    private static string Truncate(string s) => s.Length <= 120 ? s : s[..120];

    // Show only a short, non-actionable prefix of a detected secret (enough to
    // identify the kind), then redact the rest — the finding is buyer-visible.
    private static string Mask(string secret)
    {
        var head = secret.Length <= 8 ? secret : secret[..8];
        return $"{head}…(redacted, {secret.Length} chars)";
    }
}
