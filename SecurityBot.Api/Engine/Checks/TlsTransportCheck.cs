namespace SecurityBot.Api.Engine.Checks;

// P31 (transport): the surface should be reached over TLS, and HSTS should be observed at
// the edge. A plaintext http base URL is a finding; https with HSTS passes; https without
// observed HSTS is partial (the TLS-terminating edge may still emit it on other paths).
public sealed class TlsTransportCheck : IProbeCheck
{
    public string PatternId => "P31";
    public string Title => "TLS transport and HSTS";

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var isHttps = ctx.BaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        if (!isHttps)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.Present,
                $"base URL is plaintext http: {Truncate(ctx.BaseUrl)}",
                PatternId));
        }

        var reached = ctx.All.Where(r => r.Reached).ToList();
        if (reached.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.NotObservable,
                "https base URL but no response was reached, so HSTS could not be observed",
                PatternId));
        }

        var hasHsts = reached.Any(r => r.Headers.ContainsKey("Strict-Transport-Security"));
        if (hasHsts)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.Pass,
                "https with Strict-Transport-Security observed",
                PatternId));
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Medium, Verdict.Partial,
            "https but no HSTS observed (edge may emit it)",
            PatternId));
    }

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200];
}
