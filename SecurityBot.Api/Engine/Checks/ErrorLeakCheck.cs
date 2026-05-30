using System.Text.RegularExpressions;

namespace SecurityBot.Api.Engine.Checks;

// P30: error responses must return stable codes, not framework stack traces, library names,
// container paths, or internal docker hostnames. The engine sends a malformed request and
// labels the response "malformed"; we scan its body for leak markers.
public sealed partial class ErrorLeakCheck : IProbeCheck
{
    public string PatternId => "P30";
    public string Title => "Error response leaks internal detail";

    // Case-sensitive literal markers.
    private static readonly string[] Markers =
    {
        "at System.",
        "Exception:",
        "Microsoft.Data.Sqlite",
        "/app/",
    };

    // Internal docker hostname like "<bot>-api:5000".
    [GeneratedRegex(@"[a-z0-9_-]+-api:5000")]
    private static partial Regex InternalHostRegex();

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        if (!ctx.TryGet("malformed", out var r) || r is null || !r.Reached)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.NotObservable,
                "the malformed-request probe was not reached, so error leakage could not be observed",
                PatternId));
        }

        var body = r.Body ?? string.Empty;

        var marker = Markers.FirstOrDefault(m => body.Contains(m, StringComparison.Ordinal));
        if (marker is not null)
        {
            return Present($"error body leaks marker '{marker}'");
        }

        var host = InternalHostRegex().Match(body);
        if (host.Success)
        {
            return Present($"error body leaks internal docker host '{host.Value}'");
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Medium, Verdict.Pass,
            "malformed-request error body contained no internal-leak markers",
            PatternId));
    }

    private Task<Finding> Present(string snippet) => Task.FromResult(new Finding(
        PatternId, Title, Severity.Medium, Verdict.Present, Truncate(snippet), PatternId));

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200];
}
