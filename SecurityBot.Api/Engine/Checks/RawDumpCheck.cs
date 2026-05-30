using System.Text.Json;

namespace SecurityBot.Api.Engine.Checks;

// P10: a Resource that hands back a raw DB dump (whole-table read) leaks internal state.
// Heuristic: a json-typed resource body that is either a top-level array with > 50 elements,
// or whose text carries internal snake_case DB column names.
public sealed class RawDumpCheck : IProbeCheck
{
    public string PatternId => "P10";
    public string Title => "Resource returns raw DB dump";

    private static readonly string[] DbColumns =
    {
        "created_at",
        "updated_at",
        "payload_json",
        "webhook_secret",
        "last_run_at",
    };

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var resources = ctx.All
            .Where(r => r.Reached && r.Label.StartsWith("resource", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (resources.Count == 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Medium, Verdict.NotObservable,
                "no resource response was reached, so dump exposure could not be observed",
                PatternId));
        }

        foreach (var r in resources)
        {
            if (!IsJson(r)) continue;

            var body = r.Body ?? string.Empty;

            if (TryGetArrayLength(body, out var len) && len > 50)
            {
                return Present($"resource '{r.Label}' returned a top-level JSON array of {len} elements");
            }

            var hit = DbColumns.FirstOrDefault(c => body.Contains(c, StringComparison.Ordinal));
            if (hit is not null && IsParseableJson(body))
            {
                return Present($"resource '{r.Label}' body contains internal DB column '{hit}'");
            }
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Medium, Verdict.Pass,
            "no reached resource body looked like a raw DB dump",
            PatternId));
    }

    private static bool IsJson(ProbeResponse r)
        => r.Headers.TryGetValue("Content-Type", out var ct)
           && ct.Contains("application/json", StringComparison.OrdinalIgnoreCase);

    private static bool TryGetArrayLength(string body, out int length)
    {
        length = 0;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                length = doc.RootElement.GetArrayLength();
                return true;
            }
        }
        catch (JsonException) { }
        return false;
    }

    private static bool IsParseableJson(string body)
    {
        try
        {
            using var _ = JsonDocument.Parse(body);
            return true;
        }
        catch (JsonException) { return false; }
    }

    private Task<Finding> Present(string snippet) => Task.FromResult(new Finding(
        PatternId, Title, Severity.Medium, Verdict.Present, Truncate(snippet), PatternId));

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200];
}
