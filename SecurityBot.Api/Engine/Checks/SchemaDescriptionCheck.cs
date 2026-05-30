using System.Text.Json;

namespace SecurityBot.Api.Engine.Checks;

// P32: every property in a requirement/deliverable schema should carry a description.
// We walk reached resource bodies for any object under a "properties" key and count the
// child property objects that lack a "description" field.
public sealed class SchemaDescriptionCheck : IProbeCheck
{
    public string PatternId => "P32";
    public string Title => "Schema property descriptions";

    public Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct)
    {
        var resources = ctx.All
            .Where(r => r.Reached && r.Label.StartsWith("resource", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (resources.Count == 0)
        {
            return Task.FromResult(NotObservable(
                "no resource response was reached, so schema descriptions could not be observed"));
        }

        var sawPropertiesObject = false;
        var totalProps = 0;
        var missing = 0;

        foreach (var r in resources)
        {
            JsonDocument? doc = null;
            try { doc = JsonDocument.Parse(r.Body ?? string.Empty); }
            catch (JsonException) { continue; }

            using (doc)
            {
                WalkForProperties(doc.RootElement, ref sawPropertiesObject, ref totalProps, ref missing);
            }
        }

        if (!sawPropertiesObject)
        {
            return Task.FromResult(NotObservable(
                "no reached resource body exposed a 'properties' schema object"));
        }

        if (missing > 0)
        {
            return Task.FromResult(new Finding(
                PatternId, Title, Severity.Low, Verdict.Partial,
                Truncate($"{missing} of {totalProps} schema propert{(totalProps == 1 ? "y" : "ies")} lack a description"),
                PatternId));
        }

        return Task.FromResult(new Finding(
            PatternId, Title, Severity.Low, Verdict.Pass,
            $"all {totalProps} observed schema properties carry a description",
            PatternId));
    }

    // Recursively find every object value under a "properties" key, and inspect its children.
    private static void WalkForProperties(JsonElement el, ref bool sawPropertiesObject, ref int total, ref int missing)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    if (prop.NameEquals("properties") && prop.Value.ValueKind == JsonValueKind.Object)
                    {
                        sawPropertiesObject = true;
                        foreach (var child in prop.Value.EnumerateObject())
                        {
                            if (child.Value.ValueKind == JsonValueKind.Object)
                            {
                                total++;
                                if (!child.Value.TryGetProperty("description", out _))
                                {
                                    missing++;
                                }
                            }
                        }
                    }

                    WalkForProperties(prop.Value, ref sawPropertiesObject, ref total, ref missing);
                }
                break;

            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                {
                    WalkForProperties(item, ref sawPropertiesObject, ref total, ref missing);
                }
                break;
        }
    }

    private Finding NotObservable(string evidence) => new(
        PatternId, Title, Severity.Low, Verdict.NotObservable, Truncate(evidence), PatternId);

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200];
}
