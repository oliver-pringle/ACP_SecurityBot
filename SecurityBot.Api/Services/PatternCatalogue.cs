using System.Text.Json;

namespace SecurityBot.Api.Services;

// One entry from the SecurityBot pattern catalogue
// (Data/catalogue/patterns.json). Mirrors the JSON object shape 1:1:
//   { id, title, severity, detection, canonicalFix, referenceBot }.
// Severity is kept as the catalogue's string ("Info"/"Low"/"Medium"/"High"/
// "Critical") rather than the Engine.Severity enum — the catalogue is reference
// metadata, not a live finding, and the marketplace-facing rubric surfaces the
// raw string.
public sealed record PatternEntry(
    string Id,
    string Title,
    string Severity,
    string Detection,
    string CanonicalFix,
    string ReferenceBot);

// Loads + indexes the pattern catalogue from disk. The full corpus the bot
// audits against (P1-P64 cross-cutting + P31-TLS + B1-B9 bot-specific = 74
// entries as of corpus 2026-06-08).
//
// File-location choice: production uses the parameterless ctor, which resolves
// the file copied next to the API assembly (AppContext.BaseDirectory +
// Data/catalogue/patterns.json — the csproj <None Include CopyToOutputDirectory>
// puts it there). Tests use the (string path) ctor pointed at the in-repo source
// file, so they don't depend on the test project transitively copying the API's
// content file.
public sealed class PatternCatalogue
{
    public const string DefaultCorpusVersion = "2026-06-08";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly List<PatternEntry> _all;
    private readonly Dictionary<string, PatternEntry> _byId;

    public string CorpusVersion { get; }

    // Production ctor — loads the copy placed next to the API assembly.
    public PatternCatalogue()
        : this(Path.Combine(AppContext.BaseDirectory, "Data", "catalogue", "patterns.json"))
    {
    }

    // Explicit-path ctor — used by tests (points at the in-repo source file) and
    // any future operator override.
    public PatternCatalogue(string path)
    {
        CorpusVersion = DefaultCorpusVersion;

        var json = File.ReadAllText(path);
        var entries = JsonSerializer.Deserialize<List<PatternEntry>>(json, JsonOptions)
            ?? throw new InvalidOperationException(
                $"Pattern catalogue at '{path}' deserialized to null.");

        _all = entries;
        _byId = new Dictionary<string, PatternEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            // Last-writer-wins on a duplicate id; the catalogue is curated so this
            // should never trigger, but never throw at load over a dupe.
            _byId[e.Id] = e;
        }
    }

    public IReadOnlyList<PatternEntry> All() => _all;

    public PatternEntry? Get(string id)
        => _byId.TryGetValue(id, out var e) ? e : null;
}
