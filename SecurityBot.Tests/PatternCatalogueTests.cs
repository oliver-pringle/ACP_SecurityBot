using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

// Loads the REAL catalogue file (SecurityBot.Api/Data/catalogue/patterns.json,
// 74 entries: P1-P64 + P31-TLS + B1-B9). The test points the (string path) ctor
// at the in-repo source file, located relative to the test assembly so it works
// regardless of CWD. The parameterless ctor (AppContext.BaseDirectory) is what
// production uses; the csproj copies the file into the API output for that path.
public class PatternCatalogueTests
{
    private static string SourceCataloguePath()
    {
        // Test assembly runs from SecurityBot.Tests/bin/Debug/net10.0/. Walk up to
        // the repo root, then into SecurityBot.Api/Data/catalogue/patterns.json.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null &&
               !File.Exists(Path.Combine(dir.FullName, "SecurityBot.sln")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "SecurityBot.Api", "Data", "catalogue", "patterns.json");
    }

    [Fact]
    public void Loads_all_74_patterns()
    {
        var cat = new PatternCatalogue(SourceCataloguePath());
        Assert.Equal(74, cat.All().Count);
    }

    [Fact]
    public void P31_is_Low_severity()
    {
        var cat = new PatternCatalogue(SourceCataloguePath());
        var p31 = cat.Get("P31");
        Assert.NotNull(p31);
        Assert.Equal("Low", p31!.Severity);
    }

    [Fact]
    public void P9_is_present()
    {
        var cat = new PatternCatalogue(SourceCataloguePath());
        Assert.NotNull(cat.Get("P9"));
    }
}
