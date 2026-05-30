using SecurityBot.Api.Engine;

namespace SecurityBot.Tests;

public static class Fixtures
{
    public static ProbeResponse Resp(
        string label,
        int status = 200,
        IDictionary<string, string>? headers = null,
        string body = "{}",
        bool reached = true,
        string url = "https://x.example/p")
        => new(label, url, status,
               new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
               body, reached);

    public static ProbeContext Ctx(params ProbeResponse[] responses)
        => new("https://x.example", responses);
}
