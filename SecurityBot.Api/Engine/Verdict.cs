namespace SecurityBot.Api.Engine;

public enum Severity { Info, Low, Medium, High, Critical }

// Honest about a dynamic audit's limits: NotObservable is first-class.
public enum Verdict { Present, Partial, Pass, NotObservable, NotApplicable }

public sealed record Finding(
    string PatternId,
    string Title,
    Severity Severity,
    Verdict Verdict,
    string Evidence,
    string FixRef);

// One fetched response from the probe-once pass.
public sealed record ProbeResponse(
    string Label,
    string Url,
    int StatusCode,
    IReadOnlyDictionary<string, string> Headers,
    string Body,
    bool Reached);

// Shared, read-only bag of probe results handed to every check.
public sealed class ProbeContext
{
    public string BaseUrl { get; }
    private readonly Dictionary<string, ProbeResponse> _byLabel;

    public ProbeContext(string baseUrl, IEnumerable<ProbeResponse> responses)
    {
        BaseUrl = baseUrl;
        _byLabel = new Dictionary<string, ProbeResponse>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in responses) _byLabel[r.Label] = r;
    }

    public bool TryGet(string label, out ProbeResponse? response)
        => _byLabel.TryGetValue(label, out response);

    public IEnumerable<ProbeResponse> All => _byLabel.Values;
}
