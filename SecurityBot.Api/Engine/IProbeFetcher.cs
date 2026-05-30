namespace SecurityBot.Api.Engine;

public interface IProbeFetcher
{
    Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct);
    int MaxRateLimitProbes { get; }
}
