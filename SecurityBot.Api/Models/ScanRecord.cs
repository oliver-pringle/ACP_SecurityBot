namespace SecurityBot.Api.Models;

public sealed record ScanRecord(
    string? AgentAddress,
    string BaseUrl,
    string ResolvedVia,
    int Score,
    string Grade,
    int ObservableCount,
    int FindingCount,
    string Verdict,
    string CorpusVersion,
    DateTime ScannedAtUtc);
