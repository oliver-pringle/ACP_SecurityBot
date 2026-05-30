namespace SecurityBot.Api.Engine;

public interface IProbeCheck
{
    string PatternId { get; }
    string Title { get; }
    Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct);
}
