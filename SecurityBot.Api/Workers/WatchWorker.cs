namespace SecurityBot.Api.Workers;
using SecurityBot.Api.Engine;

// Pure diff between two scans of the same target. A finding is "open" when its
// verdict is Present or Partial (a posture gap we could externally observe);
// Pass / NotObservable / NotApplicable are not open. NewlyOpened is the set of
// pattern IDs that became open since the previous scan; NewlyClosed is the set
// that were open before and are no longer. The diff is by PatternId only — the
// watch tier signals "what changed", not the full finding bodies (those live in
// the persisted scan the buyer can pull separately).
public sealed record WatchDiffResult(IReadOnlyList<string> NewlyOpened, IReadOnlyList<string> NewlyClosed)
{
    public bool HasChanges => NewlyOpened.Count > 0 || NewlyClosed.Count > 0;
}

public static class WatchDiff
{
    private static bool IsOpen(Verdict v) => v is Verdict.Present or Verdict.Partial;

    public static WatchDiffResult Compute(IReadOnlyList<Finding> prev, IReadOnlyList<Finding> curr)
    {
        var prevOpen = prev.Where(f => IsOpen(f.Verdict)).Select(f => f.PatternId).ToHashSet();
        var currOpen = curr.Where(f => IsOpen(f.Verdict)).Select(f => f.PatternId).ToHashSet();
        var opened = currOpen.Where(id => !prevOpen.Contains(id)).OrderBy(x => x).ToList();
        var closed = prevOpen.Where(id => !currOpen.Contains(id)).OrderBy(x => x).ToList();
        return new WatchDiffResult(opened, closed);
    }
}
