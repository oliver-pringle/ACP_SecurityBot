namespace SecurityBot.Api.Services;

public static class RetryBackoff
{
    public const int MaxAttempts = 5;

    private static readonly TimeSpan[] Schedule =
    {
        TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromMinutes(10),
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(6),
    };

    public static TimeSpan DelayFor(int attempts)
    {
        if (attempts < 1) throw new ArgumentOutOfRangeException(nameof(attempts), "attempts must be >= 1");
        var idx = Math.Min(attempts - 1, Schedule.Length - 1);
        return Schedule[idx];
    }

    public static bool IsExhausted(int attempts) => attempts >= MaxAttempts;
}
