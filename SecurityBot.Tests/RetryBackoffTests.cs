using Xunit;
using SecurityBot.Api.Services;

namespace SecurityBot.Tests;

public class RetryBackoffTests
{
    [Theory]
    [InlineData(1, 30)]      // 30s
    [InlineData(2, 120)]     // 2m
    [InlineData(3, 600)]     // 10m
    [InlineData(4, 3600)]    // 1h
    [InlineData(5, 21600)]   // 6h
    public void DelaySeconds_for_attempt(int attempts, int expectedSeconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), RetryBackoff.DelayFor(attempts));
    }

    [Fact]
    public void IsExhausted_true_at_or_above_max()
    {
        Assert.False(RetryBackoff.IsExhausted(4));
        Assert.True(RetryBackoff.IsExhausted(5));
        Assert.True(RetryBackoff.IsExhausted(6));
    }
}
