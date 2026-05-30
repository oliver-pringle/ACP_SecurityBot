using System.Net;
using SecurityBot.Api.Engine;
using Xunit;

namespace SecurityBot.Tests;

public class ProbeClientSsrfTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.5.5", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.169.254", true)]   // cloud metadata
    [InlineData("100.64.0.1", true)]         // CGNAT
    [InlineData("224.0.0.1", true)]          // multicast
    [InlineData("240.0.0.1", true)]          // reserved
    [InlineData("0.0.0.0", true)]
    [InlineData("8.8.8.8", false)]           // public - allowed
    [InlineData("1.1.1.1", false)]
    public void IsBlockedTarget_classifies_ipv4(string ip, bool blocked)
        => Assert.Equal(blocked, ProbeClient.IsBlockedTarget(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("::1", true)]                // loopback
    [InlineData("fe80::1", true)]            // link-local
    [InlineData("fc00::1", true)]            // ULA
    [InlineData("::", true)]                 // unspecified
    [InlineData("2606:4700:4700::1111", false)] // public (cloudflare) - allowed
    public void IsBlockedTarget_classifies_ipv6(string ip, bool blocked)
        => Assert.Equal(blocked, ProbeClient.IsBlockedTarget(IPAddress.Parse(ip)));
}
