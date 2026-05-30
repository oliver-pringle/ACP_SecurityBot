using SecurityBot.Api.Email;
using Xunit;

namespace SecurityBot.Tests;

// The real email backend (how a Virtuals @agents.world mailbox actually sends
// mail) is a deferred research spike. v1 ships NoopEmailSender, which reports
// "no_backend" so the scan still succeeds and the deliverable carries an honest
// _emailDelivery status when emailReport was requested.
public class EmailSenderTests
{
    [Fact]
    public async Task NoopEmailSender_reports_no_backend()
    {
        var result = await new NoopEmailSender()
            .SendScanReportAsync("x@agents.world", new object(), default);
        Assert.Equal("no_backend", result.Status);
    }
}
