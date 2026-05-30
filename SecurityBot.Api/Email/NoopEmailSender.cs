namespace SecurityBot.Api.Email;

// v1 placeholder backend. Delivering mail to a Virtuals @agents.world mailbox
// is a research spike deferred to after this plan, so v1 always reports
// "no_backend" — the scan still succeeds and the deliverable's _emailDelivery
// is honest about the missing backend. Swap this DI registration for a real
// IEmailSender once the backend is understood.
public sealed class NoopEmailSender : IEmailSender
{
    public Task<EmailResult> SendScanReportAsync(string toAgentEmail, object report, CancellationToken ct)
        => Task.FromResult(new EmailResult("no_backend"));
}
