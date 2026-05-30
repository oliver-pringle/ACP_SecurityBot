namespace SecurityBot.Api.Email;

// Status values an email delivery attempt can report back to the scan deliverable:
//   sent       - the backend accepted the message for delivery
//   skipped    - email was requested but no recipient address could be determined
//   no_backend - email was requested but no real backend is wired (v1 default)
//   failed     - a backend was wired but the send attempt threw / was rejected
public sealed record EmailResult(string Status);

public interface IEmailSender
{
    Task<EmailResult> SendScanReportAsync(string toAgentEmail, object report, CancellationToken ct);
}
