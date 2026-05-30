namespace SecurityBot.Api.Models;

public record CreateSubscriptionRequest(
    string JobId,
    string BuyerAgent,
    string OfferingName,
    Dictionary<string, object> Requirement,
    string? PushMode = null,
    int? StreamChainId = null,
    string? StreamJobId = null
);

public record CreateSubscriptionResponse(
    string SubscriptionId,
    string? WebhookSecret,
    int TicksPurchased,
    int IntervalSeconds,
    DateTime ExpiresAt,
    string PushMode
);

// Public projection of Subscription. WebhookSecret is NEVER serialised —
// the full Subscription record holds the HMAC key buyers use to verify
// callback signatures and anyone who reads it could forge tick deliveries
// against the buyer's webhook.
//
// Two shapes (audit F5):
//
//   * SubscriptionView.Minimal — default for any X-API-Key-authenticated
//     reader. Drops buyer-identifying fields (RequirementJson, WebhookUrl,
//     BuyerAgent, StreamJobId). What's left lets the buyer poll status +
//     progress without leaking metadata to other API-key holders.
//
//   * SubscriptionView.Full — returned only when the caller proves
//     ownership via the X-Subscription-Secret request header carrying
//     the same webhookSecret delivered ONCE in the ACP receipt at hire
//     time. Includes the buyer-identifying fields. Still strips
//     WebhookSecret on the way out (no point echoing it back to a caller
//     who already holds it). inJobStream subscriptions have no
//     webhookSecret on disk, so the Full lane is unreachable — operators
//     wanting the full row hit the SQLite file directly.
public record SubscriptionView(
    string Id,
    string OfferingName,
    int IntervalSeconds,
    int TicksPurchased,
    int TicksDelivered,
    DateTime CreatedAt,
    DateTime ExpiresAt,
    DateTime? LastRunAt,
    DateTime NextRunAt,
    string Status,
    int ConsecutiveFailures,
    string PushMode,
    int? StreamChainId,
    // Fields below are only populated in the Full projection (X-Subscription-Secret).
    string? JobId = null,
    string? BuyerAgent = null,
    string? RequirementJson = null,
    string? WebhookUrl = null,
    string? StreamJobId = null
)
{
    public static SubscriptionView Minimal(Subscription s) => new(
        s.Id, s.OfferingName, s.IntervalSeconds, s.TicksPurchased, s.TicksDelivered,
        s.CreatedAt, s.ExpiresAt, s.LastRunAt, s.NextRunAt, s.Status,
        s.ConsecutiveFailures, s.PushMode, s.StreamChainId,
        JobId:          null,
        BuyerAgent:     null,
        RequirementJson:null,
        WebhookUrl:     null,
        StreamJobId:    null);

    public static SubscriptionView Full(Subscription s) => new(
        s.Id, s.OfferingName, s.IntervalSeconds, s.TicksPurchased, s.TicksDelivered,
        s.CreatedAt, s.ExpiresAt, s.LastRunAt, s.NextRunAt, s.Status,
        s.ConsecutiveFailures, s.PushMode, s.StreamChainId,
        JobId:          s.JobId,
        BuyerAgent:     s.BuyerAgent,
        RequirementJson:s.RequirementJson,
        WebhookUrl:     s.WebhookUrl,
        StreamJobId:    s.StreamJobId);
}

public record EchoRequest(string Message);
