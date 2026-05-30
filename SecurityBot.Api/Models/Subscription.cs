namespace SecurityBot.Api.Models;

public record Subscription(
    string Id,
    string JobId,
    string BuyerAgent,
    string OfferingName,
    string RequirementJson,
    string? WebhookUrl,
    string? WebhookSecret,
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
    string? StreamJobId
);
