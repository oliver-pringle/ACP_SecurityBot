namespace SecurityBot.Api.Models;

public record SubscriptionRun(
    long Id,
    string SubscriptionId,
    int TickNumber,
    DateTime ScheduledAt,
    string PayloadJson,
    string DeliveryStatus,
    int Attempts,
    DateTime? NextAttemptAt,
    DateTime? LastAttemptAt,
    string? LastError
);
