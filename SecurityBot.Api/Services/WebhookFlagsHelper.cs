namespace SecurityBot.Api.Services;

// Single source of truth for resolving the two webhook escape-hatch flags
// from configuration / environment.
//
// Split out of WebhookDeliveryService + SubscriptionService so both consumers
// observe the same evaluation rules — including the legacy
// ALLOW_INSECURE_WEBHOOKS=true alias that turns BOTH new flags on at once
// (for backward compatibility with tests and the boilerplate's prior shape).
//
// Production: leave all three unset. Program.cs refuses to boot with the
// legacy flag in any non-Development environment.
public static class WebhookFlagsHelper
{
    public static (bool AllowHttpWebhooks, bool DisableWebhookDnsValidation) Resolve(IConfiguration? cfg)
    {
        bool legacy    = Bool(cfg, "ALLOW_INSECURE_WEBHOOKS");
        bool allowHttp = Bool(cfg, "ALLOW_HTTP_WEBHOOKS");
        bool skipDns   = Bool(cfg, "DISABLE_WEBHOOK_DNS_VALIDATION");
        return (allowHttp || legacy, skipDns || legacy);
    }

    private static bool Bool(IConfiguration? cfg, string key)
    {
        var v = cfg?[key] ?? Environment.GetEnvironmentVariable(key);
        return string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
    }
}
