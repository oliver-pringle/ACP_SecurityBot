using System.Reflection;
using SecurityBot.Api.Models;
using Xunit;

namespace SecurityBot.Tests;

// Regression tests for SubscriptionView shape (audit F5, 2026-05-25).
// Hard rules:
//   1. NEITHER projection ever returns WebhookSecret. Anyone with the
//      secret can forge tick deliveries to the buyer's webhook.
//   2. Minimal projection omits all buyer-identifying fields:
//      BuyerAgent, RequirementJson, WebhookUrl, JobId, StreamJobId.
//   3. Full projection (X-Subscription-Secret-gated) returns those fields
//      but still strips WebhookSecret.
public class SubscriptionViewTests
{
    private static Subscription SeedSub() => new(
        Id:                 "sub-x",
        JobId:              "job-42",
        BuyerAgent:         "0xBuyer",
        OfferingName:       "tick_echo",
        RequirementJson:    "{\"ticks\":24}",
        WebhookUrl:         "https://buyer.example/cb",
        WebhookSecret:      "this-is-the-secret-DO-NOT-LEAK",
        IntervalSeconds:    3600,
        TicksPurchased:     24,
        TicksDelivered:     3,
        CreatedAt:          new DateTime(2026, 5, 25, 12, 0, 0, DateTimeKind.Utc),
        ExpiresAt:          new DateTime(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc),
        LastRunAt:          new DateTime(2026, 5, 25, 12, 30, 0, DateTimeKind.Utc),
        NextRunAt:          new DateTime(2026, 5, 25, 13, 30, 0, DateTimeKind.Utc),
        Status:             "active",
        ConsecutiveFailures: 0,
        PushMode:           "webhook",
        StreamChainId:      null,
        StreamJobId:        null
    );

    [Fact]
    public void SubscriptionView_record_has_no_WebhookSecret_property()
    {
        // Hard reflective check — if anyone ever adds a WebhookSecret-named
        // property to the public projection record, this test catches it
        // before the field can leak through serialisation.
        var props = typeof(SubscriptionView).GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Assert.DoesNotContain(props, p => string.Equals(p.Name, "WebhookSecret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Minimal_omits_buyer_identifying_fields()
    {
        var minimal = SubscriptionView.Minimal(SeedSub());
        Assert.Null(minimal.JobId);
        Assert.Null(minimal.BuyerAgent);
        Assert.Null(minimal.RequirementJson);
        Assert.Null(minimal.WebhookUrl);
        Assert.Null(minimal.StreamJobId);
    }

    [Fact]
    public void Minimal_keeps_status_and_counts()
    {
        var minimal = SubscriptionView.Minimal(SeedSub());
        Assert.Equal("sub-x",      minimal.Id);
        Assert.Equal("tick_echo",  minimal.OfferingName);
        Assert.Equal(24,           minimal.TicksPurchased);
        Assert.Equal(3,            minimal.TicksDelivered);
        Assert.Equal("active",     minimal.Status);
        Assert.Equal("webhook",    minimal.PushMode);
        Assert.Equal(3600,         minimal.IntervalSeconds);
    }

    [Fact]
    public void Full_returns_buyer_identifying_fields_but_not_secret()
    {
        var full = SubscriptionView.Full(SeedSub());
        Assert.Equal("job-42",                       full.JobId);
        Assert.Equal("0xBuyer",                      full.BuyerAgent);
        Assert.Equal("{\"ticks\":24}",               full.RequirementJson);
        Assert.Equal("https://buyer.example/cb",     full.WebhookUrl);
        // WebhookSecret has no property on this record — see the reflective check.
    }
}
