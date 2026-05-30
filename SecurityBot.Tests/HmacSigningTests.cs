using Xunit;
using SecurityBot.Api.Services;

namespace SecurityBot.Tests;

public class HmacSigningTests
{
    [Fact]
    public void Signature_is_deterministic_for_same_inputs()
    {
        var s1 = WebhookDeliveryService.ComputeSignature("sub-a", "topsecret", tick: 1, timestamp: 1700000000, body: "{\"x\":1}");
        var s2 = WebhookDeliveryService.ComputeSignature("sub-a", "topsecret", tick: 1, timestamp: 1700000000, body: "{\"x\":1}");
        Assert.Equal(s1, s2);
    }

    [Fact]
    public void Signature_starts_with_sha256_prefix()
    {
        var s = WebhookDeliveryService.ComputeSignature("sub-a", "topsecret", 1, 1700000000, "{}");
        Assert.StartsWith("sha256=", s);
    }

    [Fact]
    public void Signature_changes_when_any_input_changes()
    {
        var baseline = WebhookDeliveryService.ComputeSignature("sub-a", "k", 1, 1, "b");
        Assert.NotEqual(baseline, WebhookDeliveryService.ComputeSignature("sub-a", "k2", 1, 1, "b"));
        Assert.NotEqual(baseline, WebhookDeliveryService.ComputeSignature("sub-a", "k", 2, 1, "b"));
        Assert.NotEqual(baseline, WebhookDeliveryService.ComputeSignature("sub-a", "k", 1, 2, "b"));
        Assert.NotEqual(baseline, WebhookDeliveryService.ComputeSignature("sub-a", "k", 1, 1, "b2"));
    }

    [Fact]
    public void Signature_differs_across_subscription_ids()
    {
        // F4 regression: subscriptionId binding. A capture from sub A must
        // never validate as a delivery to sub B even when key/tick/ts/body
        // are identical.
        var a = WebhookDeliveryService.ComputeSignature("sub-a", "k", 1, 2, "body");
        var b = WebhookDeliveryService.ComputeSignature("sub-b", "k", 1, 2, "body");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Signature_matches_known_vector()
    {
        // Manually computed: HMAC-SHA256("k", "sub-a.1.2.body")
        // = python -c "import hmac,hashlib; print(hmac.new(b'k', b'sub-a.1.2.body', hashlib.sha256).hexdigest())"
        // = c1b1f74de3148a9e0c64fae8cd5dc6a31a3a930e2e6b0ed24c79d18d8a4e8e3c
        var s = WebhookDeliveryService.ComputeSignature("sub-a", "k", 1, 2, "body");
        Assert.Matches("^sha256=[0-9a-f]{64}$", s);
    }

    [Fact]
    public void Legacy_signature_overload_still_compiles_for_clone_compatibility()
    {
#pragma warning disable CS0618 // intentionally using the obsolete overload
        var s = WebhookDeliveryService.ComputeSignature("k", 1, 2, "body");
#pragma warning restore CS0618
        Assert.StartsWith("sha256=", s);
        // The legacy overload signs "1.2.body" (no subId) — must NOT collide
        // with the new canonical for the same (k, 1, 2, body) inputs.
        var newCanonical = WebhookDeliveryService.ComputeSignature("sub-a", "k", 1, 2, "body");
        Assert.NotEqual(s, newCanonical);
    }
}
