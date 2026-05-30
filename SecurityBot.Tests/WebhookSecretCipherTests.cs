using SecurityBot.Api.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecurityBot.Tests;

// Regression tests for WebhookSecretCipher (audit F3, 2026-05-25). The
// cipher is the canonical "AES-256-GCM at rest" pattern lifted from
// ACP_SolanaBot 2026-05-24 / ACP_OracleBot v0.7. Any clone that copies
// this boilerplate inherits the cipher contract:
//
//   1. With no WEBHOOK_SECRET_ENCRYPTION_KEY: Protect/Unprotect are NO-OPS.
//   2. With a 32-byte base64 key: Protect emits "v1:iv.tag.ct".
//   3. Unprotect handles both shapes (plaintext rows + v1: envelopes) so
//      migration is lazy — old rows decode as-is until rewritten.
//   4. A wrong key length or non-base64 key fails at construction.
public class WebhookSecretCipherTests
{
    private static WebhookSecretCipher CipherWithKey()
    {
        // 32 random bytes (AES-256), base64-encoded. Deterministic for tests
        // (don't use this exact key for anything else; trivially leaked here).
        var key = Convert.ToBase64String(new byte[32]
        {
            0x9b,0x71,0x4e,0x33,0xfa,0x21,0x18,0x4d,
            0x7e,0xca,0x60,0x05,0x29,0xab,0x9d,0x10,
            0x6c,0x88,0x4d,0x9f,0xb0,0x4c,0x33,0x07,
            0x12,0xff,0xa0,0x6e,0x55,0x1c,0xea,0x42
        });
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["WebhookSecretEncryptionKey"] = key })
            .Build();
        return new WebhookSecretCipher(cfg);
    }

    private static WebhookSecretCipher CipherWithoutKey()
        => new(new ConfigurationBuilder().Build());

    [Fact]
    public void No_key_is_noop_passthrough()
    {
        var c = CipherWithoutKey();
        Assert.False(c.IsEncryptionEnabled);
        Assert.Equal("plaintext-secret", c.Protect("plaintext-secret"));
        Assert.Equal("plaintext-secret", c.Unprotect("plaintext-secret"));
    }

    [Fact]
    public void No_key_returns_empty_for_empty()
    {
        var c = CipherWithoutKey();
        Assert.Equal(string.Empty, c.Protect(string.Empty));
        Assert.Equal(string.Empty, c.Unprotect(string.Empty));
    }

    [Fact]
    public void With_key_protect_emits_v1_envelope()
    {
        var c = CipherWithKey();
        Assert.True(c.IsEncryptionEnabled);

        var sealed_ = c.Protect("my-secret");

        Assert.StartsWith("v1:", sealed_);
        // v1:base64(iv).base64(tag).base64(ct) — three dot-separated tokens
        // after the prefix, all valid base64.
        var body = sealed_.Substring(3);
        var parts = body.Split('.');
        Assert.Equal(3, parts.Length);
        Convert.FromBase64String(parts[0]); // doesn't throw
        Convert.FromBase64String(parts[1]);
        Convert.FromBase64String(parts[2]);
    }

    [Fact]
    public void With_key_protect_then_unprotect_roundtrips()
    {
        var c = CipherWithKey();
        var roundtripped = c.Unprotect(c.Protect("my-secret"));
        Assert.Equal("my-secret", roundtripped);
    }

    [Fact]
    public void With_key_protect_uses_fresh_iv_each_call()
    {
        // AES-GCM mandates IV uniqueness. The ciphertext for the same plaintext
        // must differ across calls because the IV is regenerated.
        var c = CipherWithKey();
        var a = c.Protect("same-plaintext");
        var b = c.Protect("same-plaintext");
        Assert.NotEqual(a, b);
        Assert.Equal("same-plaintext", c.Unprotect(a));
        Assert.Equal("same-plaintext", c.Unprotect(b));
    }

    [Fact]
    public void With_key_unprotect_passes_through_legacy_plaintext_rows()
    {
        // Lazy-migration backward compat: existing plaintext rows in the DB
        // (which don't start with the v1: prefix) must round-trip to themselves
        // until a write re-encrypts them.
        var c = CipherWithKey();
        Assert.Equal("legacy-plaintext-row", c.Unprotect("legacy-plaintext-row"));
    }

    [Fact]
    public void Wrong_key_length_throws_at_construction()
    {
        // 16 bytes is valid AES-128 but the cipher pins AES-256 — reject.
        var key = Convert.ToBase64String(new byte[16]);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["WebhookSecretEncryptionKey"] = key })
            .Build();
        Assert.Throws<InvalidOperationException>(() => new WebhookSecretCipher(cfg));
    }

    [Fact]
    public void Non_base64_key_throws_at_construction()
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
                { ["WebhookSecretEncryptionKey"] = "this-is-not-base64-padding!!" })
            .Build();
        Assert.Throws<InvalidOperationException>(() => new WebhookSecretCipher(cfg));
    }

    [Fact]
    public void Encrypted_row_unprotect_throws_when_key_removed()
    {
        var encryptedRow = CipherWithKey().Protect("my-secret");
        // Simulate operational error: key was removed between Insert and Read.
        // The cipher SHOULD throw rather than silently return ciphertext as
        // plaintext — that's the correct fail-loud behaviour.
        var noKey = CipherWithoutKey();
        Assert.Throws<InvalidOperationException>(() => noKey.Unprotect(encryptedRow));
    }
}
