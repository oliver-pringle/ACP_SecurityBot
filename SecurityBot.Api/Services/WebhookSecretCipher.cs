using System.Security.Cryptography;
using System.Text;

namespace SecurityBot.Api.Services;

/// AES-256-GCM cipher for webhook secrets at rest. Closes audit finding
/// "if the SQLite file leaks, every webhook HMAC secret leaks with it and
/// an attacker can forge signed tick deliveries against the buyer's webhook."
///
/// Lifted from ACP_SolanaBot 2026-05-24 / ACP_OracleBot v0.7. Required-by-
/// default for any BSB clone running in non-Development — Program.cs fails
/// fast at boot unless the operator either sets WEBHOOK_SECRET_ENCRYPTION_KEY
/// or sets the explicit escape hatch SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS=true.
/// Production should never run with the escape hatch.
///
/// Storage format for encrypted rows: "v1:&lt;base64(iv)&gt;.&lt;base64(tag)&gt;.&lt;base64(ct)&gt;"
/// IV is 12 random bytes (AES-GCM standard), tag is 16 bytes.
///
/// Migration is LAZY: the read path is always backward-compatible — rows
/// that don't start with the "v1:" prefix are returned as-is (legacy
/// plaintext). The write path encrypts only when the key is present. So
/// old rows stay plaintext until they're rewritten, new rows are encrypted
/// from the moment WEBHOOK_SECRET_ENCRYPTION_KEY lands.
public sealed class WebhookSecretCipher
{
    private const string V1Prefix = "v1:";
    private readonly byte[]? _key;

    public WebhookSecretCipher(IConfiguration cfg)
    {
        var rawKey = Environment.GetEnvironmentVariable("WEBHOOK_SECRET_ENCRYPTION_KEY")
            ?? cfg["WebhookSecretEncryptionKey"];
        if (string.IsNullOrWhiteSpace(rawKey))
        {
            _key = null;
            return;
        }
        try
        {
            var bytes = Convert.FromBase64String(rawKey.Trim());
            if (bytes.Length != 32)
                throw new InvalidOperationException(
                    $"WEBHOOK_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256); got {bytes.Length}.");
            _key = bytes;
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                "WEBHOOK_SECRET_ENCRYPTION_KEY must be base64-encoded (32 bytes). " +
                "Generate one with `openssl rand -base64 32`.", ex);
        }
    }

    public bool IsEncryptionEnabled => _key is not null;

    /// Encrypt a plaintext webhook secret for storage. No-op (returns the
    /// plaintext unchanged) when no key is configured — the transitional
    /// plaintext path Program.cs explicitly opts into with the escape hatch.
    public string Protect(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext)) return string.Empty;
        if (_key is null) return plaintext;

        Span<byte> iv = stackalloc byte[12];
        RandomNumberGenerator.Fill(iv);
        var ptBytes = Encoding.UTF8.GetBytes(plaintext);
        var ct = new byte[ptBytes.Length];
        Span<byte> tag = stackalloc byte[16];

        using var gcm = new AesGcm(_key, 16);
        gcm.Encrypt(iv, ptBytes, ct, tag);

        return $"{V1Prefix}{Convert.ToBase64String(iv)}." +
               $"{Convert.ToBase64String(tag)}." +
               $"{Convert.ToBase64String(ct)}";
    }

    /// Decrypt a stored webhook secret. Plaintext rows (no "v1:" prefix)
    /// are returned as-is. Encrypted rows require the key to be present;
    /// throws if the key was removed between writes and reads (operational
    /// error, not buyer-visible).
    public string Unprotect(string stored)
    {
        if (string.IsNullOrEmpty(stored)) return string.Empty;
        if (!stored.StartsWith(V1Prefix, StringComparison.Ordinal))
            return stored;

        if (_key is null)
            throw new InvalidOperationException(
                "Stored webhook secret is encrypted (v1: prefix) but " +
                "WEBHOOK_SECRET_ENCRYPTION_KEY is not configured. Cannot decrypt. " +
                "Restore the key the row was encrypted with, or roll the database.");

        var body = stored.AsSpan(V1Prefix.Length).ToString();
        var parts = body.Split('.');
        if (parts.Length != 3)
            throw new InvalidOperationException("Malformed encrypted webhook secret (expected iv.tag.ct).");

        var iv = Convert.FromBase64String(parts[0]);
        var tag = Convert.FromBase64String(parts[1]);
        var ct = Convert.FromBase64String(parts[2]);
        if (iv.Length != 12 || tag.Length != 16)
            throw new InvalidOperationException("Encrypted webhook secret IV or tag length wrong.");

        var pt = new byte[ct.Length];
        using var gcm = new AesGcm(_key, 16);
        gcm.Decrypt(iv, ct, tag, pt);
        return Encoding.UTF8.GetString(pt);
    }
}
