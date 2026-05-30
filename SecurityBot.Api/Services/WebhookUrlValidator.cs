using System.Net;
using System.Net.Sockets;

namespace SecurityBot.Api.Services;

// Server-side validation for buyer-supplied webhook URLs. Defends against SSRF
// where an attacker registers a subscription pointed at internal services
// reachable from inside the docker network (loopback, cloud metadata endpoint,
// RFC1918 IPs of other containers/host services).
//
// Two operator flags split the previous single ALLOW_INSECURE_WEBHOOKS=true
// switch (audit finding #3 — that single flag bypassed BOTH the https check
// AND the DNS+private-IP check, which is way more than the name suggested):
//
//   * AllowHttpWebhooks (env: ALLOW_HTTP_WEBHOOKS)
//       Permits http:// URLs. Useful for local tests against http stub servers.
//       Production must leave it unset (or false).
//
//   * DisableWebhookDnsValidation (env: DISABLE_WEBHOOK_DNS_VALIDATION)
//       Skips DNS resolution + private-IP blocklist. Useful for unit tests that
//       use stub hostnames like `buyer.test` that don't resolve. Production
//       MUST leave it unset — without this check, an attacker can register a
//       webhook whose hostname later DNS-rebinds to 169.254.169.254 or a
//       sibling container's RFC1918 address.
//
// For backward compatibility the legacy ALLOW_INSECURE_WEBHOOKS=true flag is
// honoured at Program.cs boot: it sets BOTH new flags. But Program.cs also
// refuses to boot with the legacy flag in non-Development environments — it
// was a known foot-gun and is now the explicit fail-fast case.
public static class WebhookUrlValidator
{
    public readonly record struct Result(bool Ok, string? Error);

    /// New API — split flags. Production passes (false, false).
    public static Result Validate(string? url, bool allowHttp, bool skipDnsValidation)
    {
        if (string.IsNullOrWhiteSpace(url))
            return new Result(false, "webhookUrl required");

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new Result(false, "webhookUrl must be an absolute URI");

        if (uri.Scheme != Uri.UriSchemeHttps &&
            !(allowHttp && uri.Scheme == Uri.UriSchemeHttp))
            return new Result(false, "webhookUrl must use https://");

        if (uri.IsDefaultPort == false && (uri.Port < 1 || uri.Port > 65535))
            return new Result(false, "webhookUrl port out of range");

        // skipDnsValidation is a tests-only escape hatch. Production never sets
        // this — that's what closed audit finding #3 (the old single flag
        // bypassed both checks).
        if (skipDnsValidation) return new Result(true, null);

        IPAddress[] addresses;
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            addresses = new[] { literal };
        }
        else
        {
            try
            {
                addresses = Dns.GetHostAddresses(uri.Host);
            }
            catch (SocketException)
            {
                return new Result(false, "webhookUrl host did not resolve");
            }
            if (addresses.Length == 0)
                return new Result(false, "webhookUrl host did not resolve");
        }

        foreach (var addr in addresses)
        {
            if (IsBlocked(addr, out var reason))
                return new Result(false, $"webhookUrl resolves to {reason} ({addr})");
        }

        return new Result(true, null);
    }

    /// Legacy single-flag overload, kept for any external caller that hasn't
    /// migrated. Equivalent to passing the same value to both new flags.
    public static Result Validate(string? url, bool allowInsecure)
        => Validate(url, allowInsecure, allowInsecure);

    /// Public connect-time variant — re-validates an IP at TCP connect time
    /// from a SocketsHttpHandler.ConnectCallback, closing the DNS-rebind TOCTOU
    /// window between validate-time DNS resolution and HttpClient's own
    /// connect-time resolve.
    public static bool IsConnectBlocked(IPAddress addr, out string reason)
        => IsBlocked(addr, out reason);

    private static bool IsBlocked(IPAddress addr, out string reason)
    {
        if (IPAddress.IsLoopback(addr))           { reason = "loopback";          return true; }
        if (addr.IsIPv6LinkLocal)                  { reason = "ipv6 link-local";   return true; }
        if (addr.IsIPv6SiteLocal)                  { reason = "ipv6 site-local";   return true; }
        if (addr.IsIPv6UniqueLocal)                { reason = "ipv6 unique-local"; return true; }
        if (addr.IsIPv6Multicast)                  { reason = "ipv6 multicast";    return true; }
        if (IPAddress.IsLoopback(addr.MapToIPv4())){ reason = "loopback";          return true; }

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IPv6Any.Equals(addr))     { reason = "ipv6 unspecified";  return true; }
            var v6 = addr.GetAddressBytes();
            if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8)
                                                    { reason = "ipv6 documentation 2001:db8::/32"; return true; }
            if (v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b)
                                                    { reason = "ipv6 ipv4-translation 64:ff9b::/96"; return true; }
            // F7 additions:
            // 2002::/16 — 6to4 anycast tunnel relay. Deprecated (RFC 7526) but
            // still routable to IPv4-encoded endpoints that may sit on RFC1918
            // when stripped, so block at this layer.
            if (v6[0] == 0x20 && v6[1] == 0x02)
                                                    { reason = "ipv6 6to4 2002::/16";  return true; }
            // 2001::/32 — Teredo IPv6-over-UDP-over-IPv4 tunnel. Embedded
            // server IP may be a private/metadata address; refuse the whole /32.
            // Note: this is broader than the documentation range above and runs
            // AFTER it, so 2001:db8::/32 still matches the docs reason first.
            if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x00)
                                                    { reason = "ipv6 teredo 2001::/32"; return true; }
        }

        if (addr.AddressFamily == AddressFamily.InterNetwork ||
            (addr.IsIPv4MappedToIPv6))
        {
            var b = addr.MapToIPv4().GetAddressBytes();
            if (b[0] == 10)                             { reason = "rfc1918 10/8";       return true; }
            if (b[0] == 172 && (b[1] & 0xf0) == 16)     { reason = "rfc1918 172.16/12";  return true; }
            if (b[0] == 192 && b[1] == 168)             { reason = "rfc1918 192.168/16"; return true; }
            if (b[0] == 169 && b[1] == 254)             { reason = "link-local/metadata"; return true; }
            if (b[0] == 127)                            { reason = "loopback";           return true; }
            if (b[0] == 100 && (b[1] & 0xc0) == 64)     { reason = "cgnat 100.64/10";    return true; }
            if (b[0] == 0)                              { reason = "unspecified 0.0.0.0/8"; return true; }
            if ((b[0] & 0xf0) == 0xe0)                  { reason = "multicast 224/4";    return true; }
            if ((b[0] & 0xf0) == 0xf0)                  { reason = "reserved 240/4";     return true; }
            if (b[0] == 192 && b[1] == 0   && b[2] == 2)   { reason = "docs 192.0.2.0/24";   return true; }
            if (b[0] == 198 && b[1] == 51  && b[2] == 100) { reason = "docs 198.51.100.0/24"; return true; }
            if (b[0] == 203 && b[1] == 0   && b[2] == 113) { reason = "docs 203.0.113.0/24"; return true; }
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) { reason = "benchmark 198.18/15"; return true; }
            // F7 additions:
            // 192.0.0.0/24 — IETF protocol assignments (DS-Lite, NAT64, etc.).
            // 192.0.0.0/29 specifically holds DS-Lite anycast; the whole /24
            // is reserved and never legitimate as a webhook target. The /24
            // covers 192.0.2.0/24 (docs) by accident — check the more specific
            // docs range FIRST above so we report the better-known reason.
            if (b[0] == 192 && b[1] == 0   && b[2] == 0)   { reason = "iana 192.0.0.0/24";   return true; }
            // 192.88.99.0/24 — 6to4 anycast relay (deprecated per RFC 7526).
            if (b[0] == 192 && b[1] == 88  && b[2] == 99)  { reason = "6to4 anycast 192.88.99.0/24"; return true; }
        }

        reason = "";
        return false;
    }
}
