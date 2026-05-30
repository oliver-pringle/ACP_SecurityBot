export interface ValidationResult {
  valid: boolean;
  reason?: string;
}

export function requireString(value: unknown, name: string): ValidationResult {
  if (typeof value !== "string" || value.trim() === "") {
    return { valid: false, reason: `${name} is required` };
  }
  return { valid: true };
}

export function requireStringLength(
  value: unknown,
  name: string,
  maxLen: number
): ValidationResult {
  const base = requireString(value, name);
  if (!base.valid) return base;
  if ((value as string).length > maxLen) {
    return { valid: false, reason: `${name} exceeds ${maxLen} character limit` };
  }
  return { valid: true };
}

export function requireOneOf(
  value: unknown,
  name: string,
  allowed: readonly string[]
): ValidationResult {
  if (value === undefined || value === null) return { valid: true };
  if (typeof value !== "string" || !allowed.includes(value)) {
    return { valid: false, reason: `${name} must be one of: ${allowed.join(", ")}` };
  }
  return { valid: true };
}

// Preliminary client-side webhook URL validation. Catches obvious foot-guns
// (HTTP scheme, literal RFC1918 / loopback / metadata IPs) before the
// sidecar calls setBudget, so buyers get a fast 4xx instead of paying and
// being silently rejected at delivery time.
//
// NOT authoritative — the C# tier's WebhookUrlValidator does the full
// check including DNS resolution + per-address blocklist + connect-time
// re-validation via SocketsHttpHandler.ConnectCallback. The TS layer is
// intentionally sync (Offering.validate is sync) and therefore cannot
// resolve DNS, so a hostname like `evil.example.com` that resolves to
// 169.254.169.254 passes here and is caught server-side.
//
// Audit F7 widened the literal-IP coverage to match the C# blocklist:
// metadata (169.254/16), CGNAT (100.64/10), reserved (0/8, 240/4),
// IPv6 ULA (fc00::/7), IPv6 link-local (fe80::/10), and IPv4-mapped
// IPv6 (::ffff:127.0.0.1 etc.) literals are now rejected here too.
export function requireWebhookUrl(value: unknown, field: string): ValidationResult {
  if (typeof value !== "string") return { valid: false, reason: `${field} must be a string` };
  let url: URL;
  try { url = new URL(value); }
  catch { return { valid: false, reason: `${field} is not a valid URL` }; }

  const allowInsecure = process.env.ALLOW_INSECURE_WEBHOOKS === "true";
  if (url.protocol !== "https:" && !allowInsecure)
    return { valid: false, reason: `${field} must be HTTPS (set ALLOW_INSECURE_WEBHOOKS=true for dev)` };

  if (allowInsecure) return { valid: true };

  // url.hostname strips IPv6 brackets but keeps zone-id (`fe80::1%eth0`);
  // strip the zone for matching.
  const host = url.hostname.toLowerCase().replace(/%[a-z0-9-]+$/i, "");

  // Named loopback aliases.
  if (host === "localhost" || host === "ip6-localhost" || host === "ip6-loopback")
    return { valid: false, reason: `${field} resolves to loopback` };

  // IPv4 literal — full octet parsing, not prefix string-matching.
  const v4 = parseIpv4(host);
  if (v4 !== null) {
    const reason = isIpv4Blocked(v4);
    if (reason !== null) return { valid: false, reason: `${field} resolves to ${reason} (${host})` };
    return { valid: true };
  }

  // IPv6 literal (with or without zone, with bracket already stripped by url.hostname).
  if (host.includes(":")) {
    const reason = isIpv6Blocked(host);
    if (reason !== null) return { valid: false, reason: `${field} resolves to ${reason} (${host})` };
    return { valid: true };
  }

  // Non-literal hostname — server-side validator does the DNS resolution
  // + per-address blocklist + connect-time re-validation. Pass through.
  return { valid: true };
}

function parseIpv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function isIpv4Blocked(o: number[]): string | null {
  if (o[0] === 0)                                  return "unspecified 0.0.0.0/8";
  if (o[0] === 10)                                 return "rfc1918 10/8";
  if (o[0] === 127)                                return "loopback 127/8";
  if (o[0] === 169 && o[1] === 254)                return "link-local/metadata 169.254/16";
  if (o[0] === 172 && (o[1] & 0xf0) === 16)        return "rfc1918 172.16/12";
  if (o[0] === 192 && o[1] === 168)                return "rfc1918 192.168/16";
  if (o[0] === 100 && (o[1] & 0xc0) === 64)        return "cgnat 100.64/10";
  if ((o[0] & 0xf0) === 0xe0)                      return "multicast 224/4";
  if ((o[0] & 0xf0) === 0xf0)                      return "reserved 240/4";
  if (o[0] === 192 && o[1] === 0   && o[2] === 2)  return "docs 192.0.2/24";
  if (o[0] === 198 && o[1] === 51  && o[2] === 100) return "docs 198.51.100/24";
  if (o[0] === 203 && o[1] === 0   && o[2] === 113) return "docs 203.0.113/24";
  if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return "benchmark 198.18/15";
  return null;
}

function isIpv6Blocked(host: string): string | null {
  // Normalise leading "::" → "0:" + drop a trailing "::".
  if (host === "::")                                return "ipv6 unspecified";
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") return "ipv6 loopback";

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 → re-check the embedded IPv4).
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(host);
  if (mapped) {
    const inner = parseIpv4(mapped[1]);
    if (inner !== null) {
      const reason = isIpv4Blocked(inner);
      if (reason !== null) return `ipv4-mapped ipv6 ${reason}`;
    }
  }

  // First 16-bit group — enough for the broad block ranges below.
  const firstGroup = host.split(":")[0] ?? "";
  const head = parseInt(firstGroup, 16);
  if (Number.isFinite(head)) {
    if ((head & 0xff00) === 0xfe00 && (head & 0x00c0) >= 0x0080)
      return "ipv6 link-local fe80::/10";
    if ((head & 0xfe00) === 0xfc00)
      return "ipv6 unique-local fc00::/7";
    if ((head & 0xff00) === 0xff00)
      return "ipv6 multicast ff00::/8";
    // 2001:db8::/32 documentation
    if (head === 0x2001) {
      const second = parseInt(host.split(":")[1] ?? "", 16);
      if (second === 0xdb8) return "ipv6 documentation 2001:db8::/32";
    }
  }

  return null;
}

export function requireIntInRange(
  value: unknown,
  field: string,
  min: number,
  max: number
): ValidationResult {
  if (typeof value !== "number" || !Number.isInteger(value))
    return { valid: false, reason: `${field} must be an integer` };
  if (value < min) return { valid: false, reason: `${field} must be >= ${min}` };
  if (value > max) return { valid: false, reason: `${field} must be <= ${max}` };
  return { valid: true };
}
