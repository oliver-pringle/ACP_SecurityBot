using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace SecurityBot.Api.Engine;

// The single hardened outbound HTTP client that performs ALL of SecurityBot's
// target probing. The scan target is a buyer-or-marketplace-supplied URL -- i.e.
// UNTRUSTED input pointing at an arbitrary host. That is exactly the SSRF attack
// surface this bot flags in OTHERS, so this client must be the most-hardened
// outbound client in the portfolio: it REFUSES to connect to any private /
// loopback / metadata / reserved address.
//
// This is the INVERSE of the portfolio's cross-bot ConnectCallback pins
// (WebhookConnectCallbacks / InternalConnectCallbacks) which deliberately ALLOW
// private docker hosts. Here ALL private/reserved ranges are BLOCKED and only
// genuinely public addresses may be connected to -- SecurityBot can never be
// turned into an SSRF proxy by a malicious "scan this URL" request.
//
// The block decision is a PURE, testable static method (IsBlockedTarget) so the
// SSRF classifier can be unit-tested without sockets. SocketsHttpHandler's
// ConnectCallback invokes it at TCP-connect time (closing the DNS-rebind TOCTOU
// window: the address we are ABOUT to connect to is the one we classify).
public sealed class ProbeClient : IDisposable, IProbeFetcher
{
    public const int MaxRequestsPerScan = 25;
    public const long MaxResponseBytes = 256 * 1024;
    public const int MaxRateLimitProbes = 5;

    // Explicit interface member exposes the rate-limit-probe budget constant as an
    // instance property so the engine can read it through IProbeFetcher (the public
    // const keeps the same name, so the interface member is implemented explicitly).
    int IProbeFetcher.MaxRateLimitProbes => MaxRateLimitProbes;
    private const string UserAgent = "ACP-SecurityBot/1.0 (passive-audit)";

    private static readonly IReadOnlyDictionary<string, string> EmptyHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    private readonly HttpClient _http;
    private int _requestCount;

    public ProbeClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectCallback = ConnectAsync,
        };
        _http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(8),
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
    }

    // Reset the per-scan request budget. This client is a SINGLETON (one HttpClient +
    // SSRF handler reused across every scan), so _requestCount must be zeroed at the
    // start of each scan; otherwise the MaxRequestsPerScan cap becomes a per-PROCESS
    // cap that, once crossed (~2-3 scans, or the background WatchWorker), makes every
    // future probe short-circuit to reached=false and every agent read NOT_AUDITABLE.
    // The engine calls this at the top of ScanAsync.
    public void BeginScan() => Interlocked.Exchange(ref _requestCount, 0);

    // Pure SSRF classifier. Returns true if the bot must REFUSE to connect to
    // this address. Modelled on OracleBot's WebhookUrlValidator private-range
    // bit-math, but with the intent INVERTED: every private/reserved range is
    // BLOCKED; only genuine public addresses return false.
    public static bool IsBlockedTarget(IPAddress addr)
    {
        // Belt-and-braces loopback for both families (catches ::1 and 127/8 and
        // ::ffff:127.0.0.1 forms via the framework's own check).
        if (IPAddress.IsLoopback(addr)) return true;

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (addr.IsIPv6LinkLocal) return true;     // fe80::/10
            if (addr.IsIPv6SiteLocal) return true;     // fec0::/10 (deprecated)
            if (addr.IsIPv6UniqueLocal) return true;   // fc00::/7 ULA
            if (addr.IsIPv6Multicast) return true;     // ff00::/8
            if (IPAddress.IPv6Any.Equals(addr)) return true; // ::

            // IPv4-mapped IPv6 (::ffff:a.b.c.d) -- re-check the embedded v4 with
            // the v4 rules so a mapped private address can't sneak past.
            if (addr.IsIPv4MappedToIPv6)
                return IsBlockedV4(addr.MapToIPv4().GetAddressBytes());

            // Any other IPv6 address is treated as public.
            return false;
        }

        if (addr.AddressFamily == AddressFamily.InterNetwork)
            return IsBlockedV4(addr.GetAddressBytes());

        // Unknown address family -- fail closed.
        return true;
    }

    private static bool IsBlockedV4(byte[] b)
    {
        if (b.Length != 4) return true; // malformed -- fail closed
        if (b[0] == 0) return true;                          // 0.0.0.0/8 unspecified / this-host
        if (b[0] == 127) return true;                        // 127/8 loopback
        if (b[0] == 10) return true;                         // 10/8 RFC1918
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16/12 RFC1918
        if (b[0] == 192 && b[1] == 168) return true;         // 192.168/16 RFC1918
        if (b[0] == 169 && b[1] == 254) return true;         // 169.254/16 link-local + cloud metadata
        if (b[0] == 100 && (b[1] & 0xc0) == 64) return true; // 100.64/10 CGNAT
        if ((b[0] & 0xf0) == 0xe0) return true;              // 224/4 multicast
        if ((b[0] & 0xf0) == 0xf0) return true;              // 240/4 reserved (incl. 255.255.255.255)
        return false;                                        // genuine public address
    }

    // SocketsHttpHandler.ConnectCallback -- runs after the framework resolves the
    // hostname, on every physical socket connect. We resolve ourselves so we can
    // classify the exact address being connected to. If the literal/all resolved
    // candidates are blocked, we throw (FetchAsync swallows it into reached:false).
    private static async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext ctx, CancellationToken ct)
    {
        var host = ctx.DnsEndPoint.Host;
        var port = ctx.DnsEndPoint.Port;

        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out var literal))
        {
            addresses = new[] { literal };
        }
        else
        {
            addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        }

        Exception? lastError = null;
        foreach (var addr in addresses)
        {
            if (IsBlockedTarget(addr))
            {
                lastError = new HttpRequestException(
                    $"blocked target {addr} (private/loopback/reserved -- SSRF guard)");
                continue;
            }
            try
            {
                var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(addr, port), ct).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }
        throw lastError ?? new HttpRequestException(
            $"blocked target: no allowed address resolved for {host}");
    }

    // Single GET probe. Never throws: any failure (SSRF block from the
    // ConnectCallback, DNS failure, timeout, non-2xx, oversize body read error)
    // collapses to reached:false. Enforces the per-scan request budget so a
    // pathological scan can't fan out unbounded outbound calls.
    public async Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)
    {
        // Budget gate: once the counter EXCEEDS the cap, refuse without a request.
        if (Interlocked.Increment(ref _requestCount) > MaxRequestsPerScan)
            return new ProbeResponse(label, url, 0, EmptyHeaders, "", false);

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await _http
                .SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in resp.Headers)
                headers[h.Key] = string.Join(", ", h.Value);
            // Content headers (Content-Type, Content-Length, etc.) live on a
            // separate collection -- include them too so checks can read them.
            foreach (var h in resp.Content.Headers)
                headers[h.Key] = string.Join(", ", h.Value);

            var body = await ReadBoundedBodyAsync(resp, ct).ConfigureAwait(false);

            return new ProbeResponse(label, url, (int)resp.StatusCode, headers, body, true);
        }
        catch
        {
            // SSRF block, DNS failure, timeout, connection reset -- all collapse
            // to a non-reached result. Never throw out of FetchAsync.
            return new ProbeResponse(label, url, 0, EmptyHeaders, "", false);
        }
    }

    // Read at most MaxResponseBytes of the body into a bounded buffer; stop at
    // the cap. A hostile target can't OOM the bot with a huge / chunked body.
    private static async Task<string> ReadBoundedBodyAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        long total = 0;
        int read;
        while (total < MaxResponseBytes &&
               (read = await stream.ReadAsync(
                   buffer.AsMemory(0, (int)Math.Min(buffer.Length, MaxResponseBytes - total)),
                   ct).ConfigureAwait(false)) > 0)
        {
            ms.Write(buffer, 0, read);
            total += read;
        }
        return System.Text.Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    public void Dispose() => _http.Dispose();
}
