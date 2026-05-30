using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace SecurityBot.Api.Services;

/// SocketsHttpHandler.ConnectCallback for webhook delivery. Runs on every
/// physical socket connect, AFTER the framework has resolved the hostname
/// to a concrete IPEndPoint. Re-validates that endpoint against the same
/// blocklist WebhookUrlValidator uses; closes the DNS-rebind TOCTOU window
/// where a hostname that passed initial validation later resolves to a
/// private / metadata / loopback address.
///
/// Ported from ACP_OracleBot v0.7 (2026-05-24) / ACP_SolanaBot 2026-05-24 /
/// ACP_ChainlinkBot 2026-05-22. Paired with AllowAutoRedirect=false on the
/// same handler: even if the upstream returns a 3xx Location pointing at
/// 169.254.169.254 / 127.0.0.1 / 10.0.0.0/8, HttpClient never follows it.
public static class WebhookConnectCallbacks
{
    public static async ValueTask<Stream> PinValidatedIp(
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
            if (WebhookUrlValidator.IsConnectBlocked(addr, out var reason))
            {
                lastError = new HttpRequestException(
                    $"webhook connect target {addr} blocked: {reason}");
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
        throw lastError ?? new HttpRequestException($"no addresses resolved for {host}");
    }
}
