using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Models;

namespace SecurityBot.Api.Services;

public class TickExecutorService
{
    private readonly TickEchoRepository _tickEcho;
    public TickExecutorService(TickEchoRepository tickEcho) => _tickEcho = tickEcho;

    public async Task<string> ComputePayloadAsync(Subscription sub, int tickNumber)
    {
        // Both offering names share the same per-tick payload — only the
        // delivery mode differs. SubscriptionService accepts both, and
        // TickSchedulerWorker branches on PushMode (webhook vs inJobStream)
        // for transport; payload compute is symmetric. Pre-2026-05-25 the
        // switch only handled "tick_echo" and every tick_stream_echo
        // subscription threw at compute time (audit F3).
        return sub.OfferingName switch
        {
            "tick_echo" or "tick_stream_echo" => await ComputeTickEcho(sub, tickNumber),
            _ => throw new InvalidOperationException($"unknown offering: {sub.OfferingName}")
        };
    }

    private async Task<string> ComputeTickEcho(Subscription sub, int tick)
    {
        var state = await _tickEcho.GetAsync(sub.Id)
            ?? throw new InvalidOperationException($"tick_echo state missing for subscription {sub.Id}");
        var payload = new
        {
            subscriptionId = sub.Id,
            tick,
            totalTicks = sub.TicksPurchased,
            message = state.Message,
            deliveredAt = DateTime.UtcNow.ToString("O")
        };
        return JsonSerializer.Serialize(payload);
    }
}
