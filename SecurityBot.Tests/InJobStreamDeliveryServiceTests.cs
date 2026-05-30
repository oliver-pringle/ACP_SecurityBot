using System.Net;
using System.Text;
using System.Text.Json;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace SecurityBot.Tests;

public class InJobStreamDeliveryServiceTests
{
    private static Subscription StreamSub(
        string id = "sub-1",
        int? streamChainId = 84532,
        string? streamJobId = "12345")
        => new(
            Id: id,
            JobId: $"job-{id}",
            BuyerAgent: "0xbuyer",
            OfferingName: "tick_stream_echo",
            RequirementJson: "{}",
            WebhookUrl: null,
            WebhookSecret: null,
            IntervalSeconds: 60,
            TicksPurchased: 5,
            TicksDelivered: 0,
            CreatedAt: DateTime.UtcNow,
            ExpiresAt: DateTime.UtcNow.AddHours(1),
            LastRunAt: null,
            NextRunAt: DateTime.UtcNow,
            Status: "active",
            ConsecutiveFailures: 0,
            PushMode: "inJobStream",
            StreamChainId: streamChainId,
            StreamJobId: streamJobId
        );

    private static (InJobStreamDeliveryService svc, RecordingHandler handler) NewSvc(
        HttpStatusCode statusCode = HttpStatusCode.OK,
        string responseBody = "{\"ok\":true}",
        string baseUrl = "http://sidecar.test:6001")
    {
        var handler = new RecordingHandler(statusCode, responseBody);
        var http = new HttpClient(handler);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["StreamPush:BaseUrl"] = baseUrl,
                ["ApiKey"]             = "test-key"
            })
            .Build();
        return (new InJobStreamDeliveryService(http, cfg, NullLogger<InJobStreamDeliveryService>.Instance), handler);
    }

    [Fact]
    public async Task PushAsync_returns_ok_and_posts_to_push_tick_endpoint()
    {
        var (svc, handler) = NewSvc();
        var result = await svc.PushAsync(StreamSub(), tickNumber: 1, payloadJson: "{\"x\":1}");
        Assert.True(result.Ok);
        Assert.Single(handler.Requests);
        Assert.Equal("http://sidecar.test:6001/v1/internal/push-tick", handler.Requests[0].url);
        Assert.Equal("test-key", handler.Requests[0].apiKey);
    }

    [Fact]
    public async Task PushAsync_body_includes_subscription_chain_job_tick_payload()
    {
        var (svc, handler) = NewSvc();
        await svc.PushAsync(StreamSub("sub-42"), tickNumber: 3, payloadJson: "{\"hello\":\"world\"}");

        using var doc = JsonDocument.Parse(handler.Requests[0].body);
        var root = doc.RootElement;
        Assert.Equal("sub-42",  root.GetProperty("subscriptionId").GetString());
        Assert.Equal(84532,     root.GetProperty("chainId").GetInt32());
        Assert.Equal("12345",   root.GetProperty("jobId").GetString());
        Assert.Equal(3,         root.GetProperty("tickNumber").GetInt32());
        Assert.Equal("{\"hello\":\"world\"}", root.GetProperty("payloadJson").GetString());
    }

    [Fact]
    public async Task PushAsync_returns_failure_on_502()
    {
        var (svc, _) = NewSvc(HttpStatusCode.BadGateway, "{\"error\":\"sendMessage failed\"}");
        var result = await svc.PushAsync(StreamSub(), 1, "{}");
        Assert.False(result.Ok);
        Assert.Contains("HTTP 502", result.Error);
    }

    [Fact]
    public async Task PushAsync_returns_failure_labelled_gone_on_410()
    {
        var (svc, _) = NewSvc(HttpStatusCode.Gone, "{\"error\":\"session not active\"}");
        var result = await svc.PushAsync(StreamSub(), 1, "{}");
        Assert.False(result.Ok);
        Assert.Contains("gone", result.Error);
    }

    [Fact]
    public async Task PushAsync_throws_when_subscription_missing_chainId()
    {
        var (svc, _) = NewSvc();
        var bad = StreamSub(streamChainId: null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.PushAsync(bad, 1, "{}"));
    }

    [Fact]
    public async Task PushAsync_throws_when_subscription_missing_jobId()
    {
        var (svc, _) = NewSvc();
        var bad = StreamSub(streamJobId: null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.PushAsync(bad, 1, "{}"));
    }

    [Fact]
    public async Task PushAsync_rejects_payload_above_1MB()
    {
        var (svc, _) = NewSvc();
        var big = new string('x', 1_200_000);
        var result = await svc.PushAsync(StreamSub(), 1, big);
        Assert.False(result.Ok);
        Assert.Contains("exceeds", result.Error);
    }

    [Fact]
    public async Task FinaliseAsync_posts_to_submit_final_endpoint()
    {
        var (svc, handler) = NewSvc();
        var result = await svc.FinaliseAsync(StreamSub(), "{\"done\":true}");
        Assert.True(result.Ok);
        Assert.Single(handler.Requests);
        Assert.Equal("http://sidecar.test:6001/v1/internal/submit-final", handler.Requests[0].url);

        using var doc = JsonDocument.Parse(handler.Requests[0].body);
        var root = doc.RootElement;
        Assert.Equal("sub-1", root.GetProperty("subscriptionId").GetString());
        Assert.Equal("{\"done\":true}", root.GetProperty("finalPayloadJson").GetString());
    }

    // Test double for HttpClient. Records every request so assertions can
    // inspect URL / headers / body, and returns a fixed status + body.
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<(string url, string body, string? apiKey)> Requests { get; } = new();
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public RecordingHandler(HttpStatusCode status, string body) { _status = status; _body = body; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var url = request.RequestUri?.ToString() ?? "";
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            string? apiKey = null;
            if (request.Headers.TryGetValues("X-API-Key", out var values))
                apiKey = string.Join(",", values);
            Requests.Add((url, body, apiKey));
            return new HttpResponseMessage(_status) { Content = new StringContent(_body, Encoding.UTF8, "application/json") };
        }
    }
}
