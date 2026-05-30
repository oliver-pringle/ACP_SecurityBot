using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using SecurityBot.Api.Data;
using SecurityBot.Api.Middleware;
using SecurityBot.Api.Models;
using SecurityBot.Api.Services;
using SecurityBot.Api.Workers;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

// Data
builder.Services.AddSingleton<Db>();
builder.Services.AddSingleton<EchoRepository>();
builder.Services.AddSingleton<WebhookSecretCipher>();   // AES-GCM at rest for webhook_secret (audit F3)
builder.Services.AddSingleton<SubscriptionRepository>();
builder.Services.AddSingleton<SubscriptionRunRepository>();
builder.Services.AddSingleton<TickEchoRepository>();

// Services
builder.Services.AddSingleton<EchoService>();
builder.Services.AddSingleton<SubscriptionService>();
builder.Services.AddSingleton<TickExecutorService>();
// WebhookDeliveryService is hardened against DNS-rebind TOCTOU + 3xx
// redirects (audit F1): the SocketsHttpHandler.ConnectCallback re-validates
// every resolved IPEndPoint against WebhookUrlValidator.IsConnectBlocked
// before the TCP connect, and AllowAutoRedirect=false ensures a 302 Location
// can't redirect a validated public webhook to 169.254.169.254 / 127.0.0.1
// / 10.0.0.0/8 etc. Lifted from ACP_OracleBot v0.7 / ACP_SolanaBot 2026-05-24.
builder.Services.AddHttpClient<WebhookDeliveryService>()
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectCallback   = WebhookConnectCallbacks.PinValidatedIp,
    });
// InJobStreamDeliveryService targets the sidecar's internal HTTP server at
// an operator-controlled URL (SECURITYBOT_STREAM_PUSH_URL), NOT a
// buyer-supplied address — so the SSRF lane doesn't apply. Kept on the
// default handler.
builder.Services.AddHttpClient<InJobStreamDeliveryService>();

// Hosted workers
builder.Services.AddHostedService<TickSchedulerWorker>();
builder.Services.AddHostedService<RetryWorker>();

builder.Services.AddOpenApi();

const long MaxRequestBodyBytes = 256L * 1024L;
builder.Services.Configure<KestrelServerOptions>(o =>
{
    o.Limits.MaxRequestBodySize = MaxRequestBodyBytes;
});

// Trust X-Forwarded-For / X-Forwarded-Proto ONLY from configured proxy
// networks. Default 172.16.0.0/12 (docker bridge) + loopback v4/v6. Audit F5:
// the rate limiter keyed by ctx.Connection.RemoteIpAddress was previously
// pinned to the Caddy IP whenever the bot ran behind a reverse proxy, so
// every external caller shared one bucket. UseForwardedHeaders runs BEFORE
// the rate-limit middleware below so RemoteIpAddress reflects the real
// client when (and only when) the proxy IP is in the trusted set.
//
// Operators tighten on the droplet by setting TRUSTED_PROXY_NETWORKS to the
// exact Caddy bridge CIDR (e.g. 172.23.0.0/24). KnownIPNetworks.Clear before
// adding is critical — the default ASP.NET trust list is empty but defensive
// clones may inherit non-empty defaults.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
    var raw = builder.Configuration["TRUSTED_PROXY_NETWORKS"]
              ?? Environment.GetEnvironmentVariable("TRUSTED_PROXY_NETWORKS")
              ?? "172.16.0.0/12,127.0.0.0/8,::1/128";
    foreach (var cidr in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        try { o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr)); }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"TRUSTED_PROXY_NETWORKS entry '{cidr}' is not a valid CIDR.", ex);
        }
    }
});

var app = builder.Build();

var db = app.Services.GetRequiredService<Db>();
await db.InitializeSchemaAsync();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Fail-fast on legacy ALLOW_INSECURE_WEBHOOKS=true outside Development. The
// flag historically bypassed BOTH the https check AND the DNS+private-IP
// check — audit finding #3 split it into ALLOW_HTTP_WEBHOOKS +
// DISABLE_WEBHOOK_DNS_VALIDATION, but the legacy alias is retained for tests.
// In production, refusing to boot is safer than silently shipping the bypass.
var insecureWebhooks = string.Equals(
    builder.Configuration["ALLOW_INSECURE_WEBHOOKS"]
        ?? Environment.GetEnvironmentVariable("ALLOW_INSECURE_WEBHOOKS"),
    "true", StringComparison.OrdinalIgnoreCase);
var disableDnsValidation = string.Equals(
    builder.Configuration["DISABLE_WEBHOOK_DNS_VALIDATION"]
        ?? Environment.GetEnvironmentVariable("DISABLE_WEBHOOK_DNS_VALIDATION"),
    "true", StringComparison.OrdinalIgnoreCase);
if (!app.Environment.IsDevelopment())
{
    if (insecureWebhooks)
        throw new InvalidOperationException(
            "ALLOW_INSECURE_WEBHOOKS=true is only permitted in Development (legacy flag, " +
            "bypasses both https and DNS+private-IP checks). " +
            $"Current environment: {app.Environment.EnvironmentName}. " +
            "Use the granular ALLOW_HTTP_WEBHOOKS / DISABLE_WEBHOOK_DNS_VALIDATION flags " +
            "if you really need one of those behaviours, and never set DISABLE_WEBHOOK_DNS_VALIDATION outside tests.");
    if (disableDnsValidation)
        throw new InvalidOperationException(
            "DISABLE_WEBHOOK_DNS_VALIDATION=true is only permitted in Development. " +
            $"Current environment: {app.Environment.EnvironmentName}. " +
            "Without this check, an attacker can register a webhook whose hostname DNS-rebinds " +
            "to a private/metadata address — exactly the SSRF lane this flag exists to test.");

    // 2026-05-25 hardening (audit F3): require WEBHOOK_SECRET_ENCRYPTION_KEY in
    // non-Development so webhook HMAC secrets aren't sitting plaintext in
    // SQLite. A leaked DB ⇒ every buyer's webhook can be forged by replaying
    // signed tick payloads from the seller's side. Opt-out (for transitional
    // deploys only) via SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS=true.
    var webhookCipher = app.Services.GetRequiredService<WebhookSecretCipher>();
    var allowPlaintextSecrets = string.Equals(
        builder.Configuration["SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS"]
            ?? Environment.GetEnvironmentVariable("SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS"),
        "true", StringComparison.OrdinalIgnoreCase);
    if (!webhookCipher.IsEncryptionEnabled && !allowPlaintextSecrets)
        throw new InvalidOperationException(
            "WEBHOOK_SECRET_ENCRYPTION_KEY is required in non-Development environments. " +
            $"Current environment: {app.Environment.EnvironmentName}. Generate a 32-byte " +
            "random base64 key (`openssl rand -base64 32`) and set the env var, or set " +
            "SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS=true for a transitional deploy.");
    if (!webhookCipher.IsEncryptionEnabled && allowPlaintextSecrets)
        app.Logger.LogWarning(
            "SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS=true — webhook_secret column persists plaintext. " +
            "Treat the SQLite file + every backup as bearer credentials for forging buyer webhooks.");
}

// 2026-05-25 hardening (audit F5): trust X-Forwarded-For BEFORE the rate
// limiter so per-IP buckets attribute the real client when (and only when)
// the proxy IP is in TRUSTED_PROXY_NETWORKS. ForwardedHeadersOptions is
// configured above so this is a no-op when the bot runs without a proxy.
app.UseForwardedHeaders();

// Per-IP + per-X-API-Key sliding-window rate limit on heavy / write endpoints
// (audit F9). Placed BEFORE auth so unauthenticated floods are also throttled.
// Tunable via RateLimit:HeavyEndpointCapPerIp + RateLimit:HeavyEndpointCapPerApiKey.
app.UseMiddleware<RateLimitMiddleware>();

// Baseline security headers on every response (audit F10). OnStarting so
// downstream middleware can't accidentally erase them.
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        var p = ctx.Request.Path.Value ?? string.Empty;
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"]        = "no-referrer";
        ctx.Response.Headers["X-Frame-Options"]        = "DENY";
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
        // /health + /v1/resources/* are deliberately CACHE-friendly — they're
        // intended for orchestrator pre-flight probes that benefit from a
        // short proxy TTL. Everything else is no-store.
        if (!p.StartsWith("/v1/resources/", StringComparison.Ordinal) && p != "/health")
            ctx.Response.Headers["Cache-Control"] = "no-store";
        return Task.CompletedTask;
    });
    await next();
});

// X-API-Key middleware. Required in any non-Development environment — a fail-
// open default plus a bad .env deploy or env-load failure would silently expose
// every endpoint. In Development the key is also required by default, unless
// the explicit escape hatch SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV=true
// is set — closes audit F1 ("auth can be silently disabled by env-load failure").
//
// DEFERRED (KnownBugs P24): the boilerplate ships a single shared X-API-Key
// gating create-subscription, write-echo, and read endpoints. The audit's
// High #1 recommends a capability split (READ/WRITE/GAS/OPS) so a leaked key
// has bounded blast radius. ChainlinkBot already pioneered X-Ops-Key for
// /v1/internal/wallet-hijack as precedent. Clones that retrofit the split
// should add per-capability keys here, NOT add new auth lanes to bypass this
// middleware. See security-audit/SecurityBot/KnownBugs.md#p24.
var apiKey = builder.Configuration["ApiKey"]
    ?? Environment.GetEnvironmentVariable("SECURITYBOT_API_KEY");
var allowUnauthenticatedDev = string.Equals(
    builder.Configuration["SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV"]
        ?? Environment.GetEnvironmentVariable("SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV"),
    "true", StringComparison.OrdinalIgnoreCase);
if (string.IsNullOrEmpty(apiKey))
{
    if (!app.Environment.IsDevelopment())
    {
        throw new InvalidOperationException(
            "SECURITYBOT_API_KEY is required in non-Development environments. " +
            $"Current environment: {app.Environment.EnvironmentName}. Set the env var " +
            "(or `ApiKey` in configuration) to a high-entropy random string.");
    }
    if (!allowUnauthenticatedDev)
    {
        throw new InvalidOperationException(
            "SECURITYBOT_API_KEY is required even in Development. " +
            "Set the env var (or `ApiKey`) to any string for local dev, or set " +
            "SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV=true to explicitly opt into unauth mode.");
    }
    app.Logger.LogWarning(
        "SECURITYBOT_API_KEY not set + SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV=true — Development unauth mode. " +
        "All non-/health, non-/v1/resources endpoints accept all callers.");
}
else
{
    var expectedBytes = Encoding.UTF8.GetBytes(apiKey);
    app.Use(async (ctx, next) =>
    {
        // /health stays open for liveness/readiness probes.
        // /v1/resources/* stays open so buyer / orchestrator agents (Butler etc.)
        // can introspect the bot pre-hire — that's the whole point of Resources.
        var path = ctx.Request.Path.Value ?? string.Empty;
        if (path == "/health" || path.StartsWith("/v1/resources/", StringComparison.Ordinal)) { await next(); return; }
        if (!ctx.Request.Headers.TryGetValue("X-API-Key", out var provided))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsync("unauthorized");
            return;
        }
        var providedBytes = Encoding.UTF8.GetBytes(provided.ToString());
        if (providedBytes.Length != expectedBytes.Length ||
            !CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsync("unauthorized");
            return;
        }
        await next();
    });
    app.Logger.LogInformation("X-API-Key middleware enabled.");
}

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    time = DateTime.UtcNow.ToString("O")
}));

const int MaxMessageLength = 10_000;

app.MapPost("/echo", async (EchoRequest req, EchoService svc) =>
{
    if (string.IsNullOrWhiteSpace(req.Message))
        return Results.BadRequest(new { error = "message is required" });
    if (req.Message.Length > MaxMessageLength)
        return Results.BadRequest(new { error = $"message exceeds {MaxMessageLength} character limit" });
    var record = await svc.RecordAsync(req.Message);
    return Results.Ok(record);
});

app.MapGet("/echo/{id:long}", async (long id, EchoService svc) =>
{
    var record = await svc.GetAsync(id);
    return record is null ? Results.NotFound() : Results.Ok(record);
});

app.MapPost("/subscriptions", async (CreateSubscriptionRequest req, SubscriptionService svc) =>
{
    if (string.IsNullOrWhiteSpace(req.JobId))
        return Results.BadRequest(new { error = "jobId is required" });
    if (string.IsNullOrWhiteSpace(req.OfferingName))
        return Results.BadRequest(new { error = "offeringName is required" });
    try
    {
        var resp = await svc.CreateAsync(req);
        return Results.Ok(resp);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// GET /subscriptions/{id}
//   Default response = SubscriptionView.Minimal — excludes buyer-sensitive
//   fields (RequirementJson, WebhookUrl, BuyerAgent, StreamJobId). Any
//   X-API-Key-authenticated caller can poll status + counts; nothing buyer-
//   identifying leaks.
//
//   Pass header X-Subscription-Secret: <webhookSecret> for the FULL projection
//   (still excludes WebhookSecret itself — the caller proves they already
//   know it, no need to echo it back). The secret was delivered ONCE in the
//   ACP subscription receipt, so only the buyer holds it. Constant-time
//   compare against the stored secret. Closes audit F5.
//
//   inJobStream subscriptions have no webhookSecret — the full projection
//   is unreachable via this lane for them; only the minimal view is
//   returned regardless of headers. Operators on the box can hit the
//   SQLite file directly.
app.MapGet("/subscriptions/{id}", async (string id, HttpContext ctx, SubscriptionRepository repo) =>
{
    var sub = await repo.GetByIdAsync(id);
    if (sub is null) return Results.NotFound();

    if (ctx.Request.Headers.TryGetValue("X-Subscription-Secret", out var providedHeader) &&
        !string.IsNullOrEmpty(sub.WebhookSecret))
    {
        var providedBytes = Encoding.UTF8.GetBytes(providedHeader.ToString());
        var expectedBytes = Encoding.UTF8.GetBytes(sub.WebhookSecret);
        if (providedBytes.Length == expectedBytes.Length &&
            CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes))
        {
            return Results.Ok(SubscriptionView.Full(sub));
        }
        // Wrong secret — fall through to minimal view (not 401: the caller
        // already has X-API-Key, the header is just a privilege upgrade).
    }

    return Results.Ok(SubscriptionView.Minimal(sub));
});

// ACP v2 Resources — public, free, parameterised endpoints mirrored
// 1:1 with entries in acp-v2/src/resources.ts. Buyer / orchestrator agents
// (Butler etc.) call these BEFORE paying for an offering, so handlers must
// be cheap, side-effect-free, and stable. Add new routes here in lockstep
// with new entries in acp-v2/src/resources.ts; run `npm run print-resources`
// in acp-v2/ and paste each block into app.virtuals.io's Resources tab.
//
// Resources stay reachable even when the X-API-Key middleware is on —
// the middleware above whitelists /v1/resources/* alongside /health.
app.MapGet("/v1/resources/echoStatus", async (EchoRepository repo) =>
{
    var (count, lastAt) = await repo.GetStatusAsync();
    return Results.Ok(new
    {
        count,
        lastEchoAt = lastAt?.ToString("O")
    });
});

app.Run();
