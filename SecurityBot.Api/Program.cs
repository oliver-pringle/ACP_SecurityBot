using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Email;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using SecurityBot.Api.Middleware;
using SecurityBot.Api.Models;
using SecurityBot.Api.Resolution;
using SecurityBot.Api.Services;
using SecurityBot.Api.Workers;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

// SecurityBot suppresses its OWN Kestrel "Server: Kestrel" banner. It would be absurd to
// flag other agents for P43 (verbose server/framework banner) while leaking the framework
// in its own responses. AddServerHeader=false strips it at the source so a live self-scan
// stays clean - and any new portfolio bot should lift this line (the Kestrel banner is a
// portfolio-wide P43 finding).
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);

// Data
builder.Services.AddSingleton<Db>();
builder.Services.AddSingleton<WebhookSecretCipher>();   // AES-GCM at rest for webhook_secret (audit F3)
builder.Services.AddSingleton<SubscriptionRepository>();
builder.Services.AddSingleton<SubscriptionRunRepository>();
builder.Services.AddSingleton<ScanRepository>();
builder.Services.AddSingleton<EmailLogRepository>();

// Pattern catalogue (49 entries: P1-P39 cross-cutting + P31-TLS + B1-B9). The
// parameterless ctor loads the copy placed next to the API assembly by the
// csproj <None Include CopyToOutputDirectory>. Singleton — the file is read
// once at first resolution and held in memory.
builder.Services.AddSingleton<PatternCatalogue>();

// Email backend. Resend transactional sender when BOTH RESEND_API_KEY and
// SECURITYBOT_EMAIL_FROM are configured; otherwise NoopEmailSender ("no_backend").
// The email spike (docs/email-spike-findings.md) found @agents.world is a real
// Mailgun/SES-backed inbox reachable by any transactional send — there is NO special
// Virtuals send API — but the recipient is BUYER-SUPPLIED (no public agent->email
// directory). Default-OFF: with no key the bot reports no_backend exactly as v1 did.
// SECURITYBOT_EMAIL_FROM MUST be on a Resend-verified domain (SPF/DKIM/DMARC) or mail
// to agents.world (Mailgun inbound) will be spam-filtered.
var resendApiKey = builder.Configuration["RESEND_API_KEY"]
    ?? Environment.GetEnvironmentVariable("RESEND_API_KEY");
var emailFrom = builder.Configuration["SECURITYBOT_EMAIL_FROM"]
    ?? Environment.GetEnvironmentVariable("SECURITYBOT_EMAIL_FROM");
var emailEnabled = !string.IsNullOrWhiteSpace(resendApiKey) && !string.IsNullOrWhiteSpace(emailFrom);
if (emailEnabled)
{
    builder.Services.AddHttpClient("resend", c => c.Timeout = TimeSpan.FromSeconds(15));
    builder.Services.AddSingleton<IEmailSender>(sp => new ResendEmailSender(
        sp.GetRequiredService<IHttpClientFactory>().CreateClient("resend"),
        resendApiKey!,
        emailFrom!,
        sp.GetRequiredService<ILogger<ResendEmailSender>>()));
}
else
{
    builder.Services.AddSingleton<IEmailSender, NoopEmailSender>();
}

// Audit engine — the scan pipeline the WatchWorker re-runs each tick. The
// outbound probe client is the most-hardened HTTP client in the bot (SSRF
// classifier refuses private/loopback/reserved targets). Each of the 8 checks
// is a stateless IProbeCheck; the engine runs every registered one over a
// single probe-once pass. corpusVersion is the pattern-catalogue date stamp
// recorded on each persisted scan. The scan endpoint (Task 11) resolves the
// SAME DynamicAuditEngine singleton.
builder.Services.AddSingleton<ProbeClient>();
builder.Services.AddSingleton<IProbeFetcher>(sp => sp.GetRequiredService<ProbeClient>());
builder.Services.AddSingleton<IProbeCheck, AuthPostureCheck>();
builder.Services.AddSingleton<IProbeCheck, ErrorLeakCheck>();
builder.Services.AddSingleton<IProbeCheck, RateLimitHintCheck>();
builder.Services.AddSingleton<IProbeCheck, RawDumpCheck>();
builder.Services.AddSingleton<IProbeCheck, ResourceDisclosureCheck>();
builder.Services.AddSingleton<IProbeCheck, SchemaDescriptionCheck>();
builder.Services.AddSingleton<IProbeCheck, SecurityHeadersCheck>();
builder.Services.AddSingleton<IProbeCheck, TlsTransportCheck>();
builder.Services.AddSingleton<IProbeCheck, CorsCheck>();          // P42 wildcard CORS
builder.Services.AddSingleton<IProbeCheck, ServerBannerCheck>();  // P43 verbose server/framework banner
builder.Services.AddSingleton<IProbeCheck, StubDataCheck>();      // P38 stub/placeholder markers in served bodies
const string CorpusVersion = "2026-05-30";
builder.Services.AddSingleton(sp => new DynamicAuditEngine(
    sp.GetRequiredService<IProbeFetcher>(),
    sp.GetServices<IProbeCheck>(),
    CorpusVersion));

// Marketplace fetch lane for the resolver. A dedicated HttpClient (short
// timeout, no auto-redirect) is used to GET the V2 marketplace agent record and
// extract the agent's advertised resources[].url fields. The resolution LOGIC
// itself is unit-tested in Task 10 with a fake delegate; here we wire a
// best-effort, NON-THROWING delegate so an unreachable / shape-shifted
// marketplace yields an empty list (=> NOT_AUDITABLE) instead of a 500.
builder.Services.AddHttpClient("marketplace", c =>
{
    c.Timeout = TimeSpan.FromSeconds(8);
    c.DefaultRequestHeaders.Add("Accept", "application/json");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
{
    AllowAutoRedirect = false,
});
builder.Services.AddSingleton<ITargetResolver>(sp =>
{
    var factory = sp.GetRequiredService<IHttpClientFactory>();
    var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("MarketplaceResolver");
    return new MarketplaceTargetResolver(async (agentAddress, ct) =>
        await MarketplaceResourceFetcher.FetchAsync(factory, logger, agentAddress, ct));
});

// Services
builder.Services.AddSingleton<SubscriptionService>();
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
builder.Services.AddHostedService<WatchWorker>();
builder.Services.AddHostedService<RetryWorker>();
// Daily WAL-aware online SQLite snapshot to /data/backups (portfolio
// convention P6). Lifted from LiquidGuard. Keeps 7 days; configurable via
// Backup:HourUtc (default 04:00) / Backup:KeepDays / Backup:Directory.
builder.Services.AddHostedService<BackupWorker>();

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

// Proactive-outreach kill-switch. SecurityBot has NO outreach worker in v1 -
// this is the conscious default-OFF posture + a boot log so the stance is
// visible on every restart. The bot is a PASSIVE auditor: it answers paid
// hires and re-scans watched targets; it never cold-mails an agent operator
// unless this flag is explicitly flipped. Any future proactive-outreach
// worker MUST gate on this flag (default false) before sending anything.
var outreachEnabled = string.Equals(
    builder.Configuration["SECURITYBOT_OUTREACH_ENABLED"]
        ?? Environment.GetEnvironmentVariable("SECURITYBOT_OUTREACH_ENABLED"),
    "true", StringComparison.OrdinalIgnoreCase);
app.Logger.LogInformation("Outreach worker: {State} (SECURITYBOT_OUTREACH_ENABLED={Flag})",
    outreachEnabled ? "ENABLED" : "DISABLED", outreachEnabled);
app.Logger.LogInformation("Email backend: {Backend}",
    emailEnabled ? $"Resend ENABLED (from {emailFrom})" : "DISABLED (no_backend; set RESEND_API_KEY + SECURITYBOT_EMAIL_FROM)");

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
    catch (SubscriptionLimitException)
    {
        // P60: the seller is at its active-subscription quota (global or
        // per-buyer). 429 (not 400) so buyers retry rather than treat it as a
        // malformed request. Message is intentionally generic (P30) — the cap
        // value isn't leaked.
        return Results.Json(new { error = "SUBSCRIPTION_LIMIT_REACHED" }, statusCode: StatusCodes.Status429TooManyRequests);
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

// patternCatalogue — the full P1-P39 + B1-B9 catalogue (49 entries). Free public
// recon: the differentiator vs generic Solidity auditors. No DB, no secrets.
app.MapGet("/v1/resources/patternCatalogue", (PatternCatalogue catalogue) =>
    Results.Ok(new
    {
        corpusVersion = catalogue.CorpusVersion,
        count = catalogue.All().Count,
        patterns = catalogue.All().Select(p => new
        {
            id = p.Id, title = p.Title, severity = p.Severity,
            detection = p.Detection, canonicalFix = p.CanonicalFix, referenceBot = p.ReferenceBot
        })
    }));

// auditByAgent — most-recent scan SUMMARY for an agent. Counts + score only;
// NEVER raw evidence or URLs (P9/P10 self-application). found:false when absent.
// agentAddress binds as string? (NOT a nullable value type) to dodge the
// silent-400 nullable-VALUE-type boilerplate gotcha. The deliberate omission of
// baseUrl + evidence from the response is the P9/P10 self-application — a public
// recon surface must not echo what the bot found, only that it found N issues.
app.MapGet("/v1/resources/auditByAgent", async (string? agentAddress, ScanRepository scans) =>
{
    if (string.IsNullOrWhiteSpace(agentAddress))
        return Results.Ok(new { found = false, reason = "agentAddress query param required" });
    var rec = await scans.GetMostRecentByAgentAsync(agentAddress);
    if (rec is null)
        return Results.Ok(new { found = false });
    var counts = await scans.GetFindingSeverityCountsAsync(agentAddress, null);
    return Results.Ok(new
    {
        found = true,
        agentAddress,
        score = rec.Score,
        grade = rec.Grade,
        observableCount = rec.ObservableCount,
        findingCount = rec.FindingCount,
        severityCounts = counts,
        scannedAt = rec.ScannedAtUtc.ToString("O")
    });
});

// GET /v1/resources/offerings — free introspection: the offering catalogue with
// each offering's requirementSchema + the internal self-test path the website's
// admin "run console" (BotRunController) calls to exercise an offering without
// ACP escrow. Whitelisted (under /v1/resources/), no secrets, no DB. Keep this
// in lockstep with acp-v2/src/offerings/*.ts.
app.MapGet("/v1/resources/offerings", () => Results.Ok(new
{
    supported = true,
    offerings = new object[]
    {
        new
        {
            name = "security_scan",
            description = "Dynamic passive security audit of a live ACP agent against the P1-P43 KnownBugs catalogue.",
            priceUsdc = 1.00m,
            priceType = "fixed",
            internalPath = "/v1/internal/scan",
            requirementSchema = new
            {
                type = "object",
                properties = new
                {
                    agentAddress   = new { type = "string",  description = "The agent's 0x EVM wallet address; resolves the public surface from the marketplace. Provide this OR baseUrl." },
                    baseUrl        = new { type = "string",  format = "uri",   description = "Explicit public base URL to scan (e.g. https://api.example.com). Provide this OR agentAddress." },
                    emailReport    = new { type = "boolean", description = "If true, also email the report to recipientEmail. Default false." },
                    recipientEmail = new { type = "string",  format = "email", description = "Where to email the report when emailReport is true." }
                },
                required = Array.Empty<string>()
            },
            requirementExample = new { agentAddress = "0xecf9773b50f01f3a97b087a6ecdf12a71afc558c", emailReport = false }
        },
        new
        {
            name = "security_watch",
            description = "Recurring passive re-audit with webhook alerts on score regression.",
            priceUsdc = (decimal?)null,
            priceType = "subscription",
            internalPath = (string?)null,   // subscription: no synchronous self-test
            requirementSchema = (object?)null,
            requirementExample = (object?)null
        }
    }
}));

// POST /v1/internal/scan — the paid scan offering's internal endpoint. The
// sidecar forwards a paid hire here with the internal X-API-Key (gated by the
// middleware above; not public, not under /v1/resources/). Pipeline:
//   resolve target -> (auditable?) -> scan -> persist -> optional email
//   -> assemble the deliverable JSON the sidecar forwards to the buyer as-is.
//
// The whole handler is wrapped in try/catch returning a stable INTERNAL_ERROR
// (P30 — never leak ex.Message). NOT_AUDITABLE is a NORMAL 200 deliverable,
// not an error.
app.MapPost("/v1/internal/scan", async (
    HttpContext ctx,
    ITargetResolver resolver,
    DynamicAuditEngine engine,
    ScanRepository scanRepo,
    EmailLogRepository emailLog,
    IEmailSender emailSender,
    CancellationToken ct) =>
{
    try
    {
        // Read the body into the typed record. ReadFromJsonAsync binds the
        // reference-typed string? fields + the bool with a default; this avoids
        // the nullable-VALUE-type silent-400 boilerplate gotcha (bool is a
        // value type but it has an explicit default of false here and ASP.NET
        // tolerates a missing property on a record default). A null / empty /
        // unparseable body is a stable 400.
        ScanRequest? req;
        try
        {
            req = await ctx.Request.ReadFromJsonAsync<ScanRequest>(ct);
        }
        catch (JsonException)
        {
            return Results.Json(new { error = "INVALID_REQUEST" }, statusCode: 400);
        }
        if (req is null)
            return Results.Json(new { error = "INVALID_REQUEST" }, statusCode: 400);

        var resolved = await resolver.ResolveAsync(req.AgentAddress, req.BaseUrl, ct);

        // NOT_AUDITABLE is a normal deliverable (200), not an error — the buyer
        // paid for an honest answer and "this agent has no auditable surface" is
        // one. No scan row is written for a non-auditable target.
        if (!resolved.Auditable)
        {
            return Results.Ok(new
            {
                agentAddress = req.AgentAddress,
                baseUrl = req.BaseUrl,
                resolvedVia = resolved.ResolvedVia,
                verdict = "NOT_AUDITABLE",
                reason = resolved.Reason,
            });
        }

        var target = new ScanTarget(
            req.AgentAddress, resolved.BaseUrl!, resolved.ResolvedVia, resolved.ResourceUrls);
        var report = await engine.ScanAsync(target, ct);

        // Persist the scan + its findings atomically. FindingCount = report
        // findings count; corpus version stamped from the engine's constant.
        var rec = new ScanRecord(
            AgentAddress: report.AgentAddress,
            BaseUrl: report.BaseUrl,
            ResolvedVia: report.ResolvedVia,
            Score: report.Score,
            Grade: report.Grade,
            ObservableCount: report.ObservableCount,
            FindingCount: report.Findings.Count,
            Verdict: report.Verdict,
            CorpusVersion: CorpusVersion,
            ScannedAtUtc: report.ScannedAtUtc);
        var scanId = await scanRepo.InsertAsync(rec, report.Findings);

        // Optional email tier. The recipient is BUYER-SUPPLIED (recipientEmail). The
        // audited agent's @agents.world inbox is a real Mailgun-backed mailbox, but its
        // address is NOT exposed by the public V2 marketplace API so it can't be
        // auto-resolved (see docs/email-spike-findings.md). With no valid recipient we
        // don't call the sender — the honest status is "skipped". Otherwise the
        // configured IEmailSender (Resend when keyed, else Noop -> "no_backend") delivers.
        string? emailDelivery = null;
        if (req.EmailReport)
        {
            var recipient = req.RecipientEmail?.Trim();
            var hasRecipient = !string.IsNullOrEmpty(recipient)
                && recipient!.Length <= 254
                && System.Net.Mail.MailAddress.TryCreate(recipient, out _);

            if (!hasRecipient)
            {
                emailDelivery = "skipped";
                await emailLog.InsertAsync(
                    toAddress: recipient is { Length: > 0 } ? recipient! : "(none)",
                    agentAddress: req.AgentAddress,
                    scanId: scanId,
                    status: emailDelivery,
                    sentAt: DateTime.UtcNow);
            }
            else
            {
                var emailPayload = new
                {
                    baseUrl = report.BaseUrl,
                    agentAddress = report.AgentAddress,
                    score = report.Score,
                    grade = report.Grade,
                    verdict = report.Verdict,
                    summary = report.Summary,
                    scannedAt = report.ScannedAtUtc.ToString("O"),
                    findings = report.Findings.Select(f => new
                    {
                        patternId = f.PatternId,
                        title = f.Title,
                        severity = f.Severity.ToString(),
                        verdict = f.Verdict.ToString(),
                    }).ToList(),
                };
                var sendResult = await emailSender.SendScanReportAsync(recipient!, emailPayload, ct);
                emailDelivery = sendResult.Status;   // sent | failed | no_backend
                await emailLog.InsertAsync(
                    toAddress: recipient!,
                    agentAddress: req.AgentAddress,
                    scanId: scanId,
                    status: emailDelivery,
                    sentAt: DateTime.UtcNow);
            }
        }

        // Assemble the deliverable. Enum-typed Severity/Verdict are emitted as
        // their NAMES (ASP.NET serialises enums as ints by default — call
        // .ToString()). _emailDelivery is present ONLY when emailReport was true.
        var findings = report.Findings.Select(f => new
        {
            patternId = f.PatternId,
            title = f.Title,
            severity = f.Severity.ToString(),
            verdict = f.Verdict.ToString(),
            evidence = f.Evidence,
            fixRef = f.FixRef,
        }).ToList();

        if (req.EmailReport)
        {
            return Results.Ok(new
            {
                agentAddress = report.AgentAddress,
                baseUrl = report.BaseUrl,
                resolvedVia = report.ResolvedVia,
                scannedAt = report.ScannedAtUtc.ToString("O"),
                score = report.Score,
                grade = report.Grade,
                observableCount = report.ObservableCount,
                totalPatterns = report.TotalPatterns,
                findings,
                summary = report.Summary,
                verdict = report.Verdict,
                _emailDelivery = emailDelivery,
            });
        }

        return Results.Ok(new
        {
            agentAddress = report.AgentAddress,
            baseUrl = report.BaseUrl,
            resolvedVia = report.ResolvedVia,
            scannedAt = report.ScannedAtUtc.ToString("O"),
            score = report.Score,
            grade = report.Grade,
            observableCount = report.ObservableCount,
            totalPatterns = report.TotalPatterns,
            findings,
            summary = report.Summary,
            verdict = report.Verdict,
        });
    }
    catch (Exception)
    {
        // P30: never leak ex.Message / stack to the buyer.
        return Results.Json(new { error = "INTERNAL_ERROR" }, statusCode: 500);
    }
});

app.Run();

// The paid scan request body. AgentAddress / BaseUrl are reference-typed (no
// silent-400 nullable-value gotcha); EmailReport is a bool defaulting false so a
// body that omits it binds cleanly.
public sealed record ScanRequest(
    string? AgentAddress, string? BaseUrl, bool EmailReport = false, string? RecipientEmail = null);

// Expose the implicit Program class so WebApplicationFactory<Program> can host
// it in the endpoint tests.
public partial class Program { }
