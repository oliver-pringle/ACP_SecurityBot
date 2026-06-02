using System.Security.Cryptography;
using System.Text.Json;
using SecurityBot.Api.Data;
using SecurityBot.Api.Models;
using SecurityBot.Api.Resolution;

namespace SecurityBot.Api.Services;

// P60: thrown when a create-subscription request would push the active-
// subscription count past the configured global or per-buyer cap. The
// create-subscription route maps this to HTTP 429 (distinct from the 400 that
// InvalidOperationException maps to) so buyers can distinguish "your request is
// malformed" from "the seller is at capacity, retry later".
public sealed class SubscriptionLimitException : Exception
{
    public SubscriptionLimitException(string message) : base(message) { }
}

public class SubscriptionService
{
    private readonly SubscriptionRepository _subs;
    private readonly ITargetResolver _resolver;
    private readonly bool _allowHttpWebhooks;
    private readonly bool _disableWebhookDnsValidation;

    // P60 active-subscription quota (global + per-buyer). Enforced BEFORE the
    // first DB write in CreateAsync so a flood of create-subscription calls
    // can't unbounded-grow the subscriptions table (and the worker fan-out that
    // tracks it). 0 = unlimited for that dimension. Defaults are conservative;
    // operators raise them per-bot via SECURITYBOT_MAX_ACTIVE_GLOBAL /
    // SECURITYBOT_MAX_ACTIVE_PER_BUYER (or the Subscriptions:MaxActive* cfg keys).
    private readonly int _maxActiveGlobal;
    private readonly int _maxActivePerBuyer;
    public const int DefaultMaxActiveGlobal   = 500;
    public const int DefaultMaxActivePerBuyer = 10;

    // Bounds keep the worker pressure and DB rows sane for any clone. Override
    // per-bot only if a specific offering needs different shape.
    public const int MinIntervalSeconds      = 60;            // 1 / minute
    public const int MaxIntervalSeconds      = 86_400;        // 1 / day
    public const int MaxTicks                = 10_000;
    public const int MaxRequirementJsonBytes = 16 * 1024;     // 16 KB
    public static readonly TimeSpan MaxFutureWindow = TimeSpan.FromDays(90);

    // Audit F9: explicit per-field length caps on subscription identifiers.
    // Kestrel's 256 KB body cap and the 16 KB requirement_json cap above
    // already bound the worst case, but field-level limits keep DB rows, log
    // lines, and downstream ACP calls from carrying unexpectedly long values
    // (e.g. attacker spams identifiers under the body cap to bloat tables).
    public const int MaxJobIdLength        = 128;   // ACP jobIds are uint256 in decimal — 78 chars max
    public const int MaxBuyerAgentLength   = 256;   // EVM addresses are 42 chars; leaves headroom for future fmt
    public const int MaxOfferingNameLength = 64;    // marketplace caps offering name at 20; 64 covers any rename
    public const int MaxStreamJobIdLength  = 128;
    public const int MaxWebhookUrlLength   = 2048;  // 2 KB cap; longer URLs almost certainly buyer error

    // inJobStream-mode subscriptions keep an ACP job open for the entire
    // delivery window. The V2 indexer's tolerance for long-open jobs is
    // unverified beyond ~hours (see Phase-1 spec Q1). Hard-cap inJobStream
    // windows much lower than the webhook cap until production data widens it.
    public static readonly TimeSpan MaxStreamWindow = TimeSpan.FromHours(4);

    // Offerings this bot exposes through the subscription path. Add new names
    // here as they're registered in acp-v2/src/offerings/registry.ts; the
    // service rejects unknown names rather than silently creating orphan rows.
    private static readonly HashSet<string> KnownSubscriptionOfferings =
        new(StringComparer.OrdinalIgnoreCase) { "security_watch" };

    public SubscriptionService(SubscriptionRepository subs, ITargetResolver resolver, IConfiguration? cfg = null)
    {
        _subs = subs;
        _resolver = resolver;
        (_allowHttpWebhooks, _disableWebhookDnsValidation) = WebhookFlagsHelper.Resolve(cfg);
        _maxActiveGlobal   = ResolveCap(cfg, "Subscriptions:MaxActiveGlobal",   "SECURITYBOT_MAX_ACTIVE_GLOBAL",   DefaultMaxActiveGlobal);
        _maxActivePerBuyer = ResolveCap(cfg, "Subscriptions:MaxActivePerBuyer", "SECURITYBOT_MAX_ACTIVE_PER_BUYER", DefaultMaxActivePerBuyer);
    }

    // Resolve a cap from configuration (Subscriptions:MaxActive*) or the env
    // var, falling back to the default. A blank or unparseable value uses the
    // default rather than silently disabling the cap (0 disables intentionally).
    private static int ResolveCap(IConfiguration? cfg, string cfgKey, string envVar, int dflt)
    {
        var raw = cfg?[cfgKey] ?? Environment.GetEnvironmentVariable(envVar);
        if (string.IsNullOrWhiteSpace(raw)) return dflt;
        return int.TryParse(raw, out var v) ? v : dflt;
    }

    public async Task<CreateSubscriptionResponse> CreateAsync(CreateSubscriptionRequest req, CancellationToken ct = default)
    {
        // Audit F9: per-field length caps. The route handler in Program.cs has
        // already null-checked JobId + OfferingName, so we only need to upper-
        // bound them here. BuyerAgent / StreamJobId / webhookUrl come straight
        // from the request body; null/empty is allowed for some shapes but a
        // pathologically long value is never legitimate.
        if (req.JobId.Length > MaxJobIdLength)
            throw new InvalidOperationException($"jobId exceeds {MaxJobIdLength} characters");
        if (!string.IsNullOrEmpty(req.BuyerAgent) && req.BuyerAgent.Length > MaxBuyerAgentLength)
            throw new InvalidOperationException($"buyerAgent exceeds {MaxBuyerAgentLength} characters");
        if (req.OfferingName.Length > MaxOfferingNameLength)
            throw new InvalidOperationException($"offeringName exceeds {MaxOfferingNameLength} characters");
        if (!string.IsNullOrEmpty(req.StreamJobId) && req.StreamJobId.Length > MaxStreamJobIdLength)
            throw new InvalidOperationException($"streamJobId exceeds {MaxStreamJobIdLength} characters");

        // DEFERRED (KnownBugs P27): the boilerplate trusts that the sidecar
        // is the only caller and that any (jobId, buyerAgent, offeringName)
        // tuple reaching this method already corresponds to a funded ACP job.
        // The audit's High #2 recommends verifying via the ACP marketplace
        // API before insert — job exists / is funded / seller is us / buyer
        // matches / offering matches. That's a substantial cross-cutting
        // change requiring SDK queries on every create-subscription request
        // (latency + new failure mode). When a clone is sensitive to spoofed
        // create-subscription calls, lift the canonical verifier from
        // ButlerBridge once it ships. See security-audit/SecurityBot/KnownBugs.md#p27.

        if (!KnownSubscriptionOfferings.Contains(req.OfferingName))
            throw new InvalidOperationException($"unknown offering: {req.OfferingName}");

        // P60: enforce the active-subscription quota BEFORE building/inserting
        // the row (fail before first write). Global cap first, then per-buyer.
        // 0 = unlimited for that dimension. SubscriptionLimitException maps to
        // HTTP 429 in the create-subscription route (distinct from the 400 the
        // validation InvalidOperationExceptions above map to).
        if (_maxActiveGlobal > 0 && await _subs.CountActiveAsync() >= _maxActiveGlobal)
            throw new SubscriptionLimitException("global active-subscription limit reached");
        if (_maxActivePerBuyer > 0 && !string.IsNullOrEmpty(req.BuyerAgent)
            && await _subs.CountActiveByBuyerAsync(req.BuyerAgent) >= _maxActivePerBuyer)
            throw new SubscriptionLimitException("per-buyer active-subscription limit reached");

        var pushMode = NormalisePushMode(req.PushMode);

        var ticks = AsInt(req.Requirement, "ticks");
        var interval = AsInt(req.Requirement, "intervalSeconds");

        if (interval < MinIntervalSeconds || interval > MaxIntervalSeconds)
            throw new InvalidOperationException(
                $"intervalSeconds must be {MinIntervalSeconds}..{MaxIntervalSeconds}");
        if (ticks < 1 || ticks > MaxTicks)
            throw new InvalidOperationException($"ticks must be 1..{MaxTicks}");

        var windowSeconds = (long)interval * ticks;
        var windowCap = pushMode == "inJobStream"
            ? (long)MaxStreamWindow.TotalSeconds
            : (long)MaxFutureWindow.TotalSeconds;
        if (windowSeconds > windowCap)
        {
            var capLabel = pushMode == "inJobStream"
                ? $"{MaxStreamWindow.TotalHours} hours (inJobStream cap)"
                : $"{MaxFutureWindow.TotalDays} days";
            throw new InvalidOperationException(
                $"interval × ticks ({windowSeconds}s) exceeds {capLabel}");
        }

        // security_watch carries a scan target (agentAddress and/or baseUrl).
        // Resolve it to a concrete probeable baseUrl at BIND time and persist the
        // result into the requirement, so WatchWorker re-scans the right surface
        // each tick without a per-tick marketplace lookup (and so the buyer's
        // agentAddress-only request actually scans, instead of dead-ticking on a
        // missing baseUrl). Fail fast — BEFORE the first DB write — when the
        // target exposes no externally-auditable surface, rather than accepting a
        // subscription that would record a failed tick on every poll. The
        // resolver (MarketplaceResourceFetcher) is best-effort non-throwing, so a
        // marketplace hiccup degrades to NOT_AUDITABLE here, never a raw network
        // exception leaked to the buyer (P63).
        var resolved = await _resolver.ResolveAsync(
            AsOptionalString(req.Requirement, "agentAddress"),
            AsOptionalString(req.Requirement, "baseUrl"),
            ct);
        if (!resolved.Auditable || string.IsNullOrWhiteSpace(resolved.BaseUrl))
            throw new InvalidOperationException(
                resolved.Reason ?? "target exposes no externally-auditable surface");
        req.Requirement["baseUrl"] = resolved.BaseUrl!;

        var requirementJson = JsonSerializer.Serialize(req.Requirement);
        if (System.Text.Encoding.UTF8.GetByteCount(requirementJson) > MaxRequirementJsonBytes)
            throw new InvalidOperationException(
                $"requirement JSON exceeds {MaxRequirementJsonBytes} bytes");

        // Webhook-specific validation: URL + SSRF guard + per-secret HMAC seed.
        // For inJobStream, the ACP job + transport replaces these — no buyer-
        // hosted URL exists, so the validator and secret allocation are skipped.
        string? webhookUrl = null;
        string? webhookSecret = null;
        int? streamChainId = null;
        string? streamJobId = null;

        if (pushMode == "webhook")
        {
            webhookUrl = AsString(req.Requirement, "webhookUrl");
            // F9 length cap before SSRF check — a 1 MB URL has no legitimate
            // shape and would otherwise reach Uri.TryCreate + DNS resolution.
            if (webhookUrl.Length > MaxWebhookUrlLength)
                throw new InvalidOperationException(
                    $"webhookUrl exceeds {MaxWebhookUrlLength} characters");
            var urlCheck = WebhookUrlValidator.Validate(webhookUrl, _allowHttpWebhooks, _disableWebhookDnsValidation);
            if (!urlCheck.Ok)
                throw new InvalidOperationException(urlCheck.Error!);
            webhookSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        }
        else // inJobStream
        {
            if (req.StreamChainId is null || req.StreamChainId.Value <= 0)
                throw new InvalidOperationException(
                    "inJobStream subscriptions require streamChainId (chain the funded job is on)");
            if (string.IsNullOrWhiteSpace(req.StreamJobId))
                throw new InvalidOperationException(
                    "inJobStream subscriptions require streamJobId (on-chain job id of the kept-open job)");
            streamChainId = req.StreamChainId;
            streamJobId   = req.StreamJobId;
        }

        var id = Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        var expiresAt = now.AddSeconds(windowSeconds);
        var nextRunAt = now.AddSeconds(interval);

        var sub = new Subscription(
            Id: id,
            JobId: req.JobId,
            BuyerAgent: req.BuyerAgent,
            OfferingName: req.OfferingName,
            RequirementJson: requirementJson,
            WebhookUrl: webhookUrl,
            WebhookSecret: webhookSecret,
            IntervalSeconds: interval,
            TicksPurchased: ticks,
            TicksDelivered: 0,
            CreatedAt: now,
            ExpiresAt: expiresAt,
            LastRunAt: null,
            NextRunAt: nextRunAt,
            Status: "active",
            ConsecutiveFailures: 0,
            PushMode: pushMode,
            StreamChainId: streamChainId,
            StreamJobId: streamJobId
        );
        await _subs.InsertAsync(sub);

        // TODO Task 9/12: persist any per-subscription state the security_watch
        // offering needs here. The echo demo wrote a per-tick message row to
        // tick_echo_state via TickEchoRepository; both were removed with the
        // demo domain. The generic subscription row above is all the kept
        // plumbing requires.

        return new CreateSubscriptionResponse(id, webhookSecret, ticks, interval, expiresAt, pushMode);
    }

    private static string NormalisePushMode(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "webhook";
        var v = raw.Trim();
        if (v.Equals("webhook", StringComparison.OrdinalIgnoreCase)) return "webhook";
        if (v.Equals("inJobStream", StringComparison.OrdinalIgnoreCase)) return "inJobStream";
        throw new InvalidOperationException(
            $"pushMode must be 'webhook' or 'inJobStream', got '{raw}'");
    }

    private static int AsInt(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var v)) throw new InvalidOperationException($"missing field: {key}");
        return v switch
        {
            int i => i,
            long l => (int)l,
            JsonElement je when je.ValueKind == JsonValueKind.Number => je.GetInt32(),
            string s when int.TryParse(s, out var p) => p,
            _ => throw new InvalidOperationException($"field {key} is not an int")
        };
    }

    private static string AsString(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var v)) throw new InvalidOperationException($"missing field: {key}");
        return v switch
        {
            string s => s,
            JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString()!,
            _ => throw new InvalidOperationException($"field {key} is not a string")
        };
    }

    // Optional string getter: returns null when the key is absent or not a
    // string, rather than throwing. Used for the security_watch scan-target
    // fields (agentAddress / baseUrl), which are individually optional — the
    // resolver enforces the "at least one, and it resolves to an auditable
    // surface" contract.
    private static string? AsOptionalString(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v is null) return null;
        return v switch
        {
            string s => s,
            JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString(),
            _ => null
        };
    }
}
