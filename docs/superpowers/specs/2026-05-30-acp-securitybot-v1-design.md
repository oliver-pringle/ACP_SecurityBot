# ACP_SecurityBot v1 - Design Spec

**Date:** 2026-05-30
**Status:** Approved design (pre-implementation)
**Boilerplate:** clone of `ACP_BasicSubscriptionBot`
**Portfolio slot:** 14th bot; MetaMask Wallet 3 (1/5 used by WitnessBot - room available)

---

## 1. Purpose & business model

SecurityBot is a marketplace seller that performs a **dynamic, passive, deterministic
security audit** of a third-party ACP agent's live HTTP surface and returns per-finding
verdicts scored against the portfolio's own P1-P39 + B1-B9 pattern catalogue
(`security-audit/SecurityBot/KnownBugs.md`).

**Target:** third-party ACP agents (they run their own public hosts, so the full passive
check-set genuinely applies - unlike our gateway-only portfolio bots).

**Distribution thesis (R15):** V2 marketplace demand is the bottleneck (239 new agents in
30 days, ~0 recorded V2 hires). Every Virtuals agent has a stable `@agents.world` email
(set in the Identity tab). SecurityBot can deliver a report directly to an audited agent's
inbox - bypassing marketplace discovery. v1 ships email as an **opt-in delivery channel**;
a **proactive-outreach funnel** (cold teaser emails that drive paid hires) is designed-for
but ships **default-OFF**, to be turned on once the engine + email plumbing are proven.

**Engine stance:** deterministic rule engine, **no Claude in the hot path** - zero per-call
LLM cost, fully reproducible verdicts, no prompt-injection surface, defensible findings.
The pattern catalogue itself is the moat (the differentiator vs generic Solidity auditors).

---

## 2. Architecture

Standard portfolio two-tier, cloned from `ACP_BasicSubscriptionBot` into `ACP_SecurityBot\`.

```
ACP_SecurityBot\
  SecurityBot.Api\                 # C# .NET 10 - scan engine + verdicts + persistence
    Program.cs                     # endpoints, middleware, boot guards (P1/P3/P31...)
    Endpoints\                     # ScanEndpoints, ResourceEndpoints, SubscriptionEndpoints
    Engine\
      DynamicAuditEngine.cs        # orchestrates one scan: probe-once -> run all checks -> aggregate
      IProbeCheck.cs               # one check = one externally-observable pattern
      Checks\                      # 8 check files (see section 4)
      ProbeClient.cs               # the ONE hardened outbound HttpClient (safety chokepoint)
      Verdict.cs                   # Finding / Verdict / Severity / Evidence records
    Resolution\
      ITargetResolver.cs
      MarketplaceTargetResolver.cs # agentAddress -> V2 marketplace Resource URLs -> base host
    Email\
      IEmailSender.cs              # abstracted; backend chosen by a research spike
      NoopEmailSender.cs           # v1 default until backend wired
    Services\                      # PatternCatalogue, ScoreCalculator, ScanRepository,
                                   #   SubscriptionService, WatchWorker, WebhookDeliveryService,
                                   #   WebhookSecretCipher, WebhookUrlValidator, InternalUrlValidator,
                                   #   BackupWorker, RateLimitMiddleware (all lifted/standard)
    Data\Db.cs                     # SQLite schema
  acp-v2\                          # Node 22 TS sidecar (ACP protocol)
    src\offerings\                 # security_scan.ts, security_watch.ts
    src\resources.ts               # patternCatalogue, auditByAgent
  docker-compose.yml               # securitybot-api + securitybot-acp
  data\                            # SQLite bind-mount
```

**Two rules that shape everything:**

1. **One `ProbeClient`** is the only component that touches a target. Every check borrows it.
   It is the single chokepoint for all safety guarantees (no-redirect, connect-time IP pin,
   per-target request budget, timeouts, `ResponseHeadersRead` + body cap). This is where we
   apply P39/P2/P21 to ourselves while auditing others.

2. **Checks are a registry of independent `IProbeCheck` units**, each mapping 1:1 to a
   catalogue pattern. A check knows nothing about the others; it consumes the shared probe
   results and returns a `Finding`. Adding a pattern = adding one file + one test.

The C# API publishes **no host ports** (sidecar-only on the docker bridge); only
`/v1/resources/*` is exposed, via the shared Caddy gateway at
`api.acp-metabot.dev/securitybot/v1/resources/*`.

---

## 3. Scan engine

```csharp
public interface IProbeCheck {
    string PatternId { get; }          // "P31", "P9", ...
    string Title { get; }
    Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct);
}
```

`DynamicAuditEngine.ScanAsync(target)`:
1. Resolve the target (section 5) -> base URL or `NOT_AUDITABLE`.
2. **Probe once.** Fetch a small fixed set of responses via the shared `ProbeClient`:
   `GET /health`, an `OPTIONS`, each advertised Resource, one paid `/v1/*` path
   unauthenticated, one deliberately-malformed GET. Store them in `ProbeContext`. Every
   check reads from this context - we never exceed the per-target request budget.
3. Run all registered `IProbeCheck`s over the shared context.
4. Aggregate into `findings[]`, compute `score` (section 7), persist, build the deliverable.

`Finding` record:
```
patternId : "P31" | "P9" | ...
title     : human label
severity  : Critical | High | Medium | Low | Info   (from the catalogue, never invented)
verdict   : PRESENT | PARTIAL | PASS | NOT_OBSERVABLE | NOT_APPLICABLE
evidence  : the literal header/status/body-snippet that proves it (truncated, sanitized)
fixRef    : pattern id pointing into the catalogue's canonical fix
```

`NOT_OBSERVABLE` is a **first-class verdict** - honest about a dynamic audit's limits. When
a paid `/v1/*` surface is not publicly reachable, the auth/error checks report
`NOT_OBSERVABLE` rather than guessing. The report states "we could verify N of 48 patterns
externally", which is itself honest signal and the natural upsell to a future static tier.

---

## 4. v1 check set (8 checks)

Only the externally-observable subset ships in v1. Each is one small file + a unit test
against canned fixtures (no network in tests).

| Check | Pattern | What it observes |
|---|---|---|
| `SecurityHeadersCheck` | P31 | Missing `X-Frame-Options` / CSP / `nosniff` / `Referrer-Policy` across responses |
| `ResourceDisclosureCheck` | P9 | Resource bodies leaking operator EOAs, RPC URLs with keys, subscription IDs |
| `RawDumpCheck` | P10 | Resource/dump endpoints returning raw stored JSON instead of a typed shape |
| `AuthPostureCheck` | P1 / P18 | A paid `/v1/*` path answering 200 instead of 401 without a key (else `NOT_OBSERVABLE`) |
| `ErrorLeakCheck` | P30 | One malformed GET -> does the response echo `ex.Message` / stack / internal host |
| `SchemaDescriptionCheck` | P32 | Resource `paramsSchema` properties missing `description` |
| `TlsTransportCheck` | P31-adjacent | `http://` reachable when https expected; HSTS presence at the edge |
| `RateLimitHintCheck` | P15 / P19 | Bounded: at most `MaxRateLimitProbes = 5` cheap GETs ~150ms apart, abort on first 429 |

**`RateLimitHintCheck` is the only check that sends more than one request to a single path.**
It is hard-bounded (max 5, single cheap GET, early-abort on 429) and counts against the
per-target request budget. Every other check reads from the probe-once context.

Patterns that require source access or the private surface (P5/P6/P33-P39, B-series, etc.)
are present in the catalogue but report `NOT_OBSERVABLE` in a dynamic audit.

---

## 5. Target resolution

Input `{ agentAddress?, baseUrl? }`, at least one required.

- **`baseUrl` given** -> validate (section 6 SSRF rules) and use directly.
- **only `agentAddress`** -> query the V2 marketplace (`api.acp.virtuals.io`, the same source
  Metabot's `AcpV2MarketplaceSource` uses) for that agent's registered Resource records; take
  their `url` fields; derive the common scheme+host as the base. A small focused client -
  **not** the full Metabot indexer; **no runtime coupling on Metabot.** (Confirmed via
  Metabot's `agent_resources` table, which mirrors a per-resource `url` field populated from
  the V2 source - so resolution is real, not hypothetical.)
- **neither resolves to a reachable, allowed host** -> return a clean `NOT_AUDITABLE` verdict
  (a normal paid deliverable, not an error): "this agent exposes no externally-auditable
  surface". The buyer still gets a defensible result.

`resolvedVia` (`'baseUrl'` | `'marketplace'`) is recorded on the scan and surfaced in the
deliverable.

---

## 6. ProbeClient safety model (audit ourselves while auditing others)

The ProbeClient is the single hardened outbound client every check borrows. A
buyer-or-marketplace-supplied URL is **untrusted input pointing at an arbitrary host** -
exactly the attack surface we flag in everyone else (P2/P39). The bot whose whole job is
pointing HTTP at attacker-influenced hosts must be the **most-hardened outbound client in
the portfolio**.

- **SSRF guard (inverse pin - block everything private).** `SocketsHttpHandler` with
  `AllowAutoRedirect=false` + a connect-time IP pin that **BLOCKS** loopback / RFC1918 /
  link-local / CGNAT / cloud-metadata (`169.254.169.254`) / multicast / reserved and the
  full RFC6890 + IPv6 block-set from P2 (`::`, `2001:db8::/32`, `64:ff9b::/96` NAT64,
  `2002::/16` 6to4, `2001::/32` Teredo). A target resolving to a private/metadata address is
  **refused** -> the scan returns `NOT_AUDITABLE` with reason. SecurityBot can never be turned
  into an SSRF proxy. (This is the deliberate inverse of the internal `PinInternalIp` used by
  cross-bot lanes, which *allows* private docker hosts.)
- **Per-target request budget** - hard cap (`MaxRequestsPerScan = 25`) so a scan can never
  become a flood; `HttpCompletionOption.ResponseHeadersRead` + 256 KB response-body cap so a
  hostile target cannot memory-exhaust us; per-request timeout (~8s) + total-scan deadline (~60s).
- **Honest UA, no writes** - identifies as `ACP-SecurityBot/1.0 (passive-audit)`; GET / OPTIONS /
  HEAD only; never POSTs anything that could mutate target state. The one malformed request for
  `ErrorLeakCheck` is a GET with a deliberately-bad path/param, never a write.

**Tradeoff accepted:** a bot reachable only on a private address cannot be dynamically scanned
(returns `NOT_AUDITABLE`). That is the correct safety posture; a future static-repo tier would
cover those.

---

## 7. Scoring

`ScoreCalculator` produces a deterministic 0-100 score + letter grade from **observable
findings only**, severity-weighted, with the denominator = the count of checks that produced
an observable verdict (PRESENT/PARTIAL/PASS). A bot is never punished for what we could not
see (`NOT_OBSERVABLE` / `NOT_APPLICABLE` are excluded from the denominator). The formula is
fixed and documented; the same target + same `corpus_version` always yields the same score.

---

## 8. Data model (SQLite, extends BasicSubscriptionBot)

```
scans
  id, agent_address (nullable), base_url, resolved_via ('baseUrl'|'marketplace'),
  score, grade, observable_count, finding_count, verdict ('AUDITED'|'NOT_AUDITABLE'),
  corpus_version, scanned_at

scan_findings
  id, scan_id FK, pattern_id, severity, verdict, evidence_json, fix_ref

subscriptions            -- (from BSB) watch tier
  id, agent_address/base_url, cadence, window_start, window_end, webhook_url,
  webhook_secret (ciphered via WebhookSecretCipher), email_opt_in, last_score,
  last_finding_hash, status, ...

subscription_runs        -- (from BSB) per-tick idempotency: UNIQUE(subscription_id, tick_number)

email_log                -- audit trail of every email send (to, scan_id, sent_at, status)
                            + anti-abuse dedupe ledger (one report per agent per window)
```

Findings are stored as **typed rows**, never raw JSON blobs served back verbatim (so we do
not flunk our own P10). The public `auditByAgent` Resource reads aggregate counts only.

---

## 9. Offerings & deliverable contracts

Request for `security_scan`: `{ agentAddress?, baseUrl?, emailReport?: bool }` (at least one
of address/url required). Every requirement/deliverable schema property carries a
`description` (P32 self-application).

| Offering | Price | Internal endpoint | Deliverable shape (buyer contract) |
|---|---|---|---|
| `security_scan` | $1.00 | `POST /v1/internal/scan` | `{ agentAddress, baseUrl, resolvedVia, scannedAt, score, grade, observableCount, totalPatterns, findings[], summary, _emailDelivery? }`; each finding `{ patternId, title, severity, verdict, evidence, fixRef }` |
| `security_watch` | $3/30d (tiers `weekly_1` $1/7d, `monthly_3` $3/30d, `quarterly_9` $9/90d) | `POST /v1/internal/watch/bind` | BSB receipt: `{ subscriptionId, webhookSecret (once), cadence, windowEnd, signatureScheme }`; ticks push a diff (newly-opened / newly-closed findings) over HMAC webhook + optional email |

`emailReport` opt-in triggers `IEmailSender` to the agent's `@agents.world` address; the
deliverable's `_emailDelivery` field reports `sent | skipped | no_backend | failed` so it is
never silently dropped.

**Free Resources** (gateway-proxied at `api.acp-metabot.dev/securitybot/v1/resources/*`):

- `patternCatalogue` - the full P1-P39 + B1-B9 JSON (severity, detection, canonical fix,
  reference bot). The moat; free recon that drives scan hires.
- `auditByAgent` - most-recent scan summary for an `agentAddress` (score + per-severity counts
  + `scannedAt`). No raw evidence, no URLs (P9/P10 self-application).

---

## 10. Email & subscription worker

**`IEmailSender`:**
```csharp
public interface IEmailSender {
    Task<EmailResult> SendScanReportAsync(string toAgentEmail, ScanReport report, CancellationToken ct);
}
```
- v1 default binding = `NoopEmailSender` -> returns `no_backend`, logs to `email_log`; the scan
  still succeeds. **Implementation task #1 is a research spike** to determine the real send
  mechanism (Virtuals agent-email API / SMTP / other) and write the concrete sender. Until
  then the bot is fully functional minus actual send.
- The `@agents.world` address comes from the agent's marketplace identity (or buyer-supplied).
  `emailReport` is opt-in per scan.
- **Anti-abuse from day one (even though outreach is OFF):** `email_log` doubles as the dedupe
  ledger (one report per agent per window); every email carries an opt-out line; a global daily
  send cap applies. The proactive-outreach worker is designed-for but ships **default-OFF**
  behind `SECURITYBOT_OUTREACH_ENABLED=false` - v1 never cold-emails the marketplace.

**`WatchWorker` (lifted from BasicSubscriptionBot):** tick cadence -> re-resolve + re-scan ->
diff vs `last_finding_hash` -> on newly-opened findings, deliver over HMAC webhook
(`subscriptionId.tick.timestamp.body` scheme) + optional email. Carries the full standardized
BSB hardening: atomic claim `TryClaimDueAsync` (P36), `UNIQUE(subscription_id, tick_number)`
idempotency, `WebhookSecretCipher` AES-256-GCM at rest (P5), webhook SSRF validator +
connect-pin (P2/P39), `ResponseHeadersRead` (P4).

---

## 11. Security self-application (SecurityBot must pass its own audit)

Non-negotiable for credibility. The new-bot checklist (P1-P39) is a build gate:

- P1 fail-closed `INTERNAL_API_KEY` + `ALLOW_UNAUTHENTICATED_DEV` opt-in; 32-char floor.
- P18 paid endpoints at `/v1/internal/*`; only `/health` + `/v1/resources/*` public.
- P31 security headers; P3 trusted-proxy; P30 stable error codes (never `ex.Message`).
- ProbeClient covers P2/P21/P39 outbound; `WebhookUrlValidator` + `InternalUrlValidator` pair
  for webhook/email lanes; P5 webhook-secret cipher; P15 rate-limit dict cap on its own API.
- P22 `.env` gitignored (only `.env.example` committed); P14 pinned SQLite path; P6 BackupWorker.
- A dogfood test asserts SecurityBot scores 100/observable against itself.

---

## 12. Testing, rollout & provisioning

**Tests (~40-50):**
- Each `IProbeCheck` unit-tested against canned `ProbeContext` fixtures (no network).
- `ScoreCalculator` determinism tests.
- `MarketplaceTargetResolver` against a mocked V2 response incl. the `NOT_AUDITABLE` path.
- SSRF-block tests (private / metadata / loopback / RFC6890 targets all refused).
- Subscription idempotency + webhook HMAC tests.
- Dogfood self-scan test (100/observable).

**Build gate:** `dotnet build` 0-warn; `dotnet test` green; `npm run build` clean;
`npm run print-offerings` renders within the 20-char name / 500-char description caps.

**Rollout:**
- Deploy as the 14th bot (`securitybot-api` + `securitybot-acp`); add the `/securitybot/*`
  Caddy `handle_path` block before the metabot catch-all; restart `acp-metabot-caddy`.
- First-hire smoke via ACP_Tester scanning a portfolio bot's public host (e.g. ChainlinkBot)
  to prove buy -> resolve -> scan -> deliver end-to-end.

**Provisioning (interactive, Oliver):** create the agent on app.virtuals.io under MetaMask
**Wallet 3** (1/5 used; room available); copy signer creds into `acp-v2/.env`; run
`npm run print-offerings`; paste offerings + Resources into the dashboard. (Claude prepares
print output; cannot do the interactive steps.)

---

## 13. Explicitly deferred (not in v1)

- Proactive-outreach worker turn-on (cold teaser emails) - designed-for, default-OFF.
- Static-repo-scan tier covering the P33-P39 / B-series patterns that need source access.
- `security_attestation` cross-bot to EASIssuer (publish a `security_attested` EAS UID).
- `security_recheck` one-shot diff (the subscription already covers recurring diffs).
- LLM-written narrative / executive-summary tier.

---

## 14. Key decisions log (from brainstorming)

- Audit target = **dynamic live-URL** (works on any deployed bot, no repo access, deterministic).
- Probe depth = **passive + safe handshakes** (ethical to run against a third party's live bot).
- Engine = **deterministic rule engine** (no Claude in hot path; catalogue is the moat).
- Boilerplate = **BasicSubscriptionBot** (subscription watch tier is a first-class v1 feature).
- Target = **third-party ACP agents** (they run public hosts; full passive set applies).
- Target input = **agentAddress + optional baseUrl**, auto-discover via V2 marketplace.
- Email = **opt-in delivery now, proactive outreach designed-for but default-OFF**.
- Email send mechanism = **unknown -> abstracted behind `IEmailSender`, research spike is task #1**.
- v1 offerings = **security_scan ($1) + security_watch ($3/30d) + 2 free Resources**.
- Approach = **A** (self-contained resolver, deterministic engine, email abstracted; zero
  runtime coupling on Metabot).
