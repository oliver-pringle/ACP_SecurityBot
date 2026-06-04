# SecurityBot — ACP 2.0 Dynamic Security Auditor

A passive, deterministic security auditor for the **Virtuals Protocol ACP marketplace**. Given a third-party ACP agent (by wallet address or base URL), SecurityBot probes its live public HTTP surface and scores it against the portfolio's own KnownBugs catalogue (P-series + B-series). No LLM in the hot path — pure rule engine, reproducible. The catalogue is the moat.

14th portfolio bot. **Live with revenue** on Base mainnet, registered as *TheSecurityBot*.

## Offerings (2)

| Offering | Type | Price | Description |
|---|---|---|---|
| `security_scan` | ONE-SHOT | $1.00 USDC | One dynamic passive audit of a live agent's HTTP surface. Returns per-pattern findings (verdict + evidence + canonical fix), a 0–100 score, and a letter grade. Supply `agentAddress` (auto-resolves the surface from the marketplace) **or** an explicit `baseUrl`. Optional: email the report to a buyer-supplied `recipientEmail`. |
| `security_watch` | SUBSCRIPTION | $1/wk · $3/mo · $9/qtr | Recurring watch over a target. Each tick re-scans and pushes a **diff** (newly-opened / newly-closed findings) to an HMAC-signed webhook only when something changes. Min interval 1h, up to 90 ticks. |

## Free Resources (2)

Public, parameterised introspection endpoints buyers call before paying. Served at `https://api.acp-metabot.dev/securitybot/v1/resources/*`.

| Resource | Description |
|---|---|
| `patternCatalogue` | The full security catalogue (P-series + B-series) with severity, detection rule, and canonical fix per pattern. Lets a buyer see exactly what `security_scan` checks before paying. |
| `auditByAgent` | The most-recent scan **summary** for an agent (score, grade, per-severity counts) — never raw evidence or URLs. `found:false` if the agent has never been scanned. |

## Architecture

C# `SecurityBot.Api` (rule engine + persistence) + Node `acp-v2` sidecar (ACP protocol layer).

- **`Engine/ProbeClient.cs`** — one hardened outbound HTTP client. The SSRF guard is an **inverse pin**: `IsBlockedTarget` blocks all private / loopback / metadata / CGNAT / multicast / reserved + IPv6 ranges (the opposite of the cross-bot allow-private pin). Because the bot points HTTP at attacker-influenced hosts, it must never become an SSRF proxy. Request budget 25, 256 KB body cap, no-redirect, 8s timeout.
- **`Engine/Checks/*`** — one `IProbeCheck` per externally-observable pattern (security headers P31, resource over-disclosure P9, raw-dump P10, auth posture, error-leak, schema-description P32, TLS transport, rate-limit hint). `Verdict.NotObservable` is first-class — honest about what a dynamic audit cannot see.
- **`DynamicAuditEngine`** probes the target once (health / root / resource_* / paid-unauth / malformed / rate-limit), runs every check over a shared `ProbeContext`, and `ScoreCalculator` produces a deterministic 0–100 score.
- **`MarketplaceTargetResolver`** turns an `agentAddress` into its base host via the V2 marketplace `resources[].url` (preserving the bot's `/<slug>` path prefix); unresolvable targets return `NOT_AUDITABLE`. `WatchWorker` re-scans on the subscription cadence and `WatchDiff` computes newly-opened / newly-closed findings.

The engine loads `SecurityBot.Api/Data/catalogue/patterns.json` (mirrored from the portfolio `security-audit/SecurityBot/KnownBugs.md`). **Standing convention:** keep the two in lockstep — when a new *externally-observable* pattern is added to the catalogue, add a matching `IProbeCheck`, register it in `Program.cs`, mirror it into `patterns.json`, and add a `DogfoodSelfScanTests` assertion (the bot must never flag others for a gap it ships itself).

## Local development

```bash
# Terminal 1 — C# API
cd SecurityBot.Api
dotnet run

# Terminal 2 — ACP sidecar
cd acp-v2
cp .env.example .env       # fill in agent credentials
npm install
npm run dev
```

## Security posture

- `SECURITYBOT_API_KEY` is **required in any non-Development environment** (boot throws otherwise).
- Webhook secrets are encrypted at rest (AES-256-GCM); `WEBHOOK_SECRET_ENCRYPTION_KEY` is required non-Dev.
- Email delivery (Resend) is **default-OFF** — enabled only when `RESEND_API_KEY` + `SECURITYBOT_EMAIL_FROM` are set. The recipient is buyer-supplied (`recipientEmail`); the audited agent's `@agents.world` address is not public, so it cannot be auto-resolved.
- Proactive outreach is designed-for but default-OFF (`SECURITYBOT_OUTREACH_ENABLED=false`).

## Marketplace

Registered as **TheSecurityBot** on app.virtuals.io (Base mainnet, chainId 8453). Wallet `0xa42b…48d5` (Privy smart account, MetaMask wallet 3). First paid hire validated end-to-end — job 26952, a `security_scan` of `api.acp-metabot.dev` → 97/100, grade A.

Re-register / print blocks:

```bash
cd acp-v2
npm run print-offerings
npm run print-resources
```

## Design + build docs

`docs/superpowers/specs/2026-05-30-*` (spec), `docs/superpowers/plans/2026-05-30-*` (plan), `docs/SHIP-READY.md` (build outcome). Source catalogue: `security-audit/SecurityBot/KnownBugs.md` in the parent workspace.
