# ACP_SecurityBot v1 - SHIP-READY (2026-05-30)

Status: **v1 code-complete + local-smoke verified. Pending: email research spike, droplet deploy, marketplace registration.**

Built via the implementation plan `docs/superpowers/plans/2026-05-30-acp-securitybot-v1.md`
(15 tasks, subagent-driven TDD). Own git repo on `master`; no remote yet.

## What works (verified)

- **215/215 C# tests pass; sidecar `tsc` clean; C# build 0 warnings / 0 errors.**
- Deterministic 8-check passive auditor (P31 headers, P9 disclosure, P10 raw-dump,
  P1/P18 auth posture, P30 error-leak, P32 schema-descriptions, P31-TLS transport,
  P15/P19 bounded rate-limit hint) against a 49-entry pattern catalogue.
- `POST /v1/internal/scan` (X-API-Key gated): resolve target -> probe once -> run
  checks -> deterministic 0-100 score -> persist -> deliverable JSON. `_emailDelivery`
  only when `emailReport=true`. NOT_AUDITABLE is a normal 200 deliverable.
- Free public Resources: `/v1/resources/patternCatalogue` (49 entries) and
  `/v1/resources/auditByAgent` (summary only - never raw evidence or URLs, P9/P10).
- `security_watch` subscription tier: re-scan + diff (newly-opened/closed findings),
  HMAC webhook delivery only on change.
- Sidecar offerings render within marketplace caps: `security_scan` ($1 one-shot),
  `security_watch` ($1/wk, $3/mo, $9/qtr tiers). Every schema property has a
  `description` (P32).

## Local smoke results (2026-05-30)

- Boot clean: WatchWorker + RetryWorker + BackupWorker start; schema init; listening.
- `/health` 200; `patternCatalogue` returns 49 patterns (P1..B9, corpus 2026-05-30);
  `auditByAgent` returns `{found:false}` for an unscanned agent with no evidence/URL leak.
- **Real end-to-end scan** against the live `https://api.acp-metabot.dev` gateway:
  verdict AUDITED, score 97/100 grade A, 5 patterns observable, honest NotObservable
  for the 3 that need resource bodies the gateway did not expose.
- **SSRF guard proven:** a scan targeting `localhost`/`127.0.0.1` made ZERO connections
  to the bot (0 probe-path hits in its own request log) - the ProbeClient connect-time
  IP block refused every private/metadata target. An `https://10.0.0.1` scan returned
  all-NotObservable (nothing reached). SecurityBot cannot be used as an SSRF proxy.

## Security self-application (dogfood)

`DogfoodSelfScanTests` asserts SecurityBot scores 100 on its own expected response
shape (no Present findings). Building it caught a REAL bug: `SecurityHeadersCheck`
was inspecting the engine's synthetic `ratelimit_probe` response (empty headers) and
would have false-flagged P31 on every scan of every target - now excluded. P1 fail-
closed auth, P5 webhook-secret cipher, P31 headers, P3 trusted-proxy, P30 stable error
codes, P15 rate-limit, P22 .env gitignored, P6 BackupWorker - all present.

## Before "Live with revenue" (out of v1 scope - tracked)

1. **Email research spike (FIRST follow-up):** determine how a Virtuals @agents.world
   mailbox sends mail (agent-email API vs SMTP), implement a real `IEmailSender` to
   replace `NoopEmailSender`. Until then scans report `_emailDelivery: "no_backend"`.
2. **Confirm V2 marketplace `resources[].url` shape:** `MarketplaceResourceFetcher`
   is a best-effort GET against `api.acp.virtuals.io/api/agents/{addr}` wrapped to
   return empty (-> NOT_AUDITABLE) on any unexpected shape. Confirm the real JSON
   shape and tighten the parse. (Resolver logic itself is unit-tested.)
3. **Droplet deploy:** new repo needs a GitHub remote + clone to the droplet;
   `securitybot-api` + `securitybot-acp` containers; the `/securitybot/*` Caddy
   handle_path block (before the metabot catch-all) + `docker restart acp-metabot-caddy`.
   The `acp-shared` + `caddy_proxy` external networks must exist on the droplet first.
   Set `SECURITYBOT_API_KEY` + `WEBHOOK_SECRET_ENCRYPTION_KEY` in env (P1/P5 fail-closed).
4. **Agent provisioning (interactive, Oliver):** create the agent on app.virtuals.io
   under MetaMask Wallet 3 (room available); copy signer creds into `acp-v2/.env`;
   `npm run print-offerings` + `print-resources`; paste into the dashboard.
5. **First-hire smoke** via ACP_Tester once live.

## Deferred to v1.x

- Real proactive-outreach worker (cold @agents.world teaser emails) - designed-for,
  ships default-OFF behind `SECURITYBOT_OUTREACH_ENABLED=false`.
- Static-repo-scan tier (the P33-P39 / B-series patterns that need source access).
- `security_attestation` cross-bot to EASIssuer; `security_recheck`; LLM narrative tier.
- Minor UX: a private/unreachable post-resolution target currently returns AUDITED with
  everything NotObservable; could return NOT_AUDITABLE for a cleaner buyer signal.
