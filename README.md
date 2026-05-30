# SecurityBot — ACP 2.0 Subscription Boilerplate

Sibling to ACP_BasicBot. Same two-tier shape (TS sidecar + .NET 10 API + SQLite), plus a worker loop and webhook push delivery for **subscription / recurring offerings**. Clone this folder, rename, and replace the stub `tick_echo` with your real subscription logic.

## When to use this vs ACP_BasicBot

| Bot needs | Start from |
|---|---|
| Only one-shot offerings (request → reply, done) | ACP_BasicBot |
| Any subscription / "watch X" / scheduled push offering | ACP_SecurityBot |
| Both shapes in one bot | ACP_SecurityBot (handles both) |

## Architecture

```
acp-v2/   (Node 22 / TypeScript)            SecurityBot.Api/   (.NET 10)
@virtuals-protocol/acp-node-v2  ──HTTP──►  ADO.NET + SQLite + 2 hosted workers
                                            (TickScheduler + Retry)
                                            +
                                            HTTPS POST + HMAC-SHA256
                                              ─────────────────►  Buyer's webhook
```

## How a subscription works

Two delivery modes are supported. Each subscription offering opts in via `SubscriptionConfig.pushMode`; default is `webhook`.

### `pushMode: "webhook"` (default, battle-tested)

1. Buyer hires a subscription offering (e.g. `tick_echo`) with `{ ticks: 24, intervalSeconds: 3600, webhookUrl, ... }`.
2. Sidecar validates, computes price `pricePerTickUsdc × ticks`, calls `setBudget`.
3. Buyer funds. Sidecar calls `POST /subscriptions` on the C# API.
4. C# inserts a row, generates a 32-byte HMAC secret, returns it.
5. Sidecar `submit()`s a **subscription receipt** containing `subscriptionId` + `webhookSecret`. ACP job done.
6. `TickSchedulerWorker` fires on schedule, computes the tick payload, POSTs to the buyer's webhook with HMAC headers.
7. After N ticks: subscription marked `completed`. Done.

### `pushMode: "inJobStream"` (Phase-1, gated)

1. Buyer hires a subscription offering (e.g. `tick_stream_echo`) with `{ ticks: 5, intervalSeconds: 60, message }` — **no webhookUrl needed**.
2. Sidecar validates, prices, calls `setBudget`.
3. Buyer funds. Sidecar calls `POST /subscriptions` with `pushMode: "inJobStream"` + `streamChainId` + `streamJobId`.
4. C# inserts a row WITHOUT generating an HMAC secret; persists chainId + jobId.
5. Sidecar sends the subscription receipt as an `AgentMessage(contentType="structured")` on the open job and **deliberately does NOT call `submit()`**. The ACP job stays in `TRANSACTION` state.
6. `TickSchedulerWorker` fires on schedule, computes the tick payload, POSTs to the sidecar's internal `/v1/internal/push-tick` (port 6001), which calls `agent.sendMessage(chainId, jobId, payload, "structured")`. Buyer's `AcpAgent.on("entry", handler)` fires.
7. After N ticks: scheduler POSTs to `/v1/internal/submit-final`, sidecar calls `session.submit(finalReceipt)`, ACP job closes.

inJobStream mode is **hard-capped to 4 hours per subscription** (`MaxStreamWindow`) until the Phase-1 SDK verification gate completes — see `docs/superpowers/specs/2026-05-17-pushmode-injobstream-design.md` for the three open questions (Q1 long-lived TRANSACTION tolerance, Q2 slaMinutes upper bound, Q3 SSE reconnect dedup) and the smoke checklist for promotion to production rollout on ChainlinkBot / MEVProtect / etc.

## Local development

Two terminals:

```bash
# Terminal 1 — C# API on http://localhost:5000
cd SecurityBot.Api
dotnet run
```

```bash
# Terminal 2 — ACP sidecar
cd acp-v2
cp .env.example .env       # then fill in agent credentials
npm install
npm run dev
```

For local subscription testing without HTTPS:
```powershell
$env:ALLOW_INSECURE_WEBHOOKS = "true"
```

For local boots without an API key (the API key is required even in
Development by default after audit F1 2026-05-25, so a `dotnet run` against
an unconfigured `.env` boots clean only with the explicit opt-in):
```powershell
$env:SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV = "true"
# AND for the sidecar's streamPush server:
$env:SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH = "true"
```

For local boots without the AES-GCM webhook-secret cipher (the cipher is
required in non-Development; Development is unconstrained by default but
clones whose `ASPNETCORE_ENVIRONMENT` is anything other than `Development`
locally must opt in):
```powershell
$env:SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS = "true"
```

## Security defaults (do not deviate without explicit reason)

- **`SECURITYBOT_API_KEY` is required in any non-Development environment.** The boot will throw `InvalidOperationException` if `ASPNETCORE_ENVIRONMENT != "Development"` and the env var is unset, so a misconfigured droplet deploy can't silently start in fail-open mode. In Development the bot still boots without it (with a loud warning) so local clones work out-of-the-box.
- **`webhookUrl` is SSRF-validated on subscribe + on every delivery tick.** `Services/WebhookUrlValidator.cs` rejects loopback, RFC1918, link-local (incl. the AWS/GCP/Azure metadata IP `169.254.169.254`), IPv6 ULA/link-local, carrier-grade NAT, and any non-`https://` scheme. DNS is resolved at validate-time and every resolved address is checked. Set `ALLOW_INSECURE_WEBHOOKS=true` to bypass — dev/test only.
- **Subscription inputs are bounded** in `SubscriptionService.CreateAsync`: `intervalSeconds` 60..86400, `ticks` 1..10000, total window ≤90 days, `requirementJson` ≤16 KB. Bump constants per-bot only if a specific offering needs different shape.
- **`GET /subscriptions/{id}` returns `SubscriptionView`, not `Subscription`.** The full record holds the HMAC `WebhookSecret` used by buyers to verify tick deliveries — never echo it over an unauthenticated route, or anyone with the subscriptionId can forge ticks.

## Smoke tests

(Same 7 acceptance tests as in `docs/superpowers/specs/2026-05-03-acp-securitybot-boilerplate-design.md`.)

## Wallet delegation guard (EIP-7702)

The sidecar runs a boot-time delegation check before accepting any hires. The
ACP v2 SDK (`acp-node-v2 ^0.0.6`) only recognises wallets delegated to Alchemy
ModularAccountV2 (`0x69007702764179f14F51cdce752f4f775d74E139`). Privy WaaS
occasionally rotates a wallet to a different impl; when that happens, the next
hire fails inside the SDK with `Expected bigint, got: N` from a HexBigInt
typebox encoder that's been fed the wallet's raw integer nonce.

`acp-v2/src/walletDelegation.ts` makes the sidecar self-defending against this:

- **On every boot:** one `eth_getBytecode` call probes the wallet. If the
  delegation prefix (`0xef0100…`) points at ModularAccountV2, the sidecar
  carries on. If not, it either auto-recovers or refuses to start.
- **Auto-recovery (recommended):** set `DEPLOYER_PRIVATE_KEY` in
  `acp-v2/.env`. The guard signs a fresh 7702 authorization via Privy's
  `signer.signAuthorization` and broadcasts a sponsored type-4 tx from the
  deployer EOA. The deployer pays gas (~0.001 ETH per recovery, rare in
  practice). No on-chain tx when delegation is already correct — idempotent.
- **Without a deployer key:** the guard throws on drift with a recovery
  message pointing at `scripts/provision-7702.ts` for a manual one-shot.

`BASE_RPC_URL` in `acp-v2/.env` overrides the public RPC the probe uses
(defaults to publicnode). Even a free RPC is fine — one call per boot.

The guard is wired into `seller.ts` right after `AcpAgent.create(...)`. Do
not remove it. The pattern is shared with ChainlinkBot, where it was
battle-tested through the 2026-05-11 Base mainnet cutover. Especially
important for subscription bots — a wallet drift between subscription
hires would silently break a multi-tick subscription mid-run.

## Cloning for a new bot

1. Copy `ACP_SecurityBot/` → `ACP_MyNewBot/`
2. Find/replace `SecurityBot` → `MyNewBot` (case-sensitive) in: folder, .sln, .csproj, namespaces, package.json `name`, docker-compose service/container names, env var names (`SECURITYBOT_*` → `MYNEWBOT_*`).
3. Provision a new agent on app.virtuals.io, copy creds into `acp-v2/.env`.
4. Replace stub offerings:
   - Delete `tick_echo.ts` (or keep + add your own).
   - Delete `tick_echo_state` table + `TickEchoRepository` if not needed.
   - Add your real subscription offerings to `src/offerings/`, register in `registry.ts`. Every `Offering` carries `slaMinutes` (min 5), `requirementSchema`, `requirementExample`, `deliverableSchema`, and `deliverableExample` — fill all of them from the C# response model (camelCase keys via ASP.NET Core's web defaults). Subscription offerings ALSO declare a `subscription.tiers` list of `{name, priceUsd, durationDays}` (duration in {7, 15, 30, 90} days) which becomes the marketplace registration tier list. For subscription offerings the deliverable shape is the **subscription receipt** returned at hire time, not the per-tick webhook payload.
   - Update `TickExecutorService.cs` to route by your offering names.
   - Update `pricing.ts` and validators if your subscription has different bounds.
5. If you don't need the one-shot path: delete `echo.ts`, `EchoRepository.cs`, `EchoService.cs`, `EchoRecord.cs`, `echo_records` table, `/echo` endpoints, and the `/v1/resources/echoStatus` route + `echoStatus` entry in `src/resources.ts`.
6. Replace the TS resources (optional — delete the example if your bot won't expose any):
   - `acp-v2/src/resources.ts` → your real resources. Resources are public, free, parameterised endpoints buyer / orchestrator agents (Butler etc.) call BEFORE paying for an offering. The example `echoStatus` shows the pattern: declare metadata here, wire the matching `/v1/resources/<name>` handler in `Program.cs`.
   - The X-API-Key middleware in `Program.cs` already whitelists `/v1/resources/*` so resources stay reachable when auth is on.
7. `npm run print-offerings` and register on app.virtuals.io. If you have resources, also run `npm run print-resources` and paste each block into the dashboard's Resources tab.

## What's intentionally NOT in this shell

- Cancellation / refunds (subscription runs to completion)
- EAS attestation per tick (left as `// TODO:` — opt in per bot via the `acp-shared` network into ACP_EASIssuer)
- Pull-fallback delivery and durable buyer-side catch-up for inJobStream (Phase 1 v1 = lost ticks on buyer-side disconnect are silently dropped; defer `gap_fill` resource to v1.1)
- Subscription renewal (buyer hires again)
- Multi-replica / leader election (single replica per bot)
- `sendJobMessage` (transport push, fire-and-forget) for streams — Phase 1 uses the awaitable REST fallback `sendMessage` for delivery confidence; switch per-offering in Phase 2+ if sub-second latency matters

## Security

Webhook scheme: HTTPS only (override `ALLOW_INSECURE_WEBHOOKS=true` for dev — refused in non-Development). HMAC-SHA256 signature header `X-Subscription-Signature`. Webhook secret returned **once** in the receipt deliverable — buyer must persist.

### Buyer-side webhook verification checklist (REQUIRED)

Every tick the bot delivers carries four headers:

| Header | Purpose |
|---|---|
| `X-Subscription-Id` | Subscription identity (same value for every tick on this subscription) |
| `X-Subscription-Tick` | Tick number — monotonic per subscription starting at 1 |
| `X-Subscription-Timestamp` | Unix seconds at the moment the signature was computed |
| `X-Subscription-Signature` | `sha256=` + HMAC-SHA256(`webhookSecret`, `subscriptionId + "." + tick + "." + timestamp + "." + body`) |

> Audit F4 (2026-05-25): the canonical now binds `subscriptionId` so a captured
> tuple from subscription A cannot be replayed as a fake delivery to
> subscription B. The pre-F4 canonical was `tick.timestamp.body` (no subId);
> clones that pinned the legacy signature must update receiver code before
> upgrading. `ComputeSignature(secret, tick, timestamp, body)` is retained as
> an `[Obsolete]` overload for transitional compat.

Buyers MUST do ALL of the following to be safe against replay:

1. **Verify the HMAC.** Recompute the canonical as `${X-Subscription-Id}.${X-Subscription-Tick}.${X-Subscription-Timestamp}.${rawBody}` and constant-time-compare. Reject mismatches.
2. **Verify timestamp freshness** — reject if `abs(now_unix_sec - X-Subscription-Timestamp) > 300` (±5 minutes). The bot's `WebhookDeliveryService` sets the timestamp at signature time; legitimate ticks always arrive inside a small window. Without this check, an attacker who captures a single delivered request can replay it indefinitely (the HMAC alone has no expiry).
3. **Deduplicate by `(subscriptionId, tick)`** — accept the first delivery per tuple and respond 200; respond 200 (no-op) to all subsequent identical deliveries. The bot retries on transient failures, so a buyer hard-throwing on duplicate ticks would cause spurious retry storms.
4. (Optional but recommended) **Enforce monotonic ticks** — reject any tick < `max_seen_tick - 1`. Combined with #3 this catches both replay and re-ordering.

Reference verifier (Node, dependency-free):

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verifyDelivery(headers: Record<string,string>, rawBody: string, secret: string): boolean {
  const subId = headers["x-subscription-id"];
  const tick  = headers["x-subscription-tick"];
  const ts    = headers["x-subscription-timestamp"];
  const sig   = headers["x-subscription-signature"];
  if (!subId || !tick || !ts || !sig) return false;

  // 1. Freshness — 5-minute window
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number.parseInt(ts, 10)) > 300) return false;

  // 2. HMAC
  const canonical = `${subId}.${tick}.${ts}.${rawBody}`;
  const expected = "sha256=" + createHmac("sha256", secret).update(canonical).digest("hex");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
  // 3. (caller) idempotency by (subId, tick).
}
```

Audit F11 (2026-05-25): the bot sends the timestamp; buyer-side enforcement is the buyer's responsibility.

### Server-side defences (already wired)

- `WebhookUrlValidator` rejects loopback, RFC1918, link-local + metadata `169.254/16`, CGNAT, IPv6 ULA/link-local, and any non-`https://` scheme on subscribe AND every delivery tick.
- `WebhookDeliveryService`'s `HttpClient` is configured with `SocketsHttpHandler.ConnectCallback = WebhookConnectCallbacks.PinValidatedIp` (audit F1, 2026-05-25) — every TCP connect re-resolves and re-validates the IP, closing the DNS-rebind TOCTOU between validate-time and connect-time. Paired with `AllowAutoRedirect=false` so a 302 Location can't redirect a validated public webhook to a metadata/private IP.
- `RateLimitMiddleware` (audit F9, 2026-05-25) — 60 req/min/IP + 600 req/min/key on heavy endpoints, placed before auth so unauthenticated floods are also throttled.
- Baseline security headers on every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`, plus `Cache-Control: no-store` on everything except `/health` and `/v1/resources/*`.
- `GET /subscriptions/{id}` returns `SubscriptionView.Minimal` by default; the full projection (with buyer-identifying fields) requires `X-Subscription-Secret: <webhookSecret>` as proof of ownership (audit F5, 2026-05-25). `WebhookSecret` itself is NEVER echoed.
- `streamPush` (sidecar internal HTTP server) binds `127.0.0.1` by default (audit F2, 2026-05-25). The Docker compose deploy sets `SECURITYBOT_STREAM_PUSH_BIND_HOST=0.0.0.0` so the API container can reach it across the docker bridge; the bridge is the trust boundary. Never publish the stream-push port to the host.
- `streamPush` REFUSES to start without `SECURITYBOT_API_KEY` (audit F6, 2026-05-25). The previous behaviour was "auth-required-when-set, silent-unauth-otherwise", which regressed to unauthenticated whenever the env var was forgotten. Now an operator who genuinely wants unauth (local dev where the C# tier is also unauthenticated) opts in by name via `SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH=true`.
- `streamPush` also runs its own per-remote-address sliding-window rate limit (audit F8, 2026-05-25) — 60 req/min default; override via `SECURITYBOT_STREAM_PUSH_RATE_LIMIT`. Independent from the C# tier's `RateLimitMiddleware`; defends against a runaway loop in `InJobStreamDeliveryService` and against any caller that reaches the docker bridge IP.
- `WebhookSecretCipher` (AES-256-GCM at rest) wraps `webhook_secret` on Insert and unwraps on Read (audit F3, 2026-05-25). Required by default in non-Development — `Program.cs` fails fast at boot unless `WEBHOOK_SECRET_ENCRYPTION_KEY` is set (32 random bytes, base64), or the operator explicitly opts into plaintext via `SECURITYBOT_ALLOW_PLAINTEXT_WEBHOOK_SECRETS=true` (transitional only — emits a loud boot warning). Generate the key with `openssl rand -base64 32`. Migration is lazy: rows that pre-date the cipher decode as-is until their next write.
- `X-Forwarded-For` / `X-Forwarded-Proto` are trusted ONLY from CIDRs in `TRUSTED_PROXY_NETWORKS` (default `172.16.0.0/12,127.0.0.0/8,::1/128`; audit F5, 2026-05-25). On the droplet, tighten to the exact Caddy bridge CIDR. Without this, every external caller behind a reverse proxy shared one rate-limit bucket keyed by the proxy IP.
- Field length caps in `SubscriptionService.CreateAsync` (audit F9, 2026-05-25): `jobId ≤128`, `buyerAgent ≤256`, `offeringName ≤64`, `streamJobId ≤128`, `webhookUrl ≤2048`. Defence in depth on top of the 256 KB Kestrel body cap and the 16 KB `requirement_json` cap.
- `WebhookUrlValidator` blocklist extended (audit F7, 2026-05-25) with four additional IANA special-use ranges: IPv4 `192.0.0.0/24` (IETF protocol assignments) + `192.88.99.0/24` (6to4 anycast, deprecated), IPv6 `2002::/16` (6to4) + `2001::/32` (Teredo). These don't appear in typical Docker networks but the audit's recommendation was an allowlist rather than a blocklist; until clones move to an allowlist these closes the highest-likelihood gaps.

### Deployment notes

- **Kestrel listens HTTP-only on the docker bridge** (`ASPNETCORE_URLS=http://+:5000`) and Caddy terminates TLS at the public edge. There is no app-layer `UseHttpsRedirection` / HSTS — that would be a no-op on a process whose only listener is HTTP on a private bridge. The audit's Low #11 noted this is acceptable when a trusted reverse proxy is always in front; if you ever expose Kestrel directly (e.g. in a flat-network single-VM deploy), wire `UseHttpsRedirection` + HSTS + bind to `https://+:443` with a real cert before opening the port.
- **`webhook_secret` encryption key rotation:** the cipher uses a single global `WEBHOOK_SECRET_ENCRYPTION_KEY`; rotation requires decrypting every existing row with the old key and re-encrypting with the new one in a one-shot script (the bot itself doesn't run a migration worker). Plan rotation cadence per-bot.

See `docs/superpowers/specs/2026-05-03-acp-securitybot-boilerplate-design.md` for full design.
