import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { Buffer } from "node:buffer";
import type { AcpAgent } from "@virtuals-protocol/acp-node-v2";

// Internal HTTP server for the inJobStream PushMode. The C# tier
// (InJobStreamDeliveryService) POSTs each tick payload here, and this server
// translates the call into an SDK message on the kept-open ACP job:
//
//   POST /v1/internal/push-tick     -> agent.sendMessage(chainId, jobId, payloadJson, "structured")
//   POST /v1/internal/submit-final  -> session.submit(finalPayloadJson)  (closes job)
//   GET  /health                    -> liveness
//
// Auth: X-API-Key required on the two POST endpoints. Audit F6 (2026-05-25)
// tightened this: the previous behaviour was "auth required when apiKey is
// configured" which silently degraded to UNAUTHENTICATED on any boot with an
// unset SECURITYBOT_API_KEY (the C# tier already fails fast in non-
// Development, but defence-in-depth at the sidecar matters because the C#
// tier's NoOp-on-empty-key isn't the only deployment path). Now the apiKey
// is REQUIRED unconditionally unless the explicit escape hatch
// SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH=true is set (for
// local-only dev where the C# tier is also intentionally unauthenticated).
// Setting that flag emits a loud warning every boot.
//
// Rate limit (audit F8): a small per-IP sliding-window limiter on the POST
// endpoints (60 req/min default, override via
// SECURITYBOT_STREAM_PUSH_RATE_LIMIT). The C# tier already has its
// own limiter on /subscriptions etc., but this is a different attack surface
// — anyone who reaches the docker bridge IP can grief the SDK send path.
//
// Bind only on the docker-internal bridge  -  Caddy MUST NOT forward this port.
// Default port 6001 matches InJobStreamDeliveryService's default BaseUrl.
//
// Bind host (audit F2): defaults to 127.0.0.1 (loopback only). The Docker
// multi-container deploy MUST set SECURITYBOT_STREAM_PUSH_BIND_HOST=0.0.0.0
// explicitly in docker-compose.yml so the C# container can reach it across
// the docker bridge. The previous behaviour of `server.listen(port)` defaulting
// to "all interfaces" silently exposed /v1/internal/* to anyone reaching the
// container's IP — a single docker port-publish change or a misconfigured
// reverse proxy turned that into an unauthenticated path if the API key was
// unset (e.g. local dev). We refuse to bind to a non-loopback address when
// NODE_ENV=production AND no API key is configured (defence in depth on top
// of the C# tier's own fail-closed apiKey check).
//
// We deliberately use the SDK's REST send path (agent.sendMessage, awaitable +
// durable) rather than the transport-push agent.sendJobMessage (fire-and-
// forget). Trades ~250ms latency for delivery confidence  -  the right choice
// for the Phase-1 60s-cadence smoke. Sub-second streams in Phase 2+ can
// switch to sendJobMessage per-offering.

const MAX_BODY_BYTES = 1_048_576; // 1 MB matches C# InJobStreamDeliveryService cap

// F8: small in-memory per-IP sliding-window rate limit. Independent from
// the C# tier's RateLimitMiddleware — different process, different attack
// surface. Default 60 req/min; override via
// SECURITYBOT_STREAM_PUSH_RATE_LIMIT (integer, requests per minute).
const DEFAULT_RATE_LIMIT_PER_MIN = 60;
const RATE_WINDOW_MS = 60_000;
interface Bucket { windowStart: number; count: number; }
const rateBuckets = new Map<string, Bucket>();

function rateLimitExceeded(remoteIp: string, capacity: number): boolean {
  const now = Date.now();
  const b = rateBuckets.get(remoteIp);
  if (!b || now - b.windowStart > RATE_WINDOW_MS) {
    rateBuckets.set(remoteIp, { windowStart: now, count: 1 });
    // Opportunistic eviction every ~256 inserts. Bounded growth even if the
    // bridge sees a flood of distinct IPs (unlikely on a docker-internal lane).
    if (rateBuckets.size > 256) {
      const cutoff = now - RATE_WINDOW_MS * 2;
      for (const [k, v] of rateBuckets) {
        if (v.windowStart < cutoff) rateBuckets.delete(k);
      }
    }
    return false;
  }
  b.count += 1;
  return b.count > capacity;
}

export interface StreamPushServerOptions {
  agent: AcpAgent;
  apiKey?: string;
  port: number;
  /// Network interface to bind. Default "127.0.0.1" (loopback). For Docker
  /// multi-container deployments set to "0.0.0.0" — the docker-internal
  /// bridge is then the trust boundary, NOT this port. Never publish this
  /// port to the host via docker-compose `ports:`.
  bindHost?: string;
}

interface PushTickBody {
  subscriptionId?: string;
  chainId?: number;
  jobId?: string;
  tickNumber?: number;
  payloadJson?: string;
}

interface SubmitFinalBody {
  subscriptionId?: string;
  chainId?: number;
  jobId?: string;
  finalPayloadJson?: string;
}

export function startStreamPushServer(opts: StreamPushServerOptions): Server {
  const { agent, apiKey, port, bindHost = "127.0.0.1" } = opts;

  // F6 (2026-05-25): apiKey is REQUIRED unconditionally unless the explicit
  // escape hatch SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH=true is
  // set. The previous "auth-required-when-set, silent-unauth-otherwise" shape
  // silently regressed to unauthenticated whenever an operator forgot the env
  // var. Now an operator who really wants unauth (local dev where the C# tier
  // is also unauthenticated) opts in by name.
  const allowUnauthenticated =
    (process.env.SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH ?? "").toLowerCase() === "true";
  if (!apiKey && !allowUnauthenticated) {
    throw new Error(
      `[streamPush] REFUSING to start without SECURITYBOT_API_KEY. ` +
      `/v1/internal/push-tick + /v1/internal/submit-final would be unauthenticated. ` +
      `Set SECURITYBOT_API_KEY, or set ` +
      `SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH=true to explicitly opt into ` +
      `unauth mode for local-only dev (do NOT set this in any deployed environment).`);
  }
  if (!apiKey && allowUnauthenticated) {
    console.warn(
      `[streamPush] SECURITYBOT_ALLOW_UNAUTHENTICATED_STREAM_PUSH=true — ` +
      `/v1/internal/push-tick + /v1/internal/submit-final are UNAUTHENTICATED. ` +
      `Anyone reaching ${bindHost}:${port} can send ACP messages on every open job.`);
  }

  // Original bind-host defence-in-depth still applies (pre-F6 path): a
  // non-loopback bind without auth was previously also caught here. With F6
  // closed, the unauth branch above already refuses to start unless the new
  // escape hatch is set — keep this for older test fixtures and clones that
  // still skip the env var path.
  if (bindHost !== "127.0.0.1" && bindHost !== "::1" && !apiKey) {
    const isProdLike = (process.env.NODE_ENV ?? "").toLowerCase() === "production";
    const msg = `[streamPush] REFUSING to bind ${bindHost}:${port} without an apiKey — would expose /v1/internal/push-tick + /submit-final unauthenticated to the bind interface.`;
    if (isProdLike) {
      throw new Error(msg);
    }
    console.warn(msg + " (NODE_ENV != production — booting anyway with a warning).");
  }

  // F8 rate-limit capacity — read once at boot so test fixtures can override.
  const rateLimitPerMin = (() => {
    const raw = process.env.SECURITYBOT_STREAM_PUSH_RATE_LIMIT;
    if (!raw || raw.trim() === "") return DEFAULT_RATE_LIMIT_PER_MIN;
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n) || n < 1) {
      console.warn(`[streamPush] invalid rate-limit '${raw}', falling back to ${DEFAULT_RATE_LIMIT_PER_MIN}`);
      return DEFAULT_RATE_LIMIT_PER_MIN;
    }
    return n;
  })();

  const server = createServer(async (req, res) => {
    try {
      await handle(req, res, agent, apiKey, rateLimitPerMin);
    } catch (err) {
      console.error("[streamPush] unhandled error:", err);
      writeJson(res, 500, { error: "internal" });
    }
  });

  server.listen(port, bindHost, () => {
    const authNote = apiKey ? "X-API-Key enforced" : "UNAUTHENTICATED (apiKey unset)";
    console.log(`[streamPush] listening on ${bindHost}:${port} (${authNote}, ${rateLimitPerMin} req/min/IP)`);
  });
  return server;
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  agent: AcpAgent,
  apiKey: string | undefined,
  rateLimitPerMin: number
) {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";

  if (method === "GET" && url === "/health") {
    writeJson(res, 200, { status: "ok", time: new Date().toISOString() });
    return;
  }

  if (method !== "POST") { writeJson(res, 405, { error: "method not allowed" }); return; }

  // F8 rate-limit on POST endpoints — keyed by socket remoteAddress. On the
  // docker bridge that's the C# container's IP, so this primarily defends
  // against a runaway loop in InJobStreamDeliveryService. If the limit is
  // hit, return 429 — the C# RetryWorker will back off and retry.
  const remoteIp = req.socket.remoteAddress ?? "unknown";
  if (rateLimitExceeded(remoteIp, rateLimitPerMin)) {
    writeJson(res, 429, { error: `rate limit exceeded; ${rateLimitPerMin} req/min per remote address` });
    return;
  }

  // Auth — same secret as the C# tier; constant-time compare. F6: apiKey is
  // required at start-up unless the unauth-dev escape hatch is set, so this
  // `if` short-circuit is the dev-only path; production always enters the
  // branch.
  if (apiKey) {
    const provided = req.headers["x-api-key"];
    const providedStr = Array.isArray(provided) ? provided[0] : provided;
    if (!providedStr || !timingSafeEqual(providedStr, apiKey)) {
      writeJson(res, 401, { error: "unauthorized" });
      return;
    }
  }

  if (url === "/v1/internal/push-tick") {
    const body = await readJsonBody<PushTickBody>(req);
    if (!body) { writeJson(res, 400, { error: "invalid body" }); return; }
    const err = validatePushTick(body);
    if (err) { writeJson(res, 400, { error: err }); return; }
    try {
      // sendMessage = REST fallback (awaitable, durable). Keeps the job open
      // (no submit). Returns void on success; throws on transport/auth/etc.
      await agent.sendMessage(body.chainId!, body.jobId!, body.payloadJson!, "structured");
      writeJson(res, 200, { ok: true, subscriptionId: body.subscriptionId, tickNumber: body.tickNumber });
    } catch (sdkErr) {
      const message = sdkErr instanceof Error ? sdkErr.message : String(sdkErr);
      console.warn(`[streamPush] sendMessage failed for sub=${body.subscriptionId} job=${body.jobId}: ${message}`);
      // 502 = upstream (transport / SDK) failure  -  RetryWorker should retry.
      writeJson(res, 502, { error: "sendMessage failed", detail: message });
    }
    return;
  }

  if (url === "/v1/internal/submit-final") {
    const body = await readJsonBody<SubmitFinalBody>(req);
    if (!body) { writeJson(res, 400, { error: "invalid body" }); return; }
    const err = validateSubmitFinal(body);
    if (err) { writeJson(res, 400, { error: err }); return; }
    const session = agent.getSession(body.chainId!, body.jobId!);
    if (!session) {
      // 410 Gone = session is no longer in the agent's active set (job
      // expired, completed elsewhere, sidecar restarted before hydrate).
      // C# tier treats as terminal for this row.
      writeJson(res, 410, { error: "session not active", subscriptionId: body.subscriptionId });
      return;
    }
    try {
      await session.submit(body.finalPayloadJson!);
      writeJson(res, 200, { ok: true, subscriptionId: body.subscriptionId });
    } catch (sdkErr) {
      const message = sdkErr instanceof Error ? sdkErr.message : String(sdkErr);
      console.warn(`[streamPush] submit failed for sub=${body.subscriptionId} job=${body.jobId}: ${message}`);
      writeJson(res, 502, { error: "submit failed", detail: message });
    }
    return;
  }

  writeJson(res, 404, { error: "not found" });
}

function validatePushTick(b: PushTickBody): string | null {
  if (!b.subscriptionId || typeof b.subscriptionId !== "string") return "subscriptionId required";
  if (typeof b.chainId !== "number" || b.chainId <= 0)            return "chainId required (positive number)";
  if (!b.jobId || typeof b.jobId !== "string")                    return "jobId required";
  if (typeof b.tickNumber !== "number" || b.tickNumber < 1)       return "tickNumber required (>=1)";
  if (typeof b.payloadJson !== "string" || b.payloadJson.length === 0) return "payloadJson required";
  return null;
}

function validateSubmitFinal(b: SubmitFinalBody): string | null {
  if (!b.subscriptionId || typeof b.subscriptionId !== "string") return "subscriptionId required";
  if (typeof b.chainId !== "number" || b.chainId <= 0)            return "chainId required (positive number)";
  if (!b.jobId || typeof b.jobId !== "string")                    return "jobId required";
  if (typeof b.finalPayloadJson !== "string" || b.finalPayloadJson.length === 0)
    return "finalPayloadJson required";
  return null;
}

async function readJsonBody<T>(req: IncomingMessage): Promise<T | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES) return null;
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  try { return JSON.parse(raw) as T; } catch { return null; }
}

function writeJson(res: ServerResponse, status: number, body: unknown) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(json),
  });
  res.end(json);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
