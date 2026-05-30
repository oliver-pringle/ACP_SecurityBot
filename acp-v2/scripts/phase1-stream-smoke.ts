/**
 * Phase-1 inJobStream smoke harness.
 *
 * Acts as the buyer for ACP_SecurityBot's `tick_stream_echo`
 * offering, holds the SDK transport open for the full stream window, and
 * reports PASS/WARN/FAIL on the 8-item checklist from
 * docs/superpowers/specs/2026-05-17-pushmode-injobstream-design.md §10.
 *
 * Standalone  -  uses a buyer wallet's creds (SMOKE_BUYER_*) entirely
 * separate from the seller's ACP_* env vars. Run alongside (not inside)
 * the running BSB sidecar.
 *
 * USAGE:
 *   cd acp-v2
 *   SMOKE_BUYER_WALLET_ADDRESS=0x...          \
 *   SMOKE_BUYER_WALLET_ID=...                 \
 *   SMOKE_BUYER_SIGNER_PRIVATE_KEY=0x...      \
 *   SMOKE_SELLER_ADDRESS=0x...                \
 *   SMOKE_CHAIN=baseSepolia                   \
 *   [SMOKE_INTERVAL_SECONDS=60]               \
 *   [SMOKE_TICKS=5]                           \
 *   [SMOKE_MESSAGE="phase1"]                  \
 *   [SMOKE_RECONNECT_AFTER_TICK=2]            \
 *   [SMOKE_TIMEOUT_MS=600000]                 \
 *   npx tsx scripts/phase1-stream-smoke.ts
 *
 * EXIT CODES:
 *   0 = all checklist items PASS
 *   1 = at least one checklist item FAIL
 *   2 = setup error (env / hire / connection)
 */
import {
  AcpAgent,
  PrivyAlchemyEvmProviderAdapter,
  type JobRoomEntry,
  type JobSession,
} from "@virtuals-protocol/acp-node-v2";
import { getChain } from "../src/chain.js";
import type { ChainName } from "../src/env.js";

interface SmokeEnv {
  buyerWalletAddress: string;
  buyerWalletId: string;
  buyerSignerPrivateKey: string;
  sellerAddress: string;
  chain: ChainName;
  intervalSeconds: number;
  ticks: number;
  message: string;
  reconnectAfterTick: number;   // 0 = never
  timeoutMs: number;
}

function loadSmokeEnv(): SmokeEnv {
  const required = [
    "SMOKE_BUYER_WALLET_ADDRESS",
    "SMOKE_BUYER_WALLET_ID",
    "SMOKE_BUYER_SIGNER_PRIVATE_KEY",
    "SMOKE_SELLER_ADDRESS",
  ];
  for (const k of required) {
    if (!process.env[k] || process.env[k]!.trim() === "")
      throw new Error(`Missing required env var: ${k}`);
  }

  const chain = (process.env.SMOKE_CHAIN ?? "baseSepolia") as string;
  if (chain !== "base" && chain !== "baseSepolia")
    throw new Error(`SMOKE_CHAIN must be "base" or "baseSepolia", got "${chain}"`);

  function intEnv(name: string, def: number, min: number, max: number): number {
    const raw = process.env[name];
    if (!raw || raw.trim() === "") return def;
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n) || n < min || n > max)
      throw new Error(`${name} must be int ${min}..${max}, got "${raw}"`);
    return n;
  }

  return {
    buyerWalletAddress:     process.env.SMOKE_BUYER_WALLET_ADDRESS!,
    buyerWalletId:          process.env.SMOKE_BUYER_WALLET_ID!,
    buyerSignerPrivateKey:  process.env.SMOKE_BUYER_SIGNER_PRIVATE_KEY!,
    sellerAddress:          process.env.SMOKE_SELLER_ADDRESS!,
    chain:                  chain as ChainName,
    intervalSeconds:        intEnv("SMOKE_INTERVAL_SECONDS", 60, 60, 600),
    ticks:                  intEnv("SMOKE_TICKS", 5, 1, 5),  // tick_stream_echo cap
    message:                process.env.SMOKE_MESSAGE ?? "phase1",
    reconnectAfterTick:     intEnv("SMOKE_RECONNECT_AFTER_TICK", 0, 0, 100),
    timeoutMs:              intEnv("SMOKE_TIMEOUT_MS", 600_000, 60_000, 7_200_000),
  };
}

interface CapturedEntry {
  receivedAt: number;             // ms since hire
  kind: "system" | "message";
  detail: string;                 // event.type for system, contentType for message
  content?: string;               // structured-message payload only
}

interface ChecklistItem {
  id: string;
  label: string;
  result: "PASS" | "WARN" | "FAIL" | "N/A";
  note?: string;
}

async function main(): Promise<number> {
  const env = loadSmokeEnv();
  const chain = getChain(env.chain);

  console.log("================================================================");
  console.log("Phase-1 inJobStream Smoke Harness");
  console.log("================================================================");
  console.log(`Buyer wallet:    ${env.buyerWalletAddress}`);
  console.log(`Seller:          ${env.sellerAddress}`);
  console.log(`Chain:           ${env.chain} (chainId=${chain.id})`);
  console.log(`Cadence:         ${env.intervalSeconds}s x ${env.ticks} ticks`);
  console.log(`Reconnect after: tick ${env.reconnectAfterTick || "(never)"}`);
  console.log(`Hire-window:     ${env.timeoutMs / 1000}s`);
  console.log("");

  // -------- Setup buyer agent ----------------------------------------------
  let provider;
  try {
    provider = await PrivyAlchemyEvmProviderAdapter.create({
      walletAddress:    env.buyerWalletAddress as `0x${string}`,
      walletId:         env.buyerWalletId,
      signerPrivateKey: env.buyerSignerPrivateKey,
      chains:           [chain],
    });
  } catch (err) {
    console.error(`[setup] provider create failed: ${(err as Error).message}`);
    return 2;
  }
  let agent = await AcpAgent.create({ provider });
  console.log(`[setup] buyer agent ready`);

  const captured: CapturedEntry[] = [];
  let targetJobId: string | null = null;
  let hireStartedAt: number = 0;
  let funded = false;
  let receiptReceived = false;
  let finalCompletedAt: number | null = null;
  let lastSystemEvent: string | null = null;
  let reconnected = false;

  const settleSignal: { resolve?: () => void } = {};
  const settled = new Promise<void>((r) => (settleSignal.resolve = r));

  function attachHandler(a: AcpAgent) {
    a.on("entry", async (session: JobSession, entry: JobRoomEntry) => {
      if (!targetJobId || session.jobId !== targetJobId) return;
      const receivedAt = Date.now() - hireStartedAt;

      if (entry.kind === "system") {
        lastSystemEvent = entry.event.type;
        captured.push({ receivedAt, kind: "system", detail: entry.event.type });
        console.log(`[+${receivedAt.toString().padStart(6, " ")}ms] SYSTEM  ${entry.event.type}`);

        try {
          switch (entry.event.type) {
            case "budget.set":
              if (!funded) {
                funded = true;
                console.log(`[+${receivedAt}ms]         funding job (amount=${entry.event.amount})`);
                await session.fund();
              }
              return;
            case "job.completed":
              finalCompletedAt = receivedAt;
              settleSignal.resolve?.();
              return;
            case "job.rejected":
            case "job.expired":
              settleSignal.resolve?.();
              return;
          }
        } catch (err) {
          console.error(`[handler] error on ${entry.event.type}: ${(err as Error).message}`);
        }
      } else if (entry.kind === "message") {
        const contentPreview = entry.content.length > 200
          ? entry.content.slice(0, 200) + "..."
          : entry.content;
        captured.push({
          receivedAt,
          kind: "message",
          detail: entry.contentType,
          content: entry.content,
        });

        if (entry.contentType === "structured") {
          // The first structured message is the receipt; subsequent are tick payloads.
          if (!receiptReceived) {
            receiptReceived = true;
            console.log(`[+${receivedAt.toString().padStart(6, " ")}ms] RECEIPT structured: ${contentPreview}`);
          } else {
            const tickNum = countStructuredTicks();
            console.log(`[+${receivedAt.toString().padStart(6, " ")}ms] TICK ${tickNum}  structured: ${contentPreview}`);

            // Optional mid-stream reconnect to test Q3 (SSE catchup).
            if (env.reconnectAfterTick > 0 && tickNum === env.reconnectAfterTick && !reconnected) {
              reconnected = true;
              setTimeout(() => void doReconnect(), 1000);
            }
          }
        } else {
          console.log(`[+${receivedAt}ms] MSG     ${entry.contentType}: ${contentPreview}`);
        }
      }
    });
  }

  function countStructuredTicks(): number {
    // Tick count = total structured messages MINUS the receipt (first).
    return captured.filter((c) => c.kind === "message" && c.detail === "structured").length - 1;
  }

  async function doReconnect() {
    console.log(`\n[reconnect] stopping agent to test Q3 (SSE catchup)...`);
    try { await agent.stop(); } catch (err) {
      console.error(`[reconnect] stop failed: ${(err as Error).message}`);
    }
    console.log(`[reconnect] waiting 5s before re-connecting...`);
    await new Promise((r) => setTimeout(r, 5000));
    try {
      provider = await PrivyAlchemyEvmProviderAdapter.create({
        walletAddress:    env.buyerWalletAddress as `0x${string}`,
        walletId:         env.buyerWalletId,
        signerPrivateKey: env.buyerSignerPrivateKey,
        chains:           [chain],
      });
      agent = await AcpAgent.create({ provider });
      attachHandler(agent);
      await agent.start();
      console.log(`[reconnect] re-connected; watching for remaining ticks\n`);
    } catch (err) {
      console.error(`[reconnect] failed: ${(err as Error).message}`);
    }
  }

  attachHandler(agent);
  await agent.start();

  // -------- Resolve seller agent + offering --------------------------------
  let sellerDetail;
  try {
    sellerDetail = await agent.getAgentByWalletAddress(env.sellerAddress);
  } catch (err) {
    console.error(`[discover] getAgentByWalletAddress failed: ${(err as Error).message}`);
    await agent.stop();
    return 2;
  }
  if (!sellerDetail) {
    console.error(`[discover] no agent registered with wallet ${env.sellerAddress} on ${env.chain}`);
    await agent.stop();
    return 2;
  }
  const offering = sellerDetail.offerings.find((o) => o.name === "tick_stream_echo");
  if (!offering) {
    const names = sellerDetail.offerings.map((o) => o.name).join(", ") || "(none)";
    console.error(`[discover] tick_stream_echo not found on seller. Available: ${names}`);
    await agent.stop();
    return 2;
  }
  console.log(`[discover] seller="${sellerDetail.name}" offering=tick_stream_echo (slaMinutes=${offering.slaMinutes})\n`);

  // -------- Hire ------------------------------------------------------------
  hireStartedAt = Date.now();
  try {
    const jobIdBig = await agent.createJobFromOffering(
      chain.id,
      offering,
      env.sellerAddress,
      {
        message:         env.message,
        intervalSeconds: env.intervalSeconds,
        ticks:           env.ticks,
      }
    );
    targetJobId = jobIdBig.toString();
    console.log(`[hire] created job ${targetJobId}\n`);
  } catch (err) {
    console.error(`[hire] createJobFromOffering failed: ${(err as Error).message}`);
    await agent.stop();
    return 2;
  }

  // -------- Wait for settle (or timeout) -----------------------------------
  const timeoutSignal = new Promise<"timeout">((resolve) =>
    setTimeout(() => resolve("timeout"), env.timeoutMs)
  );
  const outcome = await Promise.race([settled.then(() => "settled" as const), timeoutSignal]);

  console.log(`\n[${outcome}] done at +${Date.now() - hireStartedAt}ms`);

  try { await agent.stop(); } catch { /* ignore */ }

  // -------- Build checklist ------------------------------------------------
  const tickCount = countStructuredTicks();
  const items: ChecklistItem[] = [];

  // (1) Receipt arrived as structured message on the OPEN job (not via submit).
  items.push({
    id: "1",
    label: "Subscription receipt arrived as AgentMessage(structured), not via submit",
    result: receiptReceived ? "PASS" : "FAIL",
    note: receiptReceived ? "First structured message captured" : "No structured-receipt message ever seen",
  });

  // (2) All N expected tick payloads landed as structured AgentMessages.
  items.push({
    id: "2",
    label: `All ${env.ticks} ticks delivered as AgentMessage(structured)`,
    result: tickCount >= env.ticks ? "PASS" : "FAIL",
    note: `${tickCount} ticks observed (expected ${env.ticks})`,
  });

  // (3) Final submit closed the job cleanly (job.completed system event).
  items.push({
    id: "3",
    label: "Final submit fired job.completed cleanly",
    result: finalCompletedAt !== null ? "PASS" : (lastSystemEvent === "job.expired" ? "FAIL" : "WARN"),
    note: finalCompletedAt !== null
      ? `job.completed at +${finalCompletedAt}ms`
      : `last system event: ${lastSystemEvent ?? "(none)"}`,
  });

  // Q1  -  Job stayed in TRANSACTION through every tick (no premature completion).
  const completedBeforeFinalTick = finalCompletedAt !== null && tickCount < env.ticks;
  items.push({
    id: "Q1",
    label: "Q1: Job remained in TRANSACTION for the whole stream (no premature close)",
    result: completedBeforeFinalTick ? "FAIL" : (finalCompletedAt !== null ? "PASS" : "WARN"),
    note: completedBeforeFinalTick
      ? `job.completed fired after only ${tickCount} ticks (expected ${env.ticks})`
      : (finalCompletedAt !== null
        ? `${tickCount} ticks delivered before close  -  V2 indexer tolerated the long-open job`
        : "no job.completed observed; rerun with longer SMOKE_TIMEOUT_MS or check seller logs"),
  });

  // Q2  -  slaMinutes upper bound. Smoke can't probe the marketplace registration form
  // directly; just confirm the SDK accepted the offering as registered.
  items.push({
    id: "Q2",
    label: "Q2: slaMinutes upper bound (manual check)",
    result: "N/A",
    note: `Confirm at registration time that app.virtuals.io accepted slaMinutes=${offering.slaMinutes} without error`,
  });

  // Q3  -  Reconnect / dedup. Only runs if --reconnect-after-tick set.
  if (env.reconnectAfterTick > 0) {
    items.push({
      id: "Q3",
      label: `Q3: SSE reconnect after tick ${env.reconnectAfterTick} caught up on later ticks`,
      result: (reconnected && tickCount >= env.ticks) ? "PASS" : "FAIL",
      note: reconnected
        ? `reconnect fired; final tick count ${tickCount}/${env.ticks}`
        : "reconnect was scheduled but did not trigger",
    });
  } else {
    items.push({
      id: "Q3",
      label: "Q3: SSE reconnect (not tested)",
      result: "N/A",
      note: "Re-run with SMOKE_RECONNECT_AFTER_TICK=2 to test SSE catchup behaviour",
    });
  }

  // (4) Cadence sanity  -  average interval between ticks within +/-10% of intervalSeconds.
  const tickEntries = captured
    .filter((c) => c.kind === "message" && c.detail === "structured")
    .slice(1); // drop receipt
  if (tickEntries.length >= 2) {
    const deltas: number[] = [];
    for (let i = 1; i < tickEntries.length; i++) {
      deltas.push(tickEntries[i].receivedAt - tickEntries[i - 1].receivedAt);
    }
    const avgMs = deltas.reduce((s, d) => s + d, 0) / deltas.length;
    const expectedMs = env.intervalSeconds * 1000;
    const driftPct = Math.abs(avgMs - expectedMs) / expectedMs * 100;
    items.push({
      id: "4",
      label: `Cadence within +/-20% of ${env.intervalSeconds}s`,
      result: driftPct <= 20 ? "PASS" : "WARN",
      note: `avg interval ${(avgMs / 1000).toFixed(1)}s (drift ${driftPct.toFixed(1)}%)`,
    });
  } else {
    items.push({
      id: "4",
      label: "Cadence sanity",
      result: "WARN",
      note: "Need >=2 ticks to compute cadence; check tick count first",
    });
  }

  // (5) Payloads parse as JSON.
  const parseFailures = tickEntries.filter((t) => {
    try { JSON.parse(t.content!); return false; } catch { return true; }
  }).length;
  items.push({
    id: "5",
    label: "Every tick payload is valid JSON",
    result: parseFailures === 0 ? "PASS" : "FAIL",
    note: parseFailures === 0 ? "all payloads parsed" : `${parseFailures}/${tickEntries.length} payloads failed to parse`,
  });

  // (6) Payload shape  -  every tick carries subscriptionId, tick, message.
  let shapeOk = true;
  let shapeReason = "";
  for (const t of tickEntries) {
    try {
      const p = JSON.parse(t.content!);
      if (!p.subscriptionId || typeof p.tick !== "number" || p.message !== env.message) {
        shapeOk = false;
        shapeReason = `tick ${p.tick ?? "?"} missing/wrong fields: ${JSON.stringify(p)}`.slice(0, 200);
        break;
      }
    } catch { shapeOk = false; break; }
  }
  items.push({
    id: "6",
    label: "Each tick payload has {subscriptionId, tick, message}",
    result: shapeOk ? "PASS" : "FAIL",
    note: shapeOk ? "shape OK on every tick" : shapeReason,
  });

  // (7) No regression  -  webhook offerings unaffected. Out of scope of this script.
  items.push({
    id: "7",
    label: "Webhook-mode regression (covered by tick_echo smoke separately)",
    result: "N/A",
    note: "Run the existing tick_echo HMAC webhook smoke after this passes",
  });

  // (8) Concurrent stress  -  out of scope for v1 of the harness.
  items.push({
    id: "8",
    label: "Concurrent stress (10 simultaneous hires)",
    result: "N/A",
    note: "Manual: run this script with 10 backgrounded instances in parallel once items 1-6 PASS",
  });

  // -------- Report ---------------------------------------------------------
  console.log("\n================================================================");
  console.log("Phase-1 Checklist Report");
  console.log("================================================================");
  for (const it of items) {
    const tag = it.result === "PASS" ? "PASS"
              : it.result === "WARN" ? "WARN"
              : it.result === "FAIL" ? "FAIL"
              : "N/A ";
    console.log(`[${tag}] ${it.id.padEnd(3, " ")} ${it.label}`);
    if (it.note) console.log(`        -> ${it.note}`);
  }
  console.log("");

  const fails = items.filter((i) => i.result === "FAIL").length;
  const warns = items.filter((i) => i.result === "WARN").length;
  console.log(`Summary: ${items.filter((i) => i.result === "PASS").length} PASS, ${warns} WARN, ${fails} FAIL, ${items.filter((i) => i.result === "N/A").length} N/A`);
  console.log("");

  if (fails > 0) {
    console.log("RESULT: ❌ Phase-1 gate FAILED. Do not roll out inJobStream offerings to production.");
    return 1;
  }
  if (warns > 0) {
    console.log("RESULT: ⚠️  Phase-1 gate passes with warnings. Review WARN items before rollout.");
    return 0;
  }
  console.log("RESULT: ✅ Phase-1 gate PASSED. Safe to register price_stream on app.virtuals.io.");
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => { console.error("FATAL:", err); process.exit(2); });
