import type { Offering } from "./types.js";
import { requireStringLength, requireIntInRange } from "../validators.js";

// Phase-1 test fixture for the inJobStream PushMode. Identical to tick_echo
// in business logic (echo a fixed message every N seconds for K ticks) but
// delivered via a kept-open ACP job + sendJobMessage(content, "structured")
// instead of HMAC-POST to a buyer webhook. Bounds are deliberately tight so
// the Phase-1 smoke runs end-to-end in <5 minutes and stays well under the
// MaxStreamWindow=4h cap on the C# tier.
//
// See docs/superpowers/specs/2026-05-17-pushmode-injobstream-design.md §10
// for the Phase-1 acceptance checklist this fixture is designed to satisfy.

const MAX_MESSAGE_LENGTH = 1000;
const PRICE_PER_TICK_USDC = 0.01;
const MIN_INTERVAL_SECONDS = 60;
const MAX_TICKS = 5;
const MAX_DURATION_MINUTES = 5;
const MAX_DURATION_SECONDS = MAX_DURATION_MINUTES * 60;

export const tickStreamEcho: Offering = {
  name: "tick_stream_echo",
  description:
    "Push a fixed message every N seconds for K ticks via the kept-open ACP job (no buyer webhook needed). Phase-1 test fixture for the inJobStream PushMode  -  buyer's AcpAgent.on(\"entry\") receives each tick as an AgentMessage(structured). Max 5 ticks / 5 minutes.",
  slaMinutes: 10, // hire is instant; the open job runs up to MAX_DURATION_MINUTES
  requirementSchema: {
    type: "object",
    properties: {
      message:         { type: "string",  maxLength: MAX_MESSAGE_LENGTH,
                         description: "Message echoed verbatim on each tick." },
      intervalSeconds: { type: "integer", minimum: MIN_INTERVAL_SECONDS,
                         description: "Seconds between ticks. Min 60." },
      ticks:           { type: "integer", minimum: 1, maximum: MAX_TICKS,
                         description: `Number of ticks (deliveries) to purchase. Max ${MAX_TICKS}.` }
    },
    required: ["message", "intervalSeconds", "ticks"]
  },
  requirementExample: {
    message: "hello stream",
    intervalSeconds: 60,
    ticks: 5
  },
  // The deliverable shape declared here is the FINAL submit body sent at
  // job-close (after the last tick). Per-tick AgentMessage(structured)
  // payloads are pushed within the open job and don't traverse the submit
  // path; their shape is described in description for buyer-side parsers.
  deliverableSchema: {
    type: "object",
    properties: {
      subscriptionId: { type: "string",  description: "UUID identifying this subscription." },
      ticksDelivered: { type: "integer", description: "Total ticks pushed during the stream." },
      deliveredAt:    { type: "string",  description: "ISO-8601 UTC stream-close timestamp." },
      streamSummary:  {
        type: "object",
        properties: {
          ticksPurchased: { type: "integer", description: "Tick budget the buyer paid for." },
          createdAt:      { type: "string",  description: "ISO-8601 UTC subscription start." }
        }
      }
    },
    required: ["subscriptionId", "ticksDelivered", "deliveredAt", "streamSummary"]
  },
  deliverableExample: {
    subscriptionId: "8f3d5a2c9e1b4d7ab2c61f4e8a9d3c70",
    ticksDelivered: 5,
    deliveredAt:    "2026-05-17T15:28:11.4127831Z",
    streamSummary:  {
      ticksPurchased: 5,
      createdAt:      "2026-05-17T15:23:11.4127831Z"
    }
  },
  validate(req) {
    const m = requireStringLength(req.message, "message", MAX_MESSAGE_LENGTH);
    if (!m.valid) return m;
    const i = requireIntInRange(req.intervalSeconds, "intervalSeconds", MIN_INTERVAL_SECONDS, MAX_DURATION_SECONDS);
    if (!i.valid) return i;
    const t = requireIntInRange(req.ticks, "ticks", 1, MAX_TICKS);
    if (!t.valid) return t;
    const totalSec = (req.intervalSeconds as number) * (req.ticks as number);
    if (totalSec > MAX_DURATION_SECONDS)
      return { valid: false, reason: `intervalSeconds x ticks (${totalSec}s) exceeds ${MAX_DURATION_MINUTES}m fixture cap` };
    return { valid: true };
  },
  subscription: {
    pricePerTickUsdc:    PRICE_PER_TICK_USDC,
    minIntervalSeconds:  MIN_INTERVAL_SECONDS,
    maxTicks:            MAX_TICKS,
    // maxDurationDays kept for type-shape compatibility; the real bound for
    // stream-mode subs is MaxStreamWindow on the C# tier (4h). This fixture
    // is intentionally far below that.
    maxDurationDays:     1,
    tiers: [
      // 5 ticks x $0.01 = $0.05; durationDays must be one of {7,15,30,90}
      // for the marketplace UI  -  use the smallest tier even though the
      // fixture finishes inside 5 minutes.
      { name: "phase1_smoke", priceUsd: 0.05, durationDays: 7 }
    ],
    pushMode: "inJobStream"
  }
};
