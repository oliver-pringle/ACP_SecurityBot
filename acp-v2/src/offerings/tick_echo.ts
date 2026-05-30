import type { Offering } from "./types.js";
import { requireStringLength, requireWebhookUrl, requireIntInRange } from "../validators.js";

const MAX_MESSAGE_LENGTH = 1000;
const PRICE_PER_TICK_USDC = 0.01;
const MIN_INTERVAL_SECONDS = 60;
const MAX_TICKS = 1000;
const MAX_DURATION_DAYS = 90;

export const tickEcho: Offering = {
  name: "tick_echo",
  description:
    "Push a fixed message to your webhook every N seconds for K ticks. Subscription offering  -  pay upfront for the full tick budget. Demonstrates the SecurityBot worker-loop + webhook + HMAC pattern end-to-end.",
  slaMinutes: 5, // subscription hire is instant; per-tick is governed by intervalSeconds
  requirementSchema: {
    type: "object",
    properties: {
      message:         { type: "string",  maxLength: MAX_MESSAGE_LENGTH, description: "Message echoed verbatim on each tick." },
      webhookUrl:      { type: "string",  format: "uri",                  description: "HTTPS URL to receive each tick." },
      intervalSeconds: { type: "integer", minimum: MIN_INTERVAL_SECONDS,  description: "Seconds between ticks." },
      ticks:           { type: "integer", minimum: 1, maximum: MAX_TICKS, description: "Number of ticks (deliveries) to purchase." }
    },
    required: ["message", "webhookUrl", "intervalSeconds", "ticks"]
  },
  requirementExample: {
    message: "hello world",
    webhookUrl: "https://buyer.example.com/webhook",
    intervalSeconds: 3600,
    ticks: 24
  },
  // Subscription deliverable = the receipt submitted on the ACP job at hire time.
  // Per-tick webhook payloads (and their HMAC headers) are pushed directly to the
  // buyer's webhookUrl  -  they don't traverse ACP and aren't part of this schema.
  deliverableSchema: {
    type: "object",
    properties: {
      subscriptionId:  { type: "string",  description: "UUID identifying this subscription." },
      webhookSecret:   { type: "string",  description: "32-byte hex HMAC-SHA256 secret. Returned ONCE  -  buyer must persist." },
      ticksPurchased:  { type: "integer", description: "Total ticks the buyer paid for." },
      intervalSeconds: { type: "integer", description: "Seconds between ticks." },
      expiresAt:       { type: "string",  description: "ISO-8601 UTC. Subscription auto-completes after this." },
      signatureScheme: { type: "string",  description: "Constant: HMAC-SHA256(secret, tick + '.' + timestamp + '.' + body)" }
    },
    required: ["subscriptionId", "webhookSecret", "ticksPurchased", "intervalSeconds", "expiresAt", "signatureScheme"]
  },
  deliverableExample: {
    subscriptionId: "8f3d5a2c-9e1b-4d7a-b2c6-1f4e8a9d3c70",
    webhookSecret:  "a1b2c3d4e5f60708091a2b3c4d5e6f708192a3b4c5d6e7f80910a1b2c3d4e5f6",
    ticksPurchased: 24,
    intervalSeconds: 3600,
    expiresAt: "2026-05-05T14:23:11.4127831Z",
    signatureScheme: "HMAC-SHA256(secret, tick + '.' + timestamp + '.' + body)"
  },
  validate(req) {
    const m = requireStringLength(req.message, "message", MAX_MESSAGE_LENGTH);
    if (!m.valid) return m;
    const w = requireWebhookUrl(req.webhookUrl, "webhookUrl");
    if (!w.valid) return w;
    const i = requireIntInRange(req.intervalSeconds, "intervalSeconds", MIN_INTERVAL_SECONDS, MAX_DURATION_DAYS * 86400);
    if (!i.valid) return i;
    const t = requireIntInRange(req.ticks, "ticks", 1, MAX_TICKS);
    if (!t.valid) return t;
    const totalSec = (req.intervalSeconds as number) * (req.ticks as number);
    const cap = MAX_DURATION_DAYS * 86400;
    if (totalSec > cap) return { valid: false, reason: `intervalSeconds x ticks (${totalSec}s) exceeds ${MAX_DURATION_DAYS}d cap (${cap}s)` };
    return { valid: true };
  },
  subscription: {
    pricePerTickUsdc: PRICE_PER_TICK_USDC,
    minIntervalSeconds: MIN_INTERVAL_SECONDS,
    maxTicks: MAX_TICKS,
    maxDurationDays: MAX_DURATION_DAYS,
    tiers: [
      { name: "weekly_hourly", priceUsd: 1.68, durationDays: 7 }  // 168 ticks x $0.01
    ]
  }
};
