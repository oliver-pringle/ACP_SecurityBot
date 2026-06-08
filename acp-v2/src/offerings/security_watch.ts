import type { Offering } from "./types.js";
import type { ValidationResult } from "../validators.js";
import { requireWebhookUrl, requireIntInRange } from "../validators.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function isAbsoluteHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// Recurring security watch over a live ACP agent. Each tick re-scans the
// target and delivers a DIFF over an HMAC-signed webhook only when something
// changes. The deliverable at HIRE time is the subscription receipt (below);
// the per-tick diff payloads go directly to the buyer's webhookUrl.
export const securityWatch: Offering = {
  name: "security_watch",
  description:
    "Recurring security watch for a live ACP agent. Re-scans the target on each tick " +
    "and delivers a DIFF (newly-opened / newly-closed findings) over an HMAC-signed " +
    "webhook only when something changes, so you are alerted to new exposures without " +
    "noise. Same 74-pattern passive audit as security_scan. Supply agentAddress or " +
    "baseUrl plus a webhookUrl and an interval/tick count.",
  slaMinutes: 5,

  requirementSchema: {
    type: "object",
    properties: {
      agentAddress: {
        type: "string",
        description:
          "The agent's 0x EVM wallet address. The bot resolves its public HTTP surface " +
          "from the marketplace. Provide this OR baseUrl (at least one is required).",
      },
      baseUrl: {
        type: "string",
        format: "uri",
        description:
          "Explicit public base URL to watch. Overrides agentAddress resolution. " +
          "Provide this OR agentAddress (at least one is required).",
      },
      webhookUrl: {
        type: "string",
        format: "uri",
        description:
          "HTTPS URL that receives each per-tick diff as an HMAC-signed POST. Required.",
      },
      intervalSeconds: {
        type: "integer",
        minimum: 3600,
        description:
          "Seconds between re-scans. Minimum 3600 (1 hour). Required.",
      },
      ticks: {
        type: "integer",
        minimum: 1,
        maximum: 90,
        description:
          "Number of re-scans to purchase (1-90). Required.",
      },
      emailReport: {
        type: "boolean",
        description:
          "If true, also email each diff to the agent's @agents.world inbox. Default false.",
      },
    },
    required: ["webhookUrl", "intervalSeconds", "ticks"],
  },

  requirementExample: {
    agentAddress: "0xecf9773b50f01f3a97b087a6ecdf12a71afc558c",
    webhookUrl: "https://buyer.example.com/securitywatch",
    intervalSeconds: 604800,
    ticks: 12,
  },

  deliverableSchema: {
    type: "object",
    description:
      "Subscription receipt returned at hire time. The recurring per-tick diff payloads " +
      "are delivered separately to webhookUrl, signed with webhookSecret.",
    properties: {
      subscriptionId: {
        type: "string",
        description: "Opaque identifier for this watch subscription; use it to query status.",
      },
      webhookSecret: {
        type: "string",
        description:
          "32-byte hex HMAC secret returned ONCE at hire time. Use it to verify the " +
          "X-Subscription-Signature header on every per-tick webhook POST. Store it now; " +
          "it is never returned again.",
      },
      ticksPurchased: {
        type: "integer",
        description: "Number of re-scans purchased for this subscription window.",
      },
      intervalSeconds: {
        type: "integer",
        description: "Seconds between re-scans, as registered for this subscription.",
      },
      expiresAt: {
        type: "string",
        description: "ISO-8601 UTC timestamp after which no further ticks will fire.",
      },
      signatureScheme: {
        type: "string",
        description: "HMAC scheme used to sign per-tick webhook payloads (e.g. HMAC-SHA256).",
      },
    },
  },

  deliverableExample: {
    subscriptionId: "sub_7f3a1c0e9b2d4f56",
    webhookSecret: "9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6b5a493827160f5e4d3c2b1a0",
    ticksPurchased: 12,
    intervalSeconds: 604800,
    expiresAt: "2026-08-22T12:34:56Z",
    signatureScheme: "HMAC-SHA256",
  },

  validate(req): ValidationResult {
    const agentAddress = req.agentAddress;
    const baseUrl = req.baseUrl;

    const hasAgent = agentAddress !== undefined && agentAddress !== null;
    const hasBaseUrl = baseUrl !== undefined && baseUrl !== null;
    if (!hasAgent && !hasBaseUrl) {
      return { valid: false, reason: "agentAddress or baseUrl is required" };
    }

    if (hasAgent) {
      if (typeof agentAddress !== "string" || !EVM_ADDRESS.test(agentAddress)) {
        return { valid: false, reason: "agentAddress must be a 0x-prefixed 40-hex EVM address" };
      }
    }

    if (hasBaseUrl) {
      if (typeof baseUrl !== "string" || !isAbsoluteHttpUrl(baseUrl)) {
        return { valid: false, reason: "baseUrl must be a valid absolute http(s) URL" };
      }
    }

    const webhook = requireWebhookUrl(req.webhookUrl, "webhookUrl");
    if (!webhook.valid) return webhook;

    const interval = requireIntInRange(req.intervalSeconds, "intervalSeconds", 3600, 90 * 86400);
    if (!interval.valid) return interval;

    const ticks = requireIntInRange(req.ticks, "ticks", 1, 90);
    if (!ticks.valid) return ticks;

    if (req.emailReport !== undefined && typeof req.emailReport !== "boolean") {
      return { valid: false, reason: "emailReport must be a boolean" };
    }

    return { valid: true };
  },

  subscription: {
    pricePerTickUsdc: 0.25,
    minIntervalSeconds: 3600,
    maxTicks: 90,
    maxDurationDays: 90,
    tiers: [
      { name: "weekly_1", priceUsd: 1, durationDays: 7 },
      { name: "monthly_3", priceUsd: 3, durationDays: 30 },
      { name: "quarterly_9", priceUsd: 9, durationDays: 90 },
    ],
  },
};
