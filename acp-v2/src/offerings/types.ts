import type { ValidationResult } from "../validators.js";
import type { ApiClient } from "../apiClient.js";

export interface OfferingContext {
  client: ApiClient;
}

/// Marketplace tier  -  what app.virtuals.io's "Add Job - Subscription Tiers"
/// form takes. Each subscription offering MUST declare >=1 tier; multiple
/// tiers let buyers pick a duration/commitment (weekly/monthly/quarterly).
/// Marketplace UI restricts duration to {7, 15, 30, 90} days.
export interface SubscriptionTier {
  /// Tier name, <=20 chars, snake_case (e.g. "monthly", "30d_watch").
  name: string;
  /// Flat USD price for the entire tier duration (NOT per-tick).
  priceUsd: number;
  /// Tier duration in days; must be one of 7, 15, 30, or 90.
  durationDays: 7 | 15 | 30 | 90;
}

export interface SubscriptionConfig {
  // Internal billing fields  -  used by the bot's worker loop / per-tick HMAC
  // delivery. NOT shown on the marketplace; the marketplace shows `tiers`.
  pricePerTickUsdc: number;
  minIntervalSeconds: number;
  maxTicks: number;
  maxDurationDays: number;

  /// Marketplace registration tiers. At least one. Buyer picks one at hire time.
  /// Required since 2026-05-10.
  tiers: SubscriptionTier[];

  /// Delivery mode for per-tick payloads. Defaults to "webhook"  -  buyer
  /// supplies an HTTPS URL in the requirement, bot HMAC-POSTs each tick.
  /// "inJobStream" keeps the ACP job open after the subscription receipt
  /// and pushes per-tick payloads as AgentMessage(contentType="structured")
  /// over the SSE/WebSocket transport the SDK already holds  -  buyer needs
  /// no webhook surface. See docs/superpowers/specs/2026-05-17-pushmode-
  /// injobstream-design.md for the SDK semantics + Phase-1 verification
  /// gate. Hard-capped to MaxStreamWindow (4h) on the C# tier until that
  /// gate passes in production.
  pushMode?: "webhook" | "inJobStream";
}

export interface Offering {
  name: string;
  description: string;
  // Required: estimated maximum job duration in minutes (min 5). Buyer-facing
  // SLA  -  marketplace surfaces this so buyers know what wall-clock window to
  // plan for between hire and deliverable. For subscription offerings this is
  // hire -> subscription receipt (always fast); per-tick latency is governed
  // by cadence.
  slaMinutes: number;
  requirementSchema: Record<string, unknown>;
  // Required: realistic example payload that satisfies requirementSchema.
  // Goes into the marketplace registration form.
  requirementExample: unknown;
  // Required: deliverable contract (JSON Schema) + one realistic example. Build the
  // schema from the C# response model  -  ASP.NET Core's web defaults emit camelCase
  // keys but DO NOT register JsonStringEnumConverter, so C# enums serialise as ints
  // unless you explicitly .ToString() them. For SUBSCRIPTION offerings, the
  // deliverable shape is the subscription receipt returned at hire time, NOT the
  // per-tick webhook payload (those go directly to the buyer with HMAC headers).
  deliverableSchema: Record<string, unknown>;
  deliverableExample: unknown;
  validate(req: Record<string, unknown>): ValidationResult;

  // Exactly one of the following two MUST be set.
  execute?(req: Record<string, unknown>, ctx: OfferingContext): Promise<unknown>;
  subscription?: SubscriptionConfig;
}
