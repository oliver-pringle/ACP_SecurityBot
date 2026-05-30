import { OFFERINGS } from "../src/offerings/registry.js";
import { priceFor } from "../src/pricing.js";

// Marketplace pre-flight check: app.virtuals.io caps offering names at 20 chars.
// `npm run print-offerings` is the last gate before pasting blocks into the
// dashboard, so fail fast here rather than discover the cap at registration.
{
  const MAX_NAME_LEN = 20;
  const violations = Object.values(OFFERINGS)
    .filter(o => o.name.length > MAX_NAME_LEN)
    .map(o => ({ name: o.name, len: o.name.length, over: o.name.length - MAX_NAME_LEN }));
  if (violations.length > 0) {
    console.error(`ERROR: ${violations.length} offering name(s) exceed the ${MAX_NAME_LEN}-char marketplace cap:`);
    for (const v of violations) console.error(`  - ${v.name} (${v.len} chars, ${v.over} over)`);
    console.error("");
    console.error("app.virtuals.io rejects offering names > 20 chars at registration time.");
    console.error("Rename in acp-v2/src/offerings/*.ts (offering 'name' field + export const + file),");
    console.error("then update entries in registry.ts and pricing.ts, then rerun.");
    process.exit(1);
  }
}

for (const [name, off] of Object.entries(OFFERINGS)) {
  console.log("=".repeat(60));
  console.log(`name:        ${name}`);
  console.log(`description: ${off.description}`);
  if (off.subscription) {
    const basePrice = Math.min(...off.subscription.tiers.map(t => t.priceUsd));
    console.log(`type:        SUBSCRIPTION`);
    console.log(`Price:        ${basePrice.toFixed(2)} USDC  (base price  -  marketplace requires min $0.01; cheapest tier)`);
    console.log(`SLA:          ${off.slaMinutes} min  (hire -> subscription receipt; per-tick is governed by interval)`);
    console.log(`Marketplace tiers (paste into "Add Job - Subscription Tiers" form):`);
    for (const tier of off.subscription.tiers) {
      console.log(`  Tier: ${tier.name} | $${tier.priceUsd} | ${tier.durationDays} days`);
    }
  } else {
    const price = priceFor(name, {});
    console.log(`type:        ONE-SHOT`);
    console.log(`Price:       ${price.amountUsdc} USDC`);
    console.log(`SLA:         ${off.slaMinutes} min  (estimated max time from hire to deliverable)`);
  }
  console.log(`requirementSchema:`);
  console.log(JSON.stringify(off.requirementSchema, null, 2));
  console.log(`requirementExample:`);
  console.log(JSON.stringify(off.requirementExample, null, 2));
  console.log(`deliverableSchema:`);
  console.log(JSON.stringify(off.deliverableSchema, null, 2));
  console.log(`deliverableExample:`);
  console.log(JSON.stringify(off.deliverableExample, null, 2));
}
console.log("=".repeat(60));
console.log("Marketplace form takes the requirement schema (with example) + tier list (subscription).");
console.log("Deliverable schema + example are for offering descriptions, buyer docs, and pre-launch wire-shape validation.");
