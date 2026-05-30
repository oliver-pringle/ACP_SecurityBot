// ACP v2 Resources  -  public, free, parameterised endpoints that buyer /
// orchestrator agents (e.g. Butler) call BEFORE paying for an offering.
//
// Resources are first-class in @virtuals-protocol/acp-node-v2 ^0.0.6 as
// AcpAgentResource: { name, url, params, description }. They surface on
// the agent's app.virtuals.io profile in a separate tab from offerings.
//
// A Resource is metadata HERE (TypeScript) and a route HANDLER in the C#
// API tier (Program.cs). This file is the canonical list pasted into
// app.virtuals.io via `npm run print-resources`; the C# tier owns serving.
//
// Default registry ships ONE example so devs see the pattern. Add entries
// when you wire actual handlers in Program.cs.

export interface Resource {
  /// Resource name, <=30 chars, camelCase. Marketplace UI takes this verbatim.
  name: string;
  /// Path on the bot's public API where the handler lives.
  /// e.g. "/v1/resources/echoStatus". This is what buyer agents call.
  url: string;
  /// JSON Schema describing the query parameters. {} for parameterless.
  params: Record<string, unknown>;
  /// Buyer-facing description. Surface what a buyer learns from calling this
  /// and explicitly mention it is FREE so orchestrator agents prefer it
  /// to a paid offering for introspection.
  description: string;
}

export const RESOURCES: Record<string, Resource> = {
  // Sample resource  -  pre-wired with a matching handler in Program.cs and
  // a backing GetStatusAsync in EchoRepository. Demonstrates the C#-side
  // pattern (read SQLite, return JSON). Delete or replace when cloning.
  //
  // DEFERRED (KnownBugs P9 — audit Low/Medium F10): echoStatus returns an
  // exact echo COUNT and lastEchoAt timestamp. Anyone reaching the bot can
  // observe usage volume + recent activity timing — recon value if you don't
  // want competitors / attackers tracking when your bot is busy. The
  // boilerplate keeps this as-is because it's a SAMPLE resource and the
  // information is intentional for demo orchestrators; downstream clones
  // exposing similar surfaces should consider:
  //   - rounding the timestamp to the nearest hour
  //   - removing the count (boolean liveness only)
  //   - caching a coarse summary on a 60-second interval
  // See security-audit/SecurityBot/KnownBugs.md#p9 for the canonical fix.
  echoStatus: {
    name: "echoStatus",
    url: "/v1/resources/echoStatus",
    params: { type: "object", properties: {} },
    description:
      "Returns total echoes recorded and the most recent echo timestamp. " +
      "Free, public, parameterless. Lets buyer agents introspect liveness " +
      "and basic state without paying for the /echo offering."
  }
};

export function listResources(): string[] {
  return Object.keys(RESOURCES);
}

export function getResource(name: string): Resource | undefined {
  return RESOURCES[name];
}
