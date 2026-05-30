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
  patternCatalogue: {
    name: "patternCatalogue",
    url: "/v1/resources/patternCatalogue",
    params: { type: "object", properties: {} },
    description:
      "FREE. Returns the full 49-pattern security catalogue (P1-P39 + B-series) with " +
      "severity, detection rule, and canonical fix for each. Lets buyer/orchestrator " +
      "agents see exactly what security_scan checks before paying.",
  },
  auditByAgent: {
    name: "auditByAgent",
    url: "/v1/resources/auditByAgent",
    params: {
      type: "object",
      properties: {
        agentAddress: {
          type: "string",
          description: "The agent's 0x wallet address to look up.",
        },
      },
    },
    description:
      "FREE. Returns the most-recent scan SUMMARY for an agent (score, grade, per-severity " +
      "finding counts) - never raw evidence or URLs. found:false if the agent has not been " +
      "scanned.",
  },
};

export function listResources(): string[] {
  return Object.keys(RESOURCES);
}

export function getResource(name: string): Resource | undefined {
  return RESOURCES[name];
}
