import type { Offering } from "./types.js";
import type { ValidationResult } from "../validators.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function isAbsoluteHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// One-shot dynamic passive security audit of a live ACP agent.
export const securityScan: Offering = {
  name: "security_scan",
  description:
    "Dynamic passive security audit of a live ACP agent. Probes the agent's public " +
    "HTTP surface (security headers, resource over-disclosure, error-leak, auth posture, " +
    "schema completeness, rate-limit hint) against a 49-pattern catalogue and returns " +
    "per-finding verdicts with evidence, a 0-100 score, a grade, and canonical-fix " +
    "references. Read-only and non-intrusive. Supply agentAddress (auto-resolves the " +
    "public surface) or a baseUrl; optionally email the report to a recipientEmail you " +
    "supply (e.g. an agent's @agents.world inbox).",
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
          "Explicit public base URL to scan (e.g. https://api.example.com). Overrides " +
          "agentAddress resolution. Provide this OR agentAddress (at least one is required).",
      },
      emailReport: {
        type: "boolean",
        description:
          "If true, also email the report to recipientEmail. Default false. The audited " +
          "agent's @agents.world address is not public, so a recipient must be supplied.",
      },
      recipientEmail: {
        type: "string",
        format: "email",
        description:
          "Where to email the report when emailReport is true (e.g. you@example.com, or an " +
          "agent's known <handle>@agents.world inbox). If omitted, email delivery is skipped.",
      },
    },
    required: [],
  },

  requirementExample: {
    agentAddress: "0xecf9773b50f01f3a97b087a6ecdf12a71afc558c",
    emailReport: false,
  },

  deliverableSchema: {
    type: "object",
    description:
      "Scan result for an auditable target. For a NON-auditable target the shape is " +
      "{ agentAddress, baseUrl, resolvedVia, verdict: \"NOT_AUDITABLE\", reason } instead.",
    properties: {
      agentAddress: {
        type: "string",
        description: "The 0x EVM wallet address that was scanned (echoed; may be null if only baseUrl was supplied).",
      },
      baseUrl: {
        type: "string",
        description: "The public base URL that was actually probed.",
      },
      resolvedVia: {
        type: "string",
        description: "How the base URL was determined: \"baseUrl\" (caller-supplied) or \"marketplace\" (resolved from agentAddress).",
      },
      scannedAt: {
        type: "string",
        description: "ISO-8601 UTC timestamp of when the scan ran.",
      },
      score: {
        type: "integer",
        description: "Overall security score, 0-100 (higher is better).",
      },
      grade: {
        type: "string",
        description: "Letter grade derived from the score (e.g. A, B, C, D, F).",
      },
      observableCount: {
        type: "integer",
        description: "Number of patterns that were observable on this target (a pattern is only scored when its precondition could be checked).",
      },
      totalPatterns: {
        type: "integer",
        description: "Total number of patterns in the catalogue considered for this scan.",
      },
      findings: {
        type: "array",
        description: "Per-pattern findings. Each entry is one catalogue pattern with its verdict and evidence.",
        items: {
          type: "object",
          properties: {
            patternId: {
              type: "string",
              description: "Catalogue pattern identifier (e.g. P3, B7).",
            },
            title: {
              type: "string",
              description: "Short human-readable title of the pattern.",
            },
            severity: {
              type: "string",
              description: "Severity of the pattern if it fails (e.g. critical, high, medium, low, info).",
            },
            verdict: {
              type: "string",
              description: "Per-finding verdict (e.g. pass, fail, warn, not_observable).",
            },
            evidence: {
              type: "string",
              description: "Concrete evidence supporting the verdict (e.g. an observed header value or response snippet).",
            },
            fixRef: {
              type: "string",
              description: "Canonical-fix reference pointing to the remediation guidance for this pattern.",
            },
          },
        },
      },
      summary: {
        type: "string",
        description: "One-paragraph human-readable summary of the scan outcome.",
      },
      verdict: {
        type: "string",
        description: "Overall verdict for the target (e.g. PASS, WARN, FAIL). For non-auditable targets this is \"NOT_AUDITABLE\".",
      },
    },
  },

  deliverableExample: {
    agentAddress: "0xecf9773b50f01f3a97b087a6ecdf12a71afc558c",
    baseUrl: "https://api.acp-metabot.dev",
    resolvedVia: "marketplace",
    scannedAt: "2026-05-30T12:34:56Z",
    score: 82,
    grade: "B",
    observableCount: 18,
    totalPatterns: 49,
    findings: [
      {
        patternId: "P31",
        title: "Missing clickjacking + CSP frame-ancestors headers",
        severity: "medium",
        verdict: "fail",
        evidence: "No X-Frame-Options or Content-Security-Policy header on GET /health.",
        fixRef: "P31: add X-Frame-Options: DENY + CSP default-src 'none'; frame-ancestors 'none'.",
      },
      {
        patternId: "P3",
        title: "Error responses do not leak internal exception text",
        severity: "high",
        verdict: "pass",
        evidence: "Malformed body returned a stable INVALID_REQUEST envelope with no stack trace.",
        fixRef: "P3: return stable error codes; never echo ex.Message.",
      },
    ],
    summary:
      "18 of 49 patterns were observable. One medium-severity header gap (P31) was found; " +
      "error-leak and auth posture passed. Score 82 (grade B).",
    verdict: "WARN",
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

    if (req.emailReport !== undefined && typeof req.emailReport !== "boolean") {
      return { valid: false, reason: "emailReport must be a boolean" };
    }

    if (req.recipientEmail !== undefined && req.recipientEmail !== null) {
      const re = req.recipientEmail;
      if (typeof re !== "string" || re.length > 254 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(re)) {
        return { valid: false, reason: "recipientEmail must be a valid email address" };
      }
    }

    return { valid: true };
  },

  execute(req, ctx) {
    return ctx.client.runScan({
      agentAddress: req.agentAddress as string | undefined,
      baseUrl: req.baseUrl as string | undefined,
      emailReport: req.emailReport === true,
      recipientEmail: req.recipientEmail as string | undefined,
    });
  },
};
