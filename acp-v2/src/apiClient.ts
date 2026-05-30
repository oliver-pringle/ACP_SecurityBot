export interface CreateSubscriptionInput {
  jobId: string;
  buyerAgent: string;
  offeringName: string;
  requirement: Record<string, unknown>;
  // PushMode plumbing. Omit (or pass "webhook") for the legacy HMAC-POST
  // delivery path. Pass "inJobStream" with the funded job's chainId + jobId
  // to register a kept-open-job stream subscription. See
  // docs/superpowers/specs/2026-05-17-pushmode-injobstream-design.md.
  pushMode?: "webhook" | "inJobStream";
  streamChainId?: number;
  streamJobId?: string;
}

export interface CreateSubscriptionResponse {
  subscriptionId: string;
  // null when pushMode === "inJobStream" (no buyer-side HMAC verification
  //  -  the SDK transport authenticates the seller).
  webhookSecret: string | null;
  ticksPurchased: number;
  intervalSeconds: number;
  expiresAt: string;
  pushMode: "webhook" | "inJobStream";
}

export interface ApiClient {
  createSubscription(input: CreateSubscriptionInput): Promise<CreateSubscriptionResponse>;
}

export function createApiClient(baseUrl: string, opts: { apiKey?: string } = {}): ApiClient {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.apiKey) headers["X-API-Key"] = opts.apiKey;

  async function post<T>(path: string, body: unknown): Promise<T> {
    const r = await fetch(`${baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`POST ${path} -> ${r.status}: ${await r.text()}`);
    return (await r.json()) as T;
  }

  return {
    createSubscription(input) { return post("/subscriptions", input); }
  };
}
