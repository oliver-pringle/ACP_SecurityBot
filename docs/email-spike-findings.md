# SecurityBot Email Research Spike — Findings (2026-05-30)

**Question:** How does a Virtuals `@agents.world` mailbox send/receive mail, and how
should SecurityBot's `IEmailSender` (currently `NoopEmailSender` → `no_backend`)
actually deliver a scan report?

**Method:** DNS probes on `agents.world`; V2 marketplace agent-API schema inspection;
Virtuals EconomyOS (`os.virtuals.io`) + whitepaper; AgentMail/AgenticMail comparison;
Virtuals Python SDK source. All claims below are from primary sources.

## Findings

1. **`agents.world` is a real, externally-deliverable mail domain.**
   - `MX` = `mxa.mailgun.org`, `mxb.mailgun.org` (Mailgun handles inbound).
   - `TXT` SPF = `v=spf1 include:amazonses.com include:mailgun.org ~all` (Virtuals
     sends outbound via Amazon SES + Mailgun).
   - ⇒ Any standard outbound email — SMTP **or** a transactional HTTP API — can deliver
     to `<local-part>@agents.world`. **No special Virtuals API is required to deliver.**

2. **It is part of EconomyOS** — Virtuals' agent identity layer (on-chain wallet +
   inbox + virtual payment card + a domain). `os.virtuals.io` frames the inbox as the
   agent's own **Web2 service-login inbox** (OTPs, verification links, receipts), set in
   the agent's **Identity tab**.

3. **No public programmatic SEND API exists.**
   - `os.virtuals.io` documents the inbox as receive-oriented; there is no advertised
     endpoint for an agent to send outbound mail *as* its `@agents.world` identity.
   - The Virtuals Python SDK has **zero** email/inbox functionality.
   - AgentMail *does* offer a send API, but it uses `@agentmail.to` — it does **not**
     power `@agents.world`. So there is no official "send as TheSecurityBot@agents.world"
     path; SecurityBot must use its **own** outbound provider.

4. **The recipient address is NOT discoverable from public data.**
   - `GET api.acp.virtuals.io/agents/wallet/{addr}` returns keys: `id, name, description,
     imageUrl, walletAddress, solWalletAddress, role, cluster, tag, createdAt, updatedAt,
     lastActiveAt, lastNotifyAt, rating, isHidden, chains, offerings, resources,
     subscriptions, builderCode, consoleAgentId` — **no email field**.
   - The `@agents.world` address is owner-only (Identity tab). ⇒ SecurityBot **cannot
     auto-resolve a third-party audited agent's inbox**. This **invalidates the v1 design
     assumption** that "the address comes from the agent's marketplace identity."

## Implications for `IEmailSender`

- **Send mechanism = standard transactional email.** Mailgun / AWS SES / Resend /
  Postmark via `HttpClient` (no new NuGet dependency), or MailKit SMTP. SecurityBot sends
  FROM a sender it controls TO the recipient address.
- **Real blocker is ops, not code:** SecurityBot needs its own transactional-email
  provider account + a **verified sending domain with SPF/DKIM/DMARC**, or mail to
  `agents.world` (Mailgun inbound) will be spam-filtered.
- **Recipient sourcing must change:** since the address isn't public, the workable path is
  **buyer-supplied recipient email** in the `security_scan` request — NOT auto-resolution.
- **Outreach thesis (R15) is not supported:** there is no public agent→email directory, so
  cold-emailing audited agents' inboxes at scale isn't viable through `@agents.world`. Keep
  the proactive-outreach funnel deferred / default-OFF.

## Open item (Oliver, authenticated)

Open SecurityBot's **Identity tab** on app.virtuals.io and note the exact `@agents.world`
address format (is the local-part the agent name, a slug/handle, or an id?). If it's
derivable from a public field, *limited* auto-resolution becomes possible; if it's a
random/owner-only handle, stick with buyer-supplied.

## Recommendation

1. **Implement `IEmailSender` as a transactional sender.** Suggested: **Resend** (simplest
   HTTP API, strong deliverability, free tier) or **Mailgun** (matches the ecosystem —
   `agents.world` is itself Mailgun) or **AWS SES** (cheapest at scale; already in the
   SPF). All are a single authenticated `HttpClient` POST.
2. **Adjust the `security_scan` request:** add an explicit `recipientEmail` (buyer-supplied);
   treat `emailReport=true` without a resolvable recipient as `skipped` (the existing
   `EmailResult` status already supports this) rather than guessing an address.
3. **Provision a sending domain** (e.g. a `mail.*` subdomain) with SPF/DKIM/DMARC before
   enabling email.
4. **Keep proactive outreach deferred** (no public directory to target).

## Status

- **Determination half of the spike: DONE** (mechanism understood, design corrected).
- **Implementation half: gated** on (a) a provider choice and (b) a verified sending
  domain — both ops decisions for Oliver. Est. ~half a day of code once those exist
  (one HttpClient sender + config + wire into the scan path + tests).

## Sources

- DNS: `nslookup -type=MX/TXT agents.world` (Mailgun MX, SES+Mailgun SPF)
- `GET https://api.acp.virtuals.io/agents/wallet/{addr}` (no email field)
- https://os.virtuals.io/ (EconomyOS identity/inbox overview)
- https://cryptobriefing.com/virtuals-protocol-economyos-ai-agents-inbox/
- https://github.com/Virtual-Protocol/virtuals-python (no email API)
- https://www.agentmail.to/ (uses @agentmail.to, not @agents.world)
