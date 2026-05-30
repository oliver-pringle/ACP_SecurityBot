# ACP_SecurityBot v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build ACP_SecurityBot v1 - a marketplace seller that performs a deterministic, passive, dynamic security audit of a third-party ACP agent's live HTTP surface and returns per-finding verdicts scored against the P1-P39 + B1-B9 catalogue, plus a subscription watch tier and opt-in email delivery.

**Architecture:** Clone of `ACP_BasicSubscriptionBot` (C# .NET 10 `.Api` + Node 22 TS `acp-v2` sidecar + SQLite). A single hardened `ProbeClient` does all outbound probing (SSRF-blocking, no-redirect, request-budgeted). A registry of 8 independent `IProbeCheck` units each maps 1:1 to a catalogue pattern and returns a structured `Finding`. `DynamicAuditEngine` probes a target once, runs all checks over the shared results, scores, and persists. Target resolution turns an `agentAddress` into a base URL via the V2 marketplace; email send is abstracted behind `IEmailSender` (default no-op, real backend is a research spike).

**Tech Stack:** .NET 10 ASP.NET Minimal API, ADO.NET + Microsoft.Data.Sqlite (no EF/Dapper), xUnit, TypeScript 5.7 + `@virtuals-protocol/acp-node-v2` ^0.0.6, Docker Compose.

**Spec:** `ACP_SecurityBot/docs/superpowers/specs/2026-05-30-acp-securitybot-v1-design.md`

---

## Conventions for every task

- **TDD:** write the failing test first, run it (confirm it fails for the right reason), implement the minimum, run it (confirm pass), commit.
- **ASCII only** in all source you author (no em-dash, smart quotes, arrows, `>=` not the glyph). The portfolio was bitten by mojibake; keep comments plain ASCII.
- **ADO.NET only** - `SqliteConnection`/`SqliteCommand`/`SqliteDataReader`, parameterized queries. No EF, no Dapper.
- **Run C# tests:** `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo`
- **Run a single C# test:** `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~<TestClass>.<TestMethod>"`
- **Run sidecar build:** `cd ACP_SecurityBot/acp-v2 && npm run build`
- **Commit cadence:** one commit per task (after its tests pass). Commit message style: `feat(securitybot): <task>`. The bot folder is committed into the workspace repo at `C:\code_crypto\ACP` (no per-bot remote yet; `git add` scoped paths only - never `git add -A` because the workspace has unrelated untracked litter).
- **Namespaces:** C# root `SecurityBot.Api`; test root `SecurityBot.Tests`.

---

## File structure (what each file owns)

```
ACP_SecurityBot\
  SecurityBot.sln
  SecurityBot.Api\
    SecurityBot.Api.csproj
    Program.cs                           # boot guards, DI, middleware, endpoint mapping
    Data\
      Db.cs                              # SQLite open + schema (scans, scan_findings, subscriptions, subscription_runs, email_log)
      ScanRepository.cs                  # insert/read scans + scan_findings
      SubscriptionRepository.cs          # (lifted from BSB) watch subscriptions
      SubscriptionRunRepository.cs       # (lifted from BSB) per-tick idempotency
      EmailLogRepository.cs              # insert/read email_log + dedupe ledger
    Models\
      Dtos.cs                            # request/response DTOs
      Subscription.cs / SubscriptionRun.cs   # (lifted from BSB)
    Engine\
      Verdict.cs                         # Finding, Verdict enum, Severity enum, ProbeContext, ProbeResponse
      IProbeCheck.cs                     # the check contract
      ProbeClient.cs                     # the single hardened outbound client + SSRF guard
      DynamicAuditEngine.cs              # orchestrate: resolve -> probe once -> run checks -> score -> persist
      Checks\
        SecurityHeadersCheck.cs          # P31
        ResourceDisclosureCheck.cs       # P9
        RawDumpCheck.cs                  # P10
        AuthPostureCheck.cs              # P1/P18
        ErrorLeakCheck.cs                # P30
        SchemaDescriptionCheck.cs        # P32
        TlsTransportCheck.cs             # P31-adjacent
        RateLimitHintCheck.cs            # P15/P19 (bounded)
    Resolution\
      ITargetResolver.cs
      MarketplaceTargetResolver.cs       # agentAddress -> V2 marketplace resource urls -> base host
    Email\
      IEmailSender.cs
      NoopEmailSender.cs
    Services\
      PatternCatalogue.cs                # loads the P/B catalogue JSON, serves patternCatalogue resource
      ScoreCalculator.cs                 # deterministic 0-100 + grade
      SubscriptionService.cs             # (lifted from BSB) bind watch subscription
      WatchWorker.cs                     # (renamed TickSchedulerWorker) re-scan + diff + deliver
      WebhookDeliveryService.cs          # (lifted from BSB) HMAC webhook
      WebhookSecretCipher.cs             # (lifted from BSB) AES-GCM at rest
      WebhookUrlValidator.cs             # (lifted from BSB) webhook SSRF (outbound to buyer)
      WebhookConnectCallbacks.cs         # (lifted from BSB) DNS-pin
      WebhookFlagsHelper.cs              # (lifted from BSB)
      InternalUrlValidator.cs            # (lifted from OracleBot) for email/internal lanes
      BackupWorker.cs                    # (lifted from LiquidGuard) daily SQLite backup
      RetryWorker.cs                     # (lifted from BSB) webhook retry
    Middleware\
      RateLimitMiddleware.cs             # (lifted from BSB) per-IP + per-key, 8192 cap
    Data\catalogue\patterns.json         # the P1-P39 + B1-B9 catalogue (generated from KnownBugs.md)
  SecurityBot.Tests\
    SecurityBot.Tests.csproj
    TestDb.cs                            # in-memory/temp-file SQLite harness (lifted from BSB)
    ... one test file per unit ...
  acp-v2\
    src\offerings\
      security_scan.ts                   # one-shot $1 scan
      security_watch.ts                  # $3/30d subscription
      registry.ts                        # exports both
      types.ts / validators.ts           # (lifted from BSB)
    src\resources.ts                     # patternCatalogue + auditByAgent
    src\pricing.ts                       # scan = fixed $1; watch = tier price
  docker-compose.yml                     # securitybot-api + securitybot-acp
  data\                                  # SQLite bind-mount (gitignored)
  .env.example                           # only this committed; .env gitignored
```

---

## Task 1: Clone and rename the boilerplate

**Files:**
- Create: entire `ACP_SecurityBot\` tree by copying `ACP_BasicSubscriptionBot\`
- Modify: solution, csproj, namespaces, docker-compose, package.json

- [ ] **Step 1: Copy the boilerplate, excluding build artifacts and scratch**

```bash
cd /c/code_crypto/acp
# Copy the source tree only (exclude bin/obj/node_modules/dist/db/.vs and the stray scratch files)
mkdir -p ACP_SecurityBot
cp -r ACP_BasicSubscriptionBot/BasicSubscriptionBot.Api ACP_SecurityBot/
cp -r ACP_BasicSubscriptionBot/BasicSubscriptionBot.Tests ACP_SecurityBot/
cp -r ACP_BasicSubscriptionBot/acp-v2 ACP_SecurityBot/
cp ACP_BasicSubscriptionBot/BasicSubscriptionBot.sln ACP_SecurityBot/
cp ACP_BasicSubscriptionBot/docker-compose.yml ACP_SecurityBot/
cp ACP_BasicSubscriptionBot/README.md ACP_SecurityBot/
cp ACP_BasicSubscriptionBot/LICENSE.txt ACP_SecurityBot/ 2>/dev/null || true
# Purge any copied build artifacts / scratch
rm -rf ACP_SecurityBot/*/bin ACP_SecurityBot/*/obj ACP_SecurityBot/acp-v2/node_modules ACP_SecurityBot/acp-v2/dist
rm -f ACP_SecurityBot/acp-v2/.env
find ACP_SecurityBot -maxdepth 2 -name "_*.txt" -delete 2>/dev/null || true
mkdir -p ACP_SecurityBot/data
```

- [ ] **Step 2: Rename project folders + files**

```bash
cd /c/code_crypto/acp/ACP_SecurityBot
mv BasicSubscriptionBot.Api SecurityBot.Api
mv BasicSubscriptionBot.Tests SecurityBot.Tests
mv SecurityBot.Api/BasicSubscriptionBot.Api.csproj SecurityBot.Api/SecurityBot.Api.csproj
mv SecurityBot.Tests/BasicSubscriptionBot.Tests.csproj SecurityBot.Tests/SecurityBot.Tests.csproj
mv BasicSubscriptionBot.sln SecurityBot.sln
```

- [ ] **Step 3: Find/replace the identifier across all text files**

Replace `BasicSubscriptionBot` -> `SecurityBot` and `BASICSUBSCRIPTIONBOT` -> `SECURITYBOT` and `basicsubscriptionbot` -> `securitybot` in: `*.csproj`, `*.sln`, `*.cs`, `*.ts`, `package.json`, `docker-compose.yml`, `README.md`, `.env.example`.

```bash
cd /c/code_crypto/acp/ACP_SecurityBot
# PowerShell is more reliable on Windows for in-place edits; from a bash shell use perl:
grep -rl --binary-files=without-match 'BasicSubscriptionBot\|BASICSUBSCRIPTIONBOT\|basicsubscriptionbot' \
  --include='*.cs' --include='*.ts' --include='*.csproj' --include='*.sln' \
  --include='*.json' --include='*.yml' --include='*.md' --include='*.example' . \
  | while read f; do
      perl -pi -e 's/BasicSubscriptionBot/SecurityBot/g; s/BASICSUBSCRIPTIONBOT/SECURITYBOT/g; s/basicsubscriptionbot/securitybot/g' "$f"
    done
```

- [ ] **Step 4: Fix the SQLite path + Version in compose and csproj**

In `docker-compose.yml`, confirm the connection string reads `Data Source=/data/securitybot.db;Cache=Shared` and container names are `securitybot-api` / `securitybot-acp`. In `SecurityBot.Api/SecurityBot.Api.csproj` set `<Version>0.1.0</Version>` and confirm `<RootNamespace>SecurityBot.Api</RootNamespace>`. In `acp-v2/package.json` set `"name": "securitybot-acp-v2"`.

- [ ] **Step 5: Build to confirm the rename is clean (stubs still present)**

Run: `dotnet build ACP_SecurityBot/SecurityBot.sln --nologo`
Expected: `Build succeeded. 0 Error(s)`. (The echo/tick_echo stubs still compile - we replace them in later tasks.)

Run: `cd ACP_SecurityBot/acp-v2 && npm install && npm run build`
Expected: clean `tsc`.

- [ ] **Step 6: Run the inherited tests to confirm the harness works**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo`
Expected: all inherited BSB tests pass (they reference `SecurityBot.*` namespaces now).

- [ ] **Step 7: Add a .gitignore guard and commit**

Confirm `ACP_SecurityBot/acp-v2/.env` and `ACP_SecurityBot/data/` are covered by a `.gitignore` (copy `ACP_BasicSubscriptionBot/.gitignore` if present; otherwise create one with `.env`, `bin/`, `obj/`, `node_modules/`, `dist/`, `data/`, `*.db`, `*.db-wal`, `*.db-shm`).

```bash
cd /c/code_crypto/acp
git ls-files --error-unmatch ACP_SecurityBot/acp-v2/.env 2>/dev/null && echo "DANGER: .env tracked" || echo ".env not tracked - good"
git add ACP_SecurityBot/SecurityBot.sln ACP_SecurityBot/SecurityBot.Api ACP_SecurityBot/SecurityBot.Tests ACP_SecurityBot/acp-v2 ACP_SecurityBot/docker-compose.yml ACP_SecurityBot/README.md ACP_SecurityBot/.gitignore ACP_SecurityBot/docs
git commit -m "feat(securitybot): clone and rename BasicSubscriptionBot boilerplate"
```

---

## Task 2: Strip the echo/tick_echo domain stubs

We keep all the security plumbing (cipher, webhook, validators, workers, rate-limit, subscription repos) but remove the echo demo domain so we can graft the scan domain in cleanly.

**Files:**
- Delete: `SecurityBot.Api/Data/EchoRepository.cs`, `SecurityBot.Api/Data/TickEchoRepository.cs`, `SecurityBot.Api/Models/EchoRecord.cs`, `SecurityBot.Api/Models/TickEchoState.cs`, `SecurityBot.Api/Services/EchoService.cs`, `SecurityBot.Api/Services/TickExecutorService.cs`
- Delete tests: `SecurityBot.Tests/EchoRepositoryTests.cs`, `TickEchoRepositoryTests.cs`, `TickExecutorTests.cs`
- Delete sidecar offerings: `acp-v2/src/offerings/echo.ts`, `tick_echo.ts`, `tick_stream_echo.ts`
- Modify: `Program.cs` (remove echo DI + endpoints), `Data/Db.cs` (remove echo_records + tick_echo_state tables), `acp-v2/src/offerings/registry.ts`, `acp-v2/src/resources.ts`

- [ ] **Step 1: Delete the echo-domain source + test files**

```bash
cd /c/code_crypto/acp/ACP_SecurityBot
rm SecurityBot.Api/Data/EchoRepository.cs SecurityBot.Api/Data/TickEchoRepository.cs
rm SecurityBot.Api/Models/EchoRecord.cs SecurityBot.Api/Models/TickEchoState.cs
rm SecurityBot.Api/Services/EchoService.cs SecurityBot.Api/Services/TickExecutorService.cs
rm SecurityBot.Tests/EchoRepositoryTests.cs SecurityBot.Tests/TickEchoRepositoryTests.cs SecurityBot.Tests/TickExecutorTests.cs
rm acp-v2/src/offerings/echo.ts acp-v2/src/offerings/tick_echo.ts acp-v2/src/offerings/tick_stream_echo.ts
```

- [ ] **Step 2: Remove echo wiring from Program.cs**

Remove these lines from `Program.cs`: the `using ... EchoRepository`/`EchoService` references, `builder.Services.AddSingleton<EchoRepository>();`, `builder.Services.AddSingleton<TickEchoRepository>();`, `builder.Services.AddSingleton<EchoService>();`, `builder.Services.AddSingleton<TickExecutorService>();`, and any `app.MapPost("/echo"...)` / `app.MapGet("/v1/resources/echoStatus"...)` handlers. Keep `WebhookSecretCipher`, `SubscriptionRepository`, `SubscriptionRunRepository`, `WebhookDeliveryService`, `RetryWorker`, the rate-limit + forwarded-headers + boot-guard blocks.

Note: `TickSchedulerWorker` currently depends on `TickExecutorService`. Leave `TickSchedulerWorker` registered for now but expect a compile error until Task 9 renames/rewrites it to `WatchWorker`. To keep this task's build green, temporarily comment out `builder.Services.AddHostedService<TickSchedulerWorker>();` and add a `// TODO Task 9: WatchWorker` marker.

- [ ] **Step 3: Drop the echo tables from Db.cs schema**

In `Data/Db.cs`, delete the `CREATE TABLE ... echo_records` and `CREATE TABLE ... tick_echo_state` blocks. Keep `subscriptions` + `subscription_runs`. (We add the scan tables in Task 4.)

- [ ] **Step 4: Empty the sidecar registry + resources**

`acp-v2/src/offerings/registry.ts`:
```typescript
import type { Offering } from "./types.js";

export const OFFERINGS: Record<string, Offering> = {
  // populated in Task 11 (security_scan) and Task 12 (security_watch)
};

export function getOffering(name: string): Offering | undefined {
  return OFFERINGS[name];
}

export function listOfferings(): string[] {
  return Object.keys(OFFERINGS);
}
```

`acp-v2/src/resources.ts`: replace the `echoStatus` entry in `RESOURCES` with an empty object `export const RESOURCES: Record<string, Resource> = {};` (populated in Task 13). Keep the `Resource` interface + helper functions.

- [ ] **Step 5: Fix DbSchemaTests to match the new table set**

In `SecurityBot.Tests/DbSchemaTests.cs`, change the asserted table set to only `subscriptions` and `subscription_runs` for now (scan tables asserted in Task 4):
```csharp
Assert.Contains("subscriptions", names);
Assert.Contains("subscription_runs", names);
```
Remove the `tick_echo_state` and `echo_records` asserts.

- [ ] **Step 6: Build + test green**

Run: `dotnet build ACP_SecurityBot/SecurityBot.sln --nologo`
Expected: 0 errors.
Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo`
Expected: PASS (echo tests gone; subscription/cipher/webhook tests remain green).
Run: `cd ACP_SecurityBot/acp-v2 && npm run build`
Expected: clean tsc (empty registry compiles).

- [ ] **Step 7: Commit**

```bash
cd /c/code_crypto/acp
git add -u ACP_SecurityBot
git add ACP_SecurityBot
git commit -m "feat(securitybot): strip echo/tick_echo demo domain, keep security plumbing"
```

---

## Task 3: Core verdict types (Verdict.cs)

**Files:**
- Create: `SecurityBot.Api/Engine/Verdict.cs`
- Test: `SecurityBot.Tests/VerdictTypesTests.cs`

- [ ] **Step 1: Write the failing test**

`SecurityBot.Tests/VerdictTypesTests.cs`:
```csharp
using SecurityBot.Api.Engine;
using Xunit;

namespace SecurityBot.Tests;

public class VerdictTypesTests
{
    [Fact]
    public void Finding_round_trips_its_fields()
    {
        var f = new Finding(
            PatternId: "P31",
            Title: "Missing security headers",
            Severity: Severity.Low,
            Verdict: Verdict.Present,
            Evidence: "no X-Frame-Options on /health",
            FixRef: "P31");

        Assert.Equal("P31", f.PatternId);
        Assert.Equal(Severity.Low, f.Severity);
        Assert.Equal(Verdict.Present, f.Verdict);
        Assert.Equal("P31", f.FixRef);
    }

    [Fact]
    public void ProbeContext_exposes_responses_by_label()
    {
        var resp = new ProbeResponse(
            Label: "health",
            Url: "https://x.example/health",
            StatusCode: 200,
            Headers: new Dictionary<string, string> { ["X-Frame-Options"] = "DENY" },
            Body: "{}",
            Reached: true);
        var ctx = new ProbeContext("https://x.example", new[] { resp });

        Assert.True(ctx.TryGet("health", out var got));
        Assert.Equal(200, got!.StatusCode);
        Assert.False(ctx.TryGet("missing", out _));
    }
}
```

- [ ] **Step 2: Run, confirm fail**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~VerdictTypesTests"`
Expected: FAIL - `Finding`/`ProbeContext` not defined.

- [ ] **Step 3: Implement Verdict.cs**

`SecurityBot.Api/Engine/Verdict.cs`:
```csharp
namespace SecurityBot.Api.Engine;

public enum Severity { Info, Low, Medium, High, Critical }

// Honest about a dynamic audit's limits: NotObservable is first-class.
public enum Verdict { Present, Partial, Pass, NotObservable, NotApplicable }

public sealed record Finding(
    string PatternId,
    string Title,
    Severity Severity,
    Verdict Verdict,
    string Evidence,
    string FixRef);

// One fetched response from the probe-once pass.
public sealed record ProbeResponse(
    string Label,
    string Url,
    int StatusCode,
    IReadOnlyDictionary<string, string> Headers,
    string Body,
    bool Reached);

// Shared, read-only bag of probe results handed to every check.
public sealed class ProbeContext
{
    public string BaseUrl { get; }
    private readonly Dictionary<string, ProbeResponse> _byLabel;

    public ProbeContext(string baseUrl, IEnumerable<ProbeResponse> responses)
    {
        BaseUrl = baseUrl;
        _byLabel = new Dictionary<string, ProbeResponse>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in responses) _byLabel[r.Label] = r;
    }

    public bool TryGet(string label, out ProbeResponse? response)
        => _byLabel.TryGetValue(label, out response);

    public IEnumerable<ProbeResponse> All => _byLabel.Values;
}
```

- [ ] **Step 4: Run, confirm pass**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~VerdictTypesTests"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api/Engine/Verdict.cs ACP_SecurityBot/SecurityBot.Tests/VerdictTypesTests.cs
git commit -m "feat(securitybot): core verdict types (Finding, ProbeContext, enums)"
```

---

## Task 4: Scan persistence schema + ScanRepository

**Files:**
- Modify: `SecurityBot.Api/Data/Db.cs` (add `scans`, `scan_findings`, `email_log` tables)
- Create: `SecurityBot.Api/Data/ScanRepository.cs`, `SecurityBot.Api/Models/ScanRecord.cs`
- Test: `SecurityBot.Tests/ScanRepositoryTests.cs`, modify `DbSchemaTests.cs`

- [ ] **Step 1: Write the failing schema test**

Add to `SecurityBot.Tests/DbSchemaTests.cs` (a new fact):
```csharp
[Fact]
public async Task InitializeSchema_creates_scan_tables()
{
    await using var t = TestDb.New();
    await t.Db.InitializeSchemaAsync();
    var names = new HashSet<string>();
    await using var conn = t.Db.OpenConnection();
    await using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table'";
    await using var reader = await cmd.ExecuteReaderAsync();
    while (await reader.ReadAsync()) names.Add(reader.GetString(0));
    Assert.Contains("scans", names);
    Assert.Contains("scan_findings", names);
    Assert.Contains("email_log", names);
}
```

- [ ] **Step 2: Write the failing repository test**

`SecurityBot.Tests/ScanRepositoryTests.cs`:
```csharp
using SecurityBot.Api.Data;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Models;
using Xunit;

namespace SecurityBot.Tests;

public class ScanRepositoryTests
{
    [Fact]
    public async Task Insert_then_GetMostRecent_round_trips_scan_and_findings()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new ScanRepository(t.Db);

        var findings = new[]
        {
            new Finding("P31", "Missing headers", Severity.Low, Verdict.Present, "no CSP", "P31"),
            new Finding("P9", "Disclosure", Severity.High, Verdict.Pass, "clean", "P9"),
        };
        var rec = new ScanRecord(
            AgentAddress: "0xabc",
            BaseUrl: "https://x.example",
            ResolvedVia: "baseUrl",
            Score: 82, Grade: "B",
            ObservableCount: 2, FindingCount: 2,
            Verdict: "AUDITED",
            CorpusVersion: "2026-05-30",
            ScannedAtUtc: DateTime.UtcNow);

        var id = await repo.InsertAsync(rec, findings);
        Assert.True(id > 0);

        var got = await repo.GetMostRecentByAgentAsync("0xabc");
        Assert.NotNull(got);
        Assert.Equal(82, got!.Score);
        Assert.Equal("B", got.Grade);
        Assert.Equal(2, got.FindingCount);
    }

    [Fact]
    public async Task GetMostRecentByAgent_returns_null_when_absent()
    {
        await using var t = TestDb.New();
        await t.Db.InitializeSchemaAsync();
        var repo = new ScanRepository(t.Db);
        Assert.Null(await repo.GetMostRecentByAgentAsync("0xnope"));
    }
}
```

- [ ] **Step 3: Run, confirm fail**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~ScanRepositoryTests|FullyQualifiedName~DbSchemaTests"`
Expected: FAIL - `ScanRepository`/`ScanRecord` not defined, scan tables missing.

- [ ] **Step 4: Add tables to Db.cs**

In `Data/Db.cs` `InitializeSchemaAsync`, add (inside the same command batch as the subscription tables):
```sql
CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_address     TEXT,
    base_url          TEXT NOT NULL,
    resolved_via      TEXT NOT NULL,
    score             INTEGER NOT NULL,
    grade             TEXT NOT NULL,
    observable_count  INTEGER NOT NULL,
    finding_count     INTEGER NOT NULL,
    verdict           TEXT NOT NULL,
    corpus_version    TEXT NOT NULL,
    scanned_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scans_agent ON scans(agent_address);
CREATE INDEX IF NOT EXISTS ix_scans_scanned ON scans(scanned_at);

CREATE TABLE IF NOT EXISTS scan_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL,
    pattern_id    TEXT NOT NULL,
    severity      TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    fix_ref       TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON scan_findings(scan_id);

CREATE TABLE IF NOT EXISTS email_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    to_address    TEXT NOT NULL,
    agent_address TEXT,
    scan_id       INTEGER,
    status        TEXT NOT NULL,
    sent_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_email_agent ON email_log(agent_address);
```

- [ ] **Step 5: Create ScanRecord model**

`SecurityBot.Api/Models/ScanRecord.cs`:
```csharp
namespace SecurityBot.Api.Models;

public sealed record ScanRecord(
    string? AgentAddress,
    string BaseUrl,
    string ResolvedVia,
    int Score,
    string Grade,
    int ObservableCount,
    int FindingCount,
    string Verdict,
    string CorpusVersion,
    DateTime ScannedAtUtc);
```

- [ ] **Step 6: Implement ScanRepository**

`SecurityBot.Api/Data/ScanRepository.cs` - ADO.NET, parameterized, insert scan + findings in one transaction; read most-recent by agent. Use `t.Db.OpenConnection()`, `System.Text.Json` for `evidence_json` (store the finding's `Evidence` as a small JSON object `{"text": "..."}` so the column is genuinely JSON, satisfying our own P10 typed-shape stance). Use `Severity`/`Verdict` `.ToString()` for the text columns. Provide:
```csharp
public Task<long> InsertAsync(ScanRecord rec, IReadOnlyList<Finding> findings)
public Task<ScanRecord?> GetMostRecentByAgentAsync(string agentAddress)
```
`GetMostRecentByAgentAsync` selects the latest row by `scanned_at` for `agent_address = $a` and maps back to `ScanRecord` (findings not needed for the summary read).

- [ ] **Step 7: Run, confirm pass**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~ScanRepositoryTests|FullyQualifiedName~DbSchemaTests"`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api/Data/Db.cs ACP_SecurityBot/SecurityBot.Api/Data/ScanRepository.cs ACP_SecurityBot/SecurityBot.Api/Models/ScanRecord.cs ACP_SecurityBot/SecurityBot.Tests/ScanRepositoryTests.cs ACP_SecurityBot/SecurityBot.Tests/DbSchemaTests.cs
git commit -m "feat(securitybot): scan persistence schema + ScanRepository"
```

---

## Task 5: IProbeCheck contract + ScoreCalculator

**Files:**
- Create: `SecurityBot.Api/Engine/IProbeCheck.cs`, `SecurityBot.Api/Services/ScoreCalculator.cs`
- Test: `SecurityBot.Tests/ScoreCalculatorTests.cs`

- [ ] **Step 1: Create the check contract (no test needed - pure interface)**

`SecurityBot.Api/Engine/IProbeCheck.cs`:
```csharp
namespace SecurityBot.Api.Engine;

public interface IProbeCheck
{
    string PatternId { get; }
    string Title { get; }
    Task<Finding> RunAsync(ProbeContext ctx, CancellationToken ct);
}
```

- [ ] **Step 2: Write the failing scorer test**

`SecurityBot.Tests/ScoreCalculatorTests.cs`:
```csharp
using SecurityBot.Api.Engine;
using SecurityBot.Api.Services;
using Xunit;

namespace SecurityBot.Tests;

public class ScoreCalculatorTests
{
    private static Finding F(Severity sev, Verdict v) =>
        new("PX", "t", sev, v, "e", "PX");

    [Fact]
    public void All_pass_scores_100_grade_A()
    {
        var (score, grade) = ScoreCalculator.Compute(new[]
        {
            F(Severity.High, Verdict.Pass),
            F(Severity.Low, Verdict.Pass),
        });
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }

    [Fact]
    public void NotObservable_and_NotApplicable_are_excluded_from_denominator()
    {
        // 1 observable Pass + 2 non-observable => score reflects only the Pass
        var (score, _) = ScoreCalculator.Compute(new[]
        {
            F(Severity.High, Verdict.Pass),
            F(Severity.High, Verdict.NotObservable),
            F(Severity.Low, Verdict.NotApplicable),
        });
        Assert.Equal(100, score);
    }

    [Fact]
    public void A_present_high_severity_finding_drops_the_score_below_a_present_low()
    {
        var (highScore, _) = ScoreCalculator.Compute(new[] { F(Severity.High, Verdict.Present), F(Severity.Low, Verdict.Pass) });
        var (lowScore, _)  = ScoreCalculator.Compute(new[] { F(Severity.Low, Verdict.Present),  F(Severity.Low, Verdict.Pass) });
        Assert.True(highScore < lowScore);
    }

    [Fact]
    public void Compute_is_deterministic()
    {
        var fs = new[] { F(Severity.Medium, Verdict.Present), F(Severity.Low, Verdict.Pass) };
        Assert.Equal(ScoreCalculator.Compute(fs), ScoreCalculator.Compute(fs));
    }

    [Fact]
    public void No_observable_findings_scores_100_NA()
    {
        var (score, grade) = ScoreCalculator.Compute(new[] { F(Severity.High, Verdict.NotObservable) });
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }
}
```

- [ ] **Step 3: Run, confirm fail**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~ScoreCalculatorTests"`
Expected: FAIL - `ScoreCalculator` not defined.

- [ ] **Step 4: Implement ScoreCalculator**

`SecurityBot.Api/Services/ScoreCalculator.cs`:
```csharp
using SecurityBot.Api.Engine;

namespace SecurityBot.Api.Services;

// Deterministic 0-100 from OBSERVABLE findings only. A "Present" finding
// costs its severity weight; "Partial" costs half. Pass costs nothing.
// NotObservable / NotApplicable are excluded from the denominator so a
// target is never punished for what we could not externally verify.
public static class ScoreCalculator
{
    private static int Weight(Severity s) => s switch
    {
        Severity.Critical => 40,
        Severity.High     => 25,
        Severity.Medium   => 12,
        Severity.Low      => 5,
        _                 => 1, // Info
    };

    public static (int score, string grade) Compute(IReadOnlyList<Finding> findings)
    {
        var observable = findings
            .Where(f => f.Verdict is Verdict.Present or Verdict.Partial or Verdict.Pass)
            .ToList();

        if (observable.Count == 0) return (100, "A");

        int maxPenalty = observable.Sum(f => Weight(f.Severity));
        int penalty = observable.Sum(f => f.Verdict switch
        {
            Verdict.Present => Weight(f.Severity),
            Verdict.Partial => Weight(f.Severity) / 2,
            _ => 0,
        });

        int score = maxPenalty == 0 ? 100 : (int)Math.Round(100.0 * (maxPenalty - penalty) / maxPenalty);
        score = Math.Clamp(score, 0, 100);
        return (score, Grade(score));
    }

    private static string Grade(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _     => "F",
    };
}
```

- [ ] **Step 5: Run, confirm pass**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~ScoreCalculatorTests"`
Expected: PASS (all 5).

- [ ] **Step 6: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api/Engine/IProbeCheck.cs ACP_SecurityBot/SecurityBot.Api/Services/ScoreCalculator.cs ACP_SecurityBot/SecurityBot.Tests/ScoreCalculatorTests.cs
git commit -m "feat(securitybot): IProbeCheck contract + deterministic ScoreCalculator"
```

---

## Task 6: The 8 checks (one sub-task each, all TDD against fixtures)

Each check is a pure function of a `ProbeContext` -> `Finding`. No network in tests. Build a small fixture helper first, then implement each check test-first.

**Files:**
- Create: `SecurityBot.Tests/Fixtures.cs` (probe-context builder)
- Create: 8 files under `SecurityBot.Api/Engine/Checks/`
- Test: `SecurityBot.Tests/Checks/*Tests.cs`

- [ ] **Step 1: Create the fixture helper**

`SecurityBot.Tests/Fixtures.cs`:
```csharp
using SecurityBot.Api.Engine;

namespace SecurityBot.Tests;

public static class Fixtures
{
    public static ProbeResponse Resp(
        string label,
        int status = 200,
        IDictionary<string, string>? headers = null,
        string body = "{}",
        bool reached = true,
        string url = "https://x.example/p")
        => new(label, url, status,
               new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
               body, reached);

    public static ProbeContext Ctx(params ProbeResponse[] responses)
        => new("https://x.example", responses);
}
```

### Task 6a: SecurityHeadersCheck (P31)

- [ ] **Test** `SecurityBot.Tests/Checks/SecurityHeadersCheckTests.cs`:
```csharp
using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;
using static SecurityBot.Tests.Fixtures;

namespace SecurityBot.Tests.Checks;

public class SecurityHeadersCheckTests
{
    [Fact]
    public async Task Present_when_headers_missing()
    {
        var ctx = Ctx(Resp("health", headers: new Dictionary<string, string>()));
        var f = await new SecurityHeadersCheck().RunAsync(ctx, default);
        Assert.Equal("P31", f.PatternId);
        Assert.Equal(Verdict.Present, f.Verdict);
    }

    [Fact]
    public async Task Pass_when_all_present()
    {
        var ctx = Ctx(Resp("health", headers: new Dictionary<string, string>
        {
            ["X-Frame-Options"] = "DENY",
            ["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'",
            ["X-Content-Type-Options"] = "nosniff",
        }));
        var f = await new SecurityHeadersCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.Pass, f.Verdict);
    }

    [Fact]
    public async Task NotObservable_when_nothing_reached()
    {
        var ctx = Ctx(Resp("health", reached: false));
        var f = await new SecurityHeadersCheck().RunAsync(ctx, default);
        Assert.Equal(Verdict.NotObservable, f.Verdict);
    }
}
```
- [ ] **Run -> fail**, then implement `SecurityBot.Api/Engine/Checks/SecurityHeadersCheck.cs`: inspect all reached responses; if none reached -> `NotObservable`; if every reached response carries `X-Frame-Options`, `Content-Security-Policy`, and `X-Content-Type-Options` -> `Pass`; otherwise `Present`, Severity `Low`, evidence naming the missing headers + the response label. **Run -> pass. Commit.**

### Task 6b: ResourceDisclosureCheck (P9)

- [ ] **Test** `SecurityBot.Tests/Checks/ResourceDisclosureCheckTests.cs`: PRESENT (High) when a resource body matches an EOA regex `0x[0-9a-fA-F]{40}` labelled as operator/owner, or contains an RPC URL with an embedded api key (`alchemy.com/v2/<key>`, `infura.io/v3/<key>`, `?apikey=`/`?key=`), or a subscription UUID field; PASS when clean; NotObservable when no resource responses reached. Evidence = the matched snippet (truncated to 120 chars). Use canned bodies.
- [ ] **Run -> fail**, implement `Checks/ResourceDisclosureCheck.cs`. **Run -> pass. Commit.**

### Task 6c: RawDumpCheck (P10)

- [ ] **Test** `Checks/RawDumpCheckTests.cs`: PRESENT (Medium) when a resource/dump response has `Content-Type: application/json` AND the body is a large array/object that looks like a raw DB row dump (heuristic: top-level array with > 50 elements, or an object whose keys include snake_case DB column names like `created_at`, `payload_json`, `webhook_secret`); PASS otherwise; NotObservable when no candidate response reached.
- [ ] **Run -> fail**, implement `Checks/RawDumpCheck.cs`. **Run -> pass. Commit.**

### Task 6d: AuthPostureCheck (P1/P18)

- [ ] **Test** `Checks/AuthPostureCheckTests.cs`: requires a probe labelled `paid_unauth` (a GET to a paid `/v1/*` path WITHOUT a key). If that probe was not reached (no such path publicly exposed) -> `NotObservable`. If reached and status is 200 -> PRESENT (High) "paid endpoint answered without auth". If reached and status is 401/403 -> PASS.
- [ ] **Run -> fail**, implement `Checks/AuthPostureCheck.cs`. **Run -> pass. Commit.**

### Task 6e: ErrorLeakCheck (P30)

- [ ] **Test** `Checks/ErrorLeakCheckTests.cs`: requires a probe labelled `malformed` (a deliberately-bad GET). If not reached -> `NotObservable`. If the body contains stack-trace / internal-leak markers (`at System.`, `Exception:`, `Microsoft.Data.Sqlite`, a file path like `/app/`, or an internal docker hostname `-api:5000`) -> PRESENT (Medium). Otherwise PASS.
- [ ] **Run -> fail**, implement `Checks/ErrorLeakCheck.cs`. **Run -> pass. Commit.**

### Task 6f: SchemaDescriptionCheck (P32)

- [ ] **Test** `Checks/SchemaDescriptionCheckTests.cs`: parse each resource response body as JSON; if any object under a `properties` key has a property whose value object lacks a `description` -> PARTIAL (Low) with the count of missing descriptions; if all present -> PASS; if no parseable resource schema reached -> NotObservable.
- [ ] **Run -> fail**, implement `Checks/SchemaDescriptionCheck.cs` (use `System.Text.Json` `JsonDocument`, tolerate non-JSON bodies as NotApplicable for that response). **Run -> pass. Commit.**

### Task 6g: TlsTransportCheck (P31-adjacent)

- [ ] **Test** `Checks/TlsTransportCheckTests.cs`: PRESENT (Medium) when `BaseUrl` scheme is `http` (plaintext); PASS when `https` and an `Strict-Transport-Security` header is observed on any reached response; PARTIAL when `https` but no HSTS seen (edge may emit it); NotObservable when nothing reached.
- [ ] **Run -> fail**, implement `Checks/TlsTransportCheck.cs`. **Run -> pass. Commit.**

### Task 6h: RateLimitHintCheck (P15/P19) - bounded

This check reads pre-collected probe results only; the bounded repeat-GET happens in the engine's probe pass (Task 8), which records a response labelled `ratelimit_probe` with a synthesized status (200 if no 429 ever seen across the bounded burst, 429 if a limiter responded). The check just interprets it.

- [ ] **Test** `Checks/RateLimitHintCheckTests.cs`: if `ratelimit_probe` reached and status 429 -> PASS ("rate limiter observed"); if reached and 200 -> PARTIAL (Low) ("no rate-limit response within bounded probe - may still exist"); if not reached -> NotObservable. (We never assert PRESENT here - absence of an observed 429 within 5 requests is not proof of a missing limiter, hence PARTIAL not PRESENT.)
- [ ] **Run -> fail**, implement `Checks/RateLimitHintCheck.cs`. **Run -> pass. Commit.**

---

## Task 7: ProbeClient (the hardened outbound client + SSRF guard)

**Files:**
- Create: `SecurityBot.Api/Engine/ProbeClient.cs`
- Test: `SecurityBot.Tests/ProbeClientSsrfTests.cs`

The SSRF-block decision (is a resolved IP private/metadata/reserved?) must be a **pure, testable static method** so we can unit-test it without sockets. The actual `SocketsHttpHandler.ConnectCallback` calls that method.

- [ ] **Step 1: Write the failing SSRF-classifier test**

`SecurityBot.Tests/ProbeClientSsrfTests.cs`:
```csharp
using System.Net;
using SecurityBot.Api.Engine;
using Xunit;

namespace SecurityBot.Tests;

public class ProbeClientSsrfTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.5.5", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.169.254", true)]   // cloud metadata
    [InlineData("100.64.0.1", true)]         // CGNAT
    [InlineData("224.0.0.1", true)]          // multicast
    [InlineData("240.0.0.1", true)]          // reserved
    [InlineData("0.0.0.0", true)]
    [InlineData("8.8.8.8", false)]           // public - allowed
    [InlineData("1.1.1.1", false)]
    public void IsBlockedTarget_classifies_ipv4(string ip, bool blocked)
        => Assert.Equal(blocked, ProbeClient.IsBlockedTarget(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("::1", true)]                // loopback
    [InlineData("fe80::1", true)]            // link-local
    [InlineData("fc00::1", true)]            // ULA
    [InlineData("::", true)]                 // unspecified
    [InlineData("2606:4700:4700::1111", false)] // public (cloudflare) - allowed
    public void IsBlockedTarget_classifies_ipv6(string ip, bool blocked)
        => Assert.Equal(blocked, ProbeClient.IsBlockedTarget(IPAddress.Parse(ip)));
}
```

- [ ] **Step 2: Run, confirm fail**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~ProbeClientSsrfTests"`
Expected: FAIL - `ProbeClient` not defined.

- [ ] **Step 3: Implement ProbeClient**

`SecurityBot.Api/Engine/ProbeClient.cs`. Provide:
- `public static bool IsBlockedTarget(IPAddress addr)` - the inverse of the cross-bot pin: BLOCK loopback, RFC1918 (10/8, 172.16/12, 192.168/16), link-local + metadata (169.254/16), CGNAT (100.64/10), multicast (224/4), reserved (240/4), 0/8, IPv6 loopback/link-local(fe80::/10)/ULA(fc00::/7)/unspecified, and IPv4-mapped-IPv6 re-checked. (Lift the bit-math from the portfolio `WebhookUrlValidator.IsBlocked` but invert the intent: here ALL private ranges are blocked, public is allowed.)
- A constructor that builds an `HttpClient` over `SocketsHttpHandler { AllowAutoRedirect = false, ConnectCallback = <pin> }` where the pin resolves the endpoint and throws `HttpRequestException` if `IsBlockedTarget` is true for the chosen IP. Set `Timeout = TimeSpan.FromSeconds(8)`.
- Constants: `public const int MaxRequestsPerScan = 25;`, `public const long MaxResponseBytes = 256 * 1024;`, `public const int MaxRateLimitProbes = 5;`, UA string `ACP-SecurityBot/1.0 (passive-audit)`.
- `public async Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)` - GET with `HttpCompletionOption.ResponseHeadersRead`, read at most `MaxResponseBytes` of the body, capture status + a copied header dictionary, return `ProbeResponse`. On any exception (incl. the SSRF block) return `ProbeResponse(label, url, 0, empty, "", reached:false)`. Enforce `MaxRequestsPerScan` via an internal counter; once exceeded, further `FetchAsync` returns `reached:false` immediately.

- [ ] **Step 4: Run, confirm pass**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~ProbeClientSsrfTests"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api/Engine/ProbeClient.cs ACP_SecurityBot/SecurityBot.Tests/ProbeClientSsrfTests.cs
git commit -m "feat(securitybot): hardened ProbeClient with SSRF-block classifier"
```

---

## Task 8: DynamicAuditEngine (orchestrate probe-once -> checks -> score)

**Files:**
- Create: `SecurityBot.Api/Engine/DynamicAuditEngine.cs`, `SecurityBot.Api/Engine/IProbeFetcher.cs`
- Test: `SecurityBot.Tests/DynamicAuditEngineTests.cs`

To test the engine without network, abstract the fetch behind `IProbeFetcher` (ProbeClient implements it; tests use a fake).

- [ ] **Step 1: Define the fetch seam**

`SecurityBot.Api/Engine/IProbeFetcher.cs`:
```csharp
namespace SecurityBot.Api.Engine;

public interface IProbeFetcher
{
    Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct);
    int MaxRateLimitProbes { get; }
}
```
Make `ProbeClient : IProbeFetcher` (add the interface; it already has `FetchAsync` and the constant). Expose `MaxRateLimitProbes` via the interface.

- [ ] **Step 2: Write the failing engine test**

`SecurityBot.Tests/DynamicAuditEngineTests.cs`:
```csharp
using SecurityBot.Api.Engine;
using SecurityBot.Api.Engine.Checks;
using Xunit;

namespace SecurityBot.Tests;

public class DynamicAuditEngineTests
{
    private sealed class FakeFetcher : IProbeFetcher
    {
        public int MaxRateLimitProbes => 5;
        public Dictionary<string, ProbeResponse> Canned = new();
        public List<string> Fetched = new();
        public Task<ProbeResponse> FetchAsync(string label, string url, CancellationToken ct)
        {
            Fetched.Add(label);
            if (Canned.TryGetValue(label, out var r)) return Task.FromResult(r);
            return Task.FromResult(new ProbeResponse(label, url, 0,
                new Dictionary<string, string>(), "", false));
        }
    }

    [Fact]
    public async Task ScanAsync_runs_all_checks_and_produces_a_report()
    {
        var fetcher = new FakeFetcher();
        fetcher.Canned["health"] = new ProbeResponse("health", "https://x.example/health", 200,
            new Dictionary<string, string> { ["X-Frame-Options"] = "DENY" }, "{}", true);

        var checks = new IProbeCheck[]
        {
            new SecurityHeadersCheck(),
            new TlsTransportCheck(),
        };
        var engine = new DynamicAuditEngine(fetcher, checks, corpusVersion: "test-1");

        var report = await engine.ScanAsync(
            new ScanTarget(AgentAddress: "0xabc", BaseUrl: "https://x.example", ResolvedVia: "baseUrl"),
            default);

        Assert.Equal("AUDITED", report.Verdict);
        Assert.Equal(2, report.Findings.Count);
        Assert.InRange(report.Score, 0, 100);
        Assert.Contains("health", fetcher.Fetched);
    }

    [Fact]
    public async Task ScanAsync_probes_each_label_at_most_the_budget()
    {
        var fetcher = new FakeFetcher();
        var engine = new DynamicAuditEngine(fetcher, new IProbeCheck[] { new SecurityHeadersCheck() }, "test-1");
        await engine.ScanAsync(new ScanTarget(null, "https://x.example", "baseUrl"), default);
        Assert.True(fetcher.Fetched.Count <= ProbeClient.MaxRequestsPerScan);
    }
}
```

- [ ] **Step 3: Run, confirm fail**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~DynamicAuditEngineTests"`
Expected: FAIL - `DynamicAuditEngine`/`ScanTarget`/`ScanReport` not defined.

- [ ] **Step 4: Implement the engine + its DTOs**

In `SecurityBot.Api/Engine/DynamicAuditEngine.cs` define:
```csharp
public sealed record ScanTarget(string? AgentAddress, string BaseUrl, string ResolvedVia);

public sealed record ScanReport(
    string? AgentAddress, string BaseUrl, string ResolvedVia,
    DateTime ScannedAtUtc, int Score, string Grade,
    int ObservableCount, int TotalPatterns,
    IReadOnlyList<Finding> Findings, string Summary, string Verdict);
```
`DynamicAuditEngine(IProbeFetcher fetcher, IEnumerable<IProbeCheck> checks, string corpusVersion)`:
- `ScanAsync(ScanTarget, ct)`:
  1. **Probe once.** Fetch the fixed label set against `target.BaseUrl`: `health` (`/health`), `options` (`OPTIONS /` - for v1 reuse a GET to `/` if OPTIONS is awkward), `resource_*` for a small fixed set of well-known resource paths to try (`/v1/resources/`-rooted: try the agent's advertised resources if provided later; for v1 probe `/v1/resources/` index plus any URLs passed on the target - see note), `paid_unauth` (`/v1/internal/` style path - best-effort; reached:false if 404/unreachable), `malformed` (a GET to `/v1/__securitybot_probe__?x=%ff`), and the bounded `ratelimit_probe` (call `fetcher.FetchAsync("health"...)` up to `MaxRateLimitProbes` times ~150ms apart; synthesize a single `ratelimit_probe` response with status 429 if any returned 429, else 200).
  2. Build `ProbeContext`.
  3. `await` every check's `RunAsync`, collect `Finding`s.
  4. `(score, grade) = ScoreCalculator.Compute(findings)`; `observableCount` = count of Present/Partial/Pass; `totalPatterns = 48`.
  5. Build a one-line `Summary` ("Audited N patterns externally; M findings; score S/100 (grade G)").
  6. Return `ScanReport` with `Verdict = "AUDITED"`.

Note on resource URLs: the engine accepts an optional `IReadOnlyList<string> resourceUrls` on `ScanTarget` (add it as a defaulted param) populated by the resolver in Task 10; for the unit test the list is empty and the resource_* probes are simply not added. Keep the probe label set small and within `MaxRequestsPerScan`.

- [ ] **Step 5: Run, confirm pass**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo --filter "FullyQualifiedName~DynamicAuditEngineTests"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api/Engine/DynamicAuditEngine.cs ACP_SecurityBot/SecurityBot.Api/Engine/IProbeFetcher.cs ACP_SecurityBot/SecurityBot.Api/Engine/ProbeClient.cs ACP_SecurityBot/SecurityBot.Tests/DynamicAuditEngineTests.cs
git commit -m "feat(securitybot): DynamicAuditEngine orchestration (probe-once -> checks -> score)"
```

---

## Task 9: Rework the subscription worker into WatchWorker

The boilerplate's `TickSchedulerWorker` + `SubscriptionService` push a fixed payload. We repurpose them to re-scan + diff. Reuse `SubscriptionRepository`, `SubscriptionRunRepository`, `WebhookDeliveryService`, `WebhookSecretCipher`, `RetryWorker` as-is.

**Files:**
- Rename: `SecurityBot.Api/Workers/TickSchedulerWorker.cs` -> `Workers/WatchWorker.cs`
- Modify: `SecurityBot.Api/Services/SubscriptionService.cs` (validate scan-target requirement instead of message/ticks)
- Test: `SecurityBot.Tests/WatchDiffTests.cs`

- [ ] **Step 1: Write the failing diff-logic test**

`SecurityBot.Tests/WatchDiffTests.cs`:
```csharp
using SecurityBot.Api.Engine;
using SecurityBot.Api.Workers;
using Xunit;

namespace SecurityBot.Tests;

public class WatchDiffTests
{
    private static Finding F(string id, Verdict v) => new(id, id, Severity.Medium, v, "e", id);

    [Fact]
    public void Diff_reports_newly_opened_findings()
    {
        var prev = new[] { F("P31", Verdict.Pass) };
        var curr = new[] { F("P31", Verdict.Present), F("P9", Verdict.Present) };
        var diff = WatchDiff.Compute(prev, curr);
        Assert.Contains("P31", diff.NewlyOpened);
        Assert.Contains("P9", diff.NewlyOpened);
    }

    [Fact]
    public void Diff_reports_newly_closed_findings()
    {
        var prev = new[] { F("P31", Verdict.Present) };
        var curr = new[] { F("P31", Verdict.Pass) };
        var diff = WatchDiff.Compute(prev, curr);
        Assert.Contains("P31", diff.NewlyClosed);
    }

    [Fact]
    public void Diff_is_empty_when_unchanged()
    {
        var prev = new[] { F("P31", Verdict.Present) };
        var curr = new[] { F("P31", Verdict.Present) };
        var diff = WatchDiff.Compute(prev, curr);
        Assert.Empty(diff.NewlyOpened);
        Assert.Empty(diff.NewlyClosed);
        Assert.False(diff.HasChanges);
    }
}
```

- [ ] **Step 2: Run, confirm fail**, then implement a small pure `WatchDiff` in `Workers/WatchWorker.cs`:
```csharp
namespace SecurityBot.Api.Workers;
using SecurityBot.Api.Engine;

public sealed record WatchDiffResult(IReadOnlyList<string> NewlyOpened, IReadOnlyList<string> NewlyClosed)
{
    public bool HasChanges => NewlyOpened.Count > 0 || NewlyClosed.Count > 0;
}

public static class WatchDiff
{
    private static bool IsOpen(Verdict v) => v is Verdict.Present or Verdict.Partial;

    public static WatchDiffResult Compute(IReadOnlyList<Finding> prev, IReadOnlyList<Finding> curr)
    {
        var prevOpen = prev.Where(f => IsOpen(f.Verdict)).Select(f => f.PatternId).ToHashSet();
        var currOpen = curr.Where(f => IsOpen(f.Verdict)).Select(f => f.PatternId).ToHashSet();
        var opened = currOpen.Where(id => !prevOpen.Contains(id)).OrderBy(x => x).ToList();
        var closed = prevOpen.Where(id => !currOpen.Contains(id)).OrderBy(x => x).ToList();
        return new WatchDiffResult(opened, closed);
    }
}
```
**Run -> pass. Commit.**

- [ ] **Step 3: Wire WatchWorker's loop**

In the same file, the `WatchWorker : BackgroundService` (lifted body of TickSchedulerWorker) on each due tick processes the subscriptions returned by `SubscriptionRepository.GetDueAsync(now, limit)` (BSB's real method - it does NOT have a `TryClaimDueAsync`; the boilerplate is single-replica and relies on the `UNIQUE(subscription_id, tick_number)` constraint for idempotency, which we keep). For each due subscription: re-run a scan via `DynamicAuditEngine` for the subscription's stored target, load the previous scan's findings via `ScanRepository`, compute `WatchDiff`, and only if `HasChanges` deliver via `WebhookDeliveryService` (+ optional email via `IEmailSender`). Persist the new scan and call `SubscriptionRepository.RecordTickResultAsync(...)` to advance `next_run_at` (same call the BSB TickSchedulerWorker used). If a future multi-replica deploy is needed, add an atomic claim (P36) then - out of scope for v1 single-replica.

Re-register the worker in `Program.cs`: `builder.Services.AddHostedService<WatchWorker>();` (replacing the commented `TickSchedulerWorker` from Task 2). Delete the old `Workers/TickSchedulerWorker.cs` filename if the rename left it.

- [ ] **Step 4: Update SubscriptionService validation**

In `Services/SubscriptionService.cs`, the create path should accept `{ agentAddress?, baseUrl?, intervalSeconds, ticks, webhookUrl?, emailOptIn? }` (a watch target rather than a message). Validate at least one of agentAddress/baseUrl present; reuse existing interval/ticks bounds + the EVM-address + webhook-URL validators already lifted from BSB. Persist `email_opt_in`.

- [ ] **Step 5: Build + full test run**

Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo`
Expected: PASS (existing subscription/cipher/webhook tests + new WatchDiff tests).

- [ ] **Step 6: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api ACP_SecurityBot/SecurityBot.Tests/WatchDiffTests.cs
git commit -m "feat(securitybot): WatchWorker re-scan + diff over subscription tier"
```

---

## Task 10: Target resolution (MarketplaceTargetResolver)

**Files:**
- Create: `SecurityBot.Api/Resolution/ITargetResolver.cs`, `Resolution/MarketplaceTargetResolver.cs`
- Test: `SecurityBot.Tests/TargetResolverTests.cs`

The V2-marketplace HTTP call is abstracted behind a fetch seam so we can test resolution logic (incl. NOT_AUDITABLE) without network.

- [ ] **Step 1: Define the resolver contract + result**

`SecurityBot.Api/Resolution/ITargetResolver.cs`:
```csharp
namespace SecurityBot.Api.Resolution;

public sealed record ResolvedTarget(
    bool Auditable, string? BaseUrl, string ResolvedVia,
    IReadOnlyList<string> ResourceUrls, string? Reason);

public interface ITargetResolver
{
    Task<ResolvedTarget> ResolveAsync(string? agentAddress, string? baseUrl, CancellationToken ct);
}
```

- [ ] **Step 2: Write the failing test**

`SecurityBot.Tests/TargetResolverTests.cs`: cover (a) explicit `baseUrl` -> `Auditable=true, ResolvedVia="baseUrl"`; (b) only `agentAddress` with a fake marketplace returning two resource URLs sharing host `https://api.foo.dev/...` -> `BaseUrl="https://api.foo.dev", ResolvedVia="marketplace", ResourceUrls.Count==2`; (c) neither provided -> `Auditable=false, Reason` set; (d) agentAddress that the fake marketplace returns no resources for -> `Auditable=false, ResolvedVia="marketplace"`, reason "no externally-auditable surface". Inject the marketplace-fetch via a `Func<string, CancellationToken, Task<IReadOnlyList<string>>>` constructor arg (the fake supplies canned URL lists).

- [ ] **Step 3: Run -> fail**, implement `MarketplaceTargetResolver`:
  - constructor takes the fetch delegate (production wires it to a small `HttpClient` GET against the V2 marketplace agent endpoint, parsing the `resources[].url` fields; this delegate is the only network part and is NOT unit-tested here).
  - `ResolveAsync`: if `baseUrl` non-empty -> validate it's an absolute http(s) URL and return Auditable. Else if `agentAddress` non-empty -> call the fetch delegate; if it returns >=1 URL, derive the common scheme+host (take the first URL's `scheme://host`) and return Auditable with `ResourceUrls`; if 0 URLs -> NOT_AUDITABLE. Else -> NOT_AUDITABLE with reason "agentAddress or baseUrl required".
- [ ] **Step 4: Run -> pass. Commit.**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/SecurityBot.Api/Resolution ACP_SecurityBot/SecurityBot.Tests/TargetResolverTests.cs
git commit -m "feat(securitybot): marketplace target resolver with NOT_AUDITABLE path"
```

---

## Task 11: Email abstraction + PatternCatalogue + scan endpoint wiring

**Files:**
- Create: `SecurityBot.Api/Email/IEmailSender.cs`, `Email/NoopEmailSender.cs`, `Services/PatternCatalogue.cs`, `Data/catalogue/patterns.json`
- Modify: `SecurityBot.Api/Program.cs` (DI for engine + checks + resolver + repo + catalogue; map `POST /v1/internal/scan` + the two Resource GETs)
- Modify: `Models/Dtos.cs` (scan request/response DTOs)
- Test: `SecurityBot.Tests/EmailSenderTests.cs`, `PatternCatalogueTests.cs`, `ScanEndpointTests.cs`

- [ ] **Step 1: IEmailSender + Noop (test-first)**

`SecurityBot.Tests/EmailSenderTests.cs`: assert `NoopEmailSender.SendScanReportAsync(...)` returns `EmailResult` with `Status == "no_backend"`. Then implement:
```csharp
// Email/IEmailSender.cs
namespace SecurityBot.Api.Email;
public sealed record EmailResult(string Status); // sent | skipped | no_backend | failed
public interface IEmailSender
{
    Task<EmailResult> SendScanReportAsync(string toAgentEmail, object report, CancellationToken ct);
}
// Email/NoopEmailSender.cs
namespace SecurityBot.Api.Email;
public sealed class NoopEmailSender : IEmailSender
{
    public Task<EmailResult> SendScanReportAsync(string toAgentEmail, object report, CancellationToken ct)
        => Task.FromResult(new EmailResult("no_backend"));
}
```
**Run -> pass. Commit.**

> NOTE - **research spike is the FIRST follow-up after this plan ships**: determine how a Virtuals `@agents.world` mailbox sends mail (official agent-email API vs SMTP creds from the Identity tab) and implement a real `IEmailSender` to replace `NoopEmailSender`. Until then the scan succeeds and reports `_emailDelivery: "no_backend"`. Outreach worker stays default-OFF (`SECURITYBOT_OUTREACH_ENABLED=false`).

- [ ] **Step 2: PatternCatalogue (test-first)**

First generate `Data/catalogue/patterns.json` from `security-audit/SecurityBot/KnownBugs.md`: a JSON array of `{ id, title, severity, detection, canonicalFix, referenceBot }` for P1-P39 + B1-B9 (48 entries). (One-time authoring task; copy the title/severity/fix text from each KnownBugs section.) Set the csproj to copy it to output:
```xml
<ItemGroup>
  <None Include="Data/catalogue/patterns.json" CopyToOutputDirectory="PreserveNewest" />
</ItemGroup>
```
`PatternCatalogueTests.cs`: assert `new PatternCatalogue(path).All().Count == 48` and `Get("P31").Severity == "Low"`. Implement `Services/PatternCatalogue.cs` loading + indexing the JSON (System.Text.Json). **Run -> pass. Commit.**

- [ ] **Step 3: Scan endpoint (integration test via WebApplicationFactory)**

`ScanEndpointTests.cs`: spin a test host with a stubbed `ITargetResolver` (returns a fixed `https://x.example` Auditable) and a stubbed `IProbeFetcher` (canned responses), POST `/v1/internal/scan` with the internal key header and `{ baseUrl: "https://x.example" }`, assert 200 + the deliverable JSON has `score`, `grade`, `findings`, `observableCount`, `totalPatterns == 48`, `_emailDelivery` absent (no emailReport). (Use the BSB `SmokeTest.cs` WebApplicationFactory pattern as the template; register the stubs by overriding the DI in the factory.)

Implement in `Program.cs`:
- DI: register `ProbeClient` (as `IProbeFetcher`), all 8 `IProbeCheck` singletons, `DynamicAuditEngine` (with `corpusVersion` from the catalogue file's date), `MarketplaceTargetResolver` (as `ITargetResolver`), `ScanRepository`, `PatternCatalogue`, `IEmailSender -> NoopEmailSender`, `EmailLogRepository`.
- `app.MapPost("/v1/internal/scan", ...)` behind the existing X-API-Key middleware: parse `{ agentAddress?, baseUrl?, emailReport? }` (bind as strings/bool, manual parse per the nullable-value-type 400 gotcha), resolve target, if not auditable return the `NOT_AUDITABLE` deliverable (200, `verdict:"NOT_AUDITABLE"`, reason), else `engine.ScanAsync`, persist via `ScanRepository`, optionally email (set `_emailDelivery` from the result), return the `ScanReport` shaped to the deliverable contract in spec section 9. Wrap in try/catch returning a stable `{ error: "INTERNAL_ERROR" }` (P30).

**Run -> pass. Commit.**

---

## Task 12: Resource endpoints (patternCatalogue + auditByAgent)

**Files:**
- Modify: `Program.cs` (two GET handlers under `/v1/resources/`)
- Create: `Data/EmailLogRepository.cs` (if not already in Task 11)
- Test: `SecurityBot.Tests/ResourceEndpointTests.cs`

- [ ] **Step 1: Failing test** `ResourceEndpointTests.cs`: GET `/v1/resources/patternCatalogue` (no auth) -> 200 + a JSON array length 48; GET `/v1/resources/auditByAgent?agentAddress=0xabc` -> 200 with `{ agentAddress, score, grade, severityCounts, scannedAt }` or `{ found:false }` when no scan exists; confirm neither returns raw evidence or URLs (assert the response body does NOT contain `evidence` or `base_url`).
- [ ] **Step 2: Run -> fail**, implement the two handlers in `Program.cs`. `patternCatalogue` returns `PatternCatalogue.All()`. `auditByAgent` reads `ScanRepository.GetMostRecentByAgentAsync` and projects to summary counts only (group findings by severity for the most recent scan - add a `GetFindingSeverityCountsAsync(scanId)` to `ScanRepository`). Whitelist both under the public-path check (only `/health` + `/v1/resources/*` bypass the API key - already the BSB convention).
- [ ] **Step 3: Run -> pass. Commit.**

---

## Task 13: Sidecar offerings + resources (security_scan, security_watch)

**Files:**
- Create: `acp-v2/src/offerings/security_scan.ts`, `security_watch.ts`
- Modify: `acp-v2/src/offerings/registry.ts`, `acp-v2/src/resources.ts`, `acp-v2/src/pricing.ts`, `acp-v2/src/apiClient.ts`
- (No C# test; verify via `npm run build` + `npm run print-offerings`)

- [ ] **Step 1: security_scan.ts** - a one-shot `Offering` with `execute()` that POSTs to the C# `/v1/internal/scan` via `apiClient` and returns the deliverable. `requirementSchema` = `{ agentAddress?: string(0x40 hex, description), baseUrl?: string(uri, description), emailReport?: boolean(description) }` with a oneOf-style note that at least one of agentAddress/baseUrl is required; `requirementExample` = `{ agentAddress: "0xecf97...", emailReport: false }`. `deliverableSchema` mirrors spec section 9 (`score, grade, findings[], observableCount, totalPatterns, summary, verdict, _emailDelivery?`), every property with a `description` (P32). `slaMinutes: 5`. `validate()` enforces at-least-one + EVM-hex on agentAddress + uri on baseUrl using the lifted `validators.ts`. Name `security_scan` (12 chars, within the 20 cap); description < 500 chars.

- [ ] **Step 2: security_watch.ts** - a subscription `Offering` (`subscription` block, no `execute`). `requirementSchema` adds `intervalSeconds`, `ticks`, optional `webhookUrl`, optional `emailReport`. `subscription.tiers` = `[{name:"weekly_1",priceUsd:1,durationDays:7},{name:"monthly_3",priceUsd:3,durationDays:30},{name:"quarterly_9",priceUsd:9,durationDays:90}]`. `deliverableSchema` = the BSB subscription receipt shape (`subscriptionId, webhookSecret, ticksPurchased, intervalSeconds, expiresAt, signatureScheme`). Name `security_watch` (14 chars).

- [ ] **Step 3: registry.ts** exports both:
```typescript
import { securityScan } from "./security_scan.js";
import { securityWatch } from "./security_watch.js";
export const OFFERINGS: Record<string, Offering> = {
  security_scan: securityScan,
  security_watch: securityWatch,
};
```

- [ ] **Step 4: resources.ts** adds `patternCatalogue` (`/v1/resources/patternCatalogue`, parameterless) + `auditByAgent` (`/v1/resources/auditByAgent`, param `agentAddress`), both with `description` mentioning FREE.

- [ ] **Step 5: pricing.ts** - `security_scan` fixed `$1.00`; subscription priced by tier (the BSB pattern already prices subscriptions by `pricePerTickUsdc * ticks`; for the watch tier set `pricePerTickUsdc` so the tier math matches, or special-case the flat tier price). Confirm `priceFor` returns `1.0` for `security_scan`.

- [ ] **Step 6: Build + print**

Run: `cd ACP_SecurityBot/acp-v2 && npm run build`
Expected: clean tsc.
Run: `npm run print-offerings`
Expected: both offerings render; names within 20 chars, descriptions within 500. Fix any cap violations.

- [ ] **Step 7: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot/acp-v2/src
git commit -m "feat(securitybot): sidecar offerings (security_scan, security_watch) + resources"
```

---

## Task 14: Security self-application + boot guards

**Files:**
- Modify: `Program.cs` (confirm P1/P18/P31/P30/P3 guards present; add SECURITYBOT_OUTREACH_ENABLED default-OFF), `docker-compose.yml`, `.env.example`
- Create: `SecurityBot.Tests/DogfoodSelfScanTests.cs`
- Lift if missing: `Services/BackupWorker.cs`, `Services/InternalUrlValidator.cs`

- [ ] **Step 1: Confirm/lift BackupWorker + InternalUrlValidator**

If not inherited from BSB, lift `Services/BackupWorker.cs` from `ACP_LiquidGuard/LiquidGuard.Api/Services/BackupWorker.cs` (rename namespace) and `Services/InternalUrlValidator.cs` from `ACP_OracleBot/OracleBot.Api/Services/InternalUrlValidator.cs`; register `BackupWorker` as a hosted service in `Program.cs`. Run `dotnet build` to confirm.

- [ ] **Step 2: Add the outreach kill-switch**

In `Program.cs`, near boot, read `SECURITYBOT_OUTREACH_ENABLED` (default `false`); if any future outreach worker is added it must check this. For v1, just log at boot: `Outreach worker: DISABLED (SECURITYBOT_OUTREACH_ENABLED=false)`. Document it in `.env.example`.

- [ ] **Step 3: Dogfood self-scan test**

`DogfoodSelfScanTests.cs`: build a `ProbeContext` from SecurityBot's OWN expected response shape (security headers present, no disclosure, stable error codes) and run all 8 checks; assert the resulting score is 100 (no Present findings) for the observable subset. This encodes "SecurityBot passes its own audit" as a regression test.

- [ ] **Step 4: Compose + env**

In `docker-compose.yml`: container names `securitybot-api`/`securitybot-acp`; api joins `acp-shared` + `caddy_proxy` networks (for the gateway-proxied Resources) per the portfolio Resources-routing convention; add `AllowedHosts=securitybot-api;localhost;api.acp-metabot.dev` and `PUBLIC_RESOURCES_BASE_URL`. `.env.example` lists every var with placeholder values; confirm `.env` is gitignored.

- [ ] **Step 5: Full build + test + sidecar build**

Run: `dotnet build ACP_SecurityBot/SecurityBot.sln --nologo` -> 0 warnings.
Run: `dotnet test ACP_SecurityBot/SecurityBot.sln --nologo` -> all green (target 40-50 tests).
Run: `cd ACP_SecurityBot/acp-v2 && npm run build` -> clean.

- [ ] **Step 6: Commit**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot
git commit -m "feat(securitybot): security self-application, BackupWorker, outreach kill-switch, compose"
```

---

## Task 15: Local smoke + readiness (no deploy in this plan)

**Files:** none (verification only)

- [ ] **Step 1: Boot the API locally with the dev opt-ins**

```bash
cd /c/code_crypto/acp/ACP_SecurityBot/SecurityBot.Api
SECURITYBOT_ALLOW_UNAUTHENTICATED_DEV=true ASPNETCORE_ENVIRONMENT=Development dotnet run
```
In another shell: `curl -fsS http://localhost:5000/health` -> 200; `curl -fsS http://localhost:5000/v1/resources/patternCatalogue | head -c 200` -> JSON array.

- [ ] **Step 2: Exercise a scan against a known public host (read-only, your own portfolio bot)**

With the API running, POST a scan for ChainlinkBot's public Resources host (a safe, owned target) and confirm a well-formed report with real findings + `_emailDelivery` absent. (Use the internal key header.) This proves resolve -> probe -> checks -> score -> deliverable end to end against a real surface, within the bounded request budget.

- [ ] **Step 3: Confirm print-offerings caps + readiness checklist**

Run `cd ../acp-v2 && npm run print-offerings && npm run print-resources`. Confirm names <=20, descriptions <=500. Confirm the new-bot hardening checklist (P1/P3/P5/P6/P9/P14/P15/P18/P22/P30/P31/P39) all pass by inspection.

- [ ] **Step 4: Commit a SHIP-READY note**

```bash
cd /c/code_crypto/acp
git add ACP_SecurityBot
git commit -m "chore(securitybot): v1 local-smoke verified, ship-ready pending email spike + deploy"
```

---

## Out of scope for this plan (tracked, do NOT build)

- Real `IEmailSender` backend (research spike - the immediate next task after this plan).
- Droplet deploy + Caddy `/securitybot/*` block + first-hire smoke (use the `acp-bot-deploy` + `acp-bot-smoke` skills as a separate step once the email spike resolves; deploy is a user-authorized action).
- Agent provisioning on app.virtuals.io (interactive, Oliver; Wallet 3).
- Proactive-outreach worker turn-on.
- Static-repo-scan tier; `security_attestation` cross-bot; `security_recheck`; LLM narrative.

---

## Self-review notes (author)

- Spec section coverage: arch (Tasks 1-2), verdict types (3), persistence (4), engine contract+score (5), 8 checks (6a-h), ProbeClient SSRF (7), engine orchestration (8), subscription/watch (9), resolution incl. NOT_AUDITABLE (10), email abstraction + catalogue + scan endpoint (11), resources (12), sidecar offerings (13), self-application + boot guards (14), smoke (15). Email research-spike explicitly deferred per spec section 10. All 14 spec sections map to >=1 task.
- Type consistency: `Finding`/`Verdict`/`Severity`/`ProbeContext`/`ProbeResponse` defined once (Task 3) and reused verbatim; `ScanReport`/`ScanTarget` (Task 8); `ResolvedTarget` (Task 10); `EmailResult` (Task 11). `IProbeFetcher.MaxRateLimitProbes` defined in Task 8 and consumed by the engine's bounded rate-limit probe.
- No placeholders: every code step shows real code; the one authoring step (patterns.json from KnownBugs.md) is explicit about content + source.
