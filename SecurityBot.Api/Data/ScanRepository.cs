using System.Globalization;
using System.Text.Json;
using SecurityBot.Api.Engine;
using SecurityBot.Api.Models;
using Microsoft.Data.Sqlite;

namespace SecurityBot.Api.Data;

public class ScanRepository
{
    private readonly Db _db;

    public ScanRepository(Db db)
    {
        _db = db;
    }

    // Persists one scan row plus its findings atomically. The scan + every
    // finding land inside a single transaction so a partially-written scan is
    // never visible to a concurrent GetMostRecentByAgentAsync read. Returns the
    // new scans.id (last_insert_rowid()).
    public async Task<long> InsertAsync(ScanRecord rec, IReadOnlyList<Finding> findings)
    {
        await using var conn = _db.OpenConnection();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        long scanId;
        await using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO scans
                    (agent_address, base_url, resolved_via, score, grade,
                     observable_count, finding_count, verdict, corpus_version, scanned_at)
                VALUES ($agent, $url, $via, $score, $grade,
                        $obs, $fc, $verdict, $corpus, $scanned);
                SELECT last_insert_rowid();";
            // agent_address may be null (scans resolved via baseUrl only).
            cmd.Parameters.AddWithValue("$agent", (object?)rec.AgentAddress ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$url", rec.BaseUrl);
            cmd.Parameters.AddWithValue("$via", rec.ResolvedVia);
            cmd.Parameters.AddWithValue("$score", rec.Score);
            cmd.Parameters.AddWithValue("$grade", rec.Grade);
            cmd.Parameters.AddWithValue("$obs", rec.ObservableCount);
            cmd.Parameters.AddWithValue("$fc", rec.FindingCount);
            cmd.Parameters.AddWithValue("$verdict", rec.Verdict);
            cmd.Parameters.AddWithValue("$corpus", rec.CorpusVersion);
            // ISO-8601 round-trip so GetMostRecentByAgentAsync can parse back
            // with DateTimeStyles.RoundtripKind and ORDER BY scanned_at sorts
            // lexicographically in true chronological order.
            cmd.Parameters.AddWithValue("$scanned", rec.ScannedAtUtc.ToString("O"));
            scanId = (long)(await cmd.ExecuteScalarAsync())!;
        }

        await using (var fcmd = conn.CreateCommand())
        {
            fcmd.Transaction = tx;
            fcmd.CommandText = @"
                INSERT INTO scan_findings
                    (scan_id, pattern_id, severity, verdict, evidence_json, fix_ref)
                VALUES ($scan, $pat, $sev, $verdict, $ev, $fix);";
            var pScan = fcmd.Parameters.Add("$scan", SqliteType.Integer);
            var pPat = fcmd.Parameters.Add("$pat", SqliteType.Text);
            var pSev = fcmd.Parameters.Add("$sev", SqliteType.Text);
            var pVerdict = fcmd.Parameters.Add("$verdict", SqliteType.Text);
            var pEv = fcmd.Parameters.Add("$ev", SqliteType.Text);
            var pFix = fcmd.Parameters.Add("$fix", SqliteType.Text);

            foreach (var f in findings)
            {
                pScan.Value = scanId;
                pPat.Value = f.PatternId;
                pSev.Value = f.Severity.ToString();
                pVerdict.Value = f.Verdict.ToString();
                // Wrap the evidence string in a small JSON object so the column
                // is genuinely JSON (typed-shape stance), not a bare string.
                pEv.Value = JsonSerializer.Serialize(new { text = f.Evidence });
                pFix.Value = f.FixRef;
                await fcmd.ExecuteNonQueryAsync();
            }
        }

        await tx.CommitAsync();
        return scanId;
    }

    // Latest scan for an agent by scanned_at. Findings are not hydrated — this
    // read backs the resources surface's "most recent grade" lookup. Returns
    // null when the agent has never been scanned.
    public async Task<ScanRecord?> GetMostRecentByAgentAsync(string agentAddress)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT agent_address, base_url, resolved_via, score, grade,
                   observable_count, finding_count, verdict, corpus_version, scanned_at
            FROM scans
            WHERE agent_address = $a
            ORDER BY scanned_at DESC
            LIMIT 1";
        cmd.Parameters.AddWithValue("$a", agentAddress);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;
        return ReadRow(reader);
    }

    // Hydrates the FINDINGS of the most recent scan for a target — by
    // agent_address when one is supplied, else by base_url. This backs the
    // watch tier's per-tick diff (WatchWorker): the previous tick's open
    // findings are compared against the fresh re-scan. Returns an empty list
    // when the target has never been scanned (the first watch tick treats every
    // currently-open finding as newly-opened, which is the correct semantics).
    //
    // The two-step (find scan id, then read its findings) is intentional: the
    // findings join would otherwise duplicate the scan row per finding, and the
    // most-recent-scan selection (ORDER BY scanned_at DESC LIMIT 1) is cleanest
    // against the scans table alone. Both reads run on the same connection.
    public async Task<IReadOnlyList<Finding>> GetMostRecentFindingsAsync(string? agentAddress, string baseUrl)
    {
        await using var conn = _db.OpenConnection();

        long scanId;
        await using (var findCmd = conn.CreateCommand())
        {
            if (!string.IsNullOrEmpty(agentAddress))
            {
                findCmd.CommandText = @"
                    SELECT id FROM scans
                    WHERE agent_address = $a
                    ORDER BY scanned_at DESC
                    LIMIT 1";
                findCmd.Parameters.AddWithValue("$a", agentAddress);
            }
            else
            {
                findCmd.CommandText = @"
                    SELECT id FROM scans
                    WHERE base_url = $u
                    ORDER BY scanned_at DESC
                    LIMIT 1";
                findCmd.Parameters.AddWithValue("$u", baseUrl);
            }
            var idObj = await findCmd.ExecuteScalarAsync();
            if (idObj is null || idObj is DBNull) return Array.Empty<Finding>();
            scanId = (long)idObj;
        }

        var findings = new List<Finding>();
        await using (var fcmd = conn.CreateCommand())
        {
            fcmd.CommandText = @"
                SELECT pattern_id, severity, verdict, evidence_json, fix_ref
                FROM scan_findings
                WHERE scan_id = $id";
            fcmd.Parameters.AddWithValue("$id", scanId);
            await using var reader = await fcmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                var patternId = reader.GetString(0);
                var severity = Enum.Parse<Severity>(reader.GetString(1), ignoreCase: true);
                var verdict = Enum.Parse<Verdict>(reader.GetString(2), ignoreCase: true);
                var evidence = ParseEvidence(reader.GetString(3));
                var fixRef = reader.GetString(4);
                // Title is not persisted (it's a constant of the check, not of
                // the scan); reuse the patternId as the title for the diff —
                // WatchDiff only reads PatternId + Verdict, so this is lossless
                // for the watch path.
                findings.Add(new Finding(patternId, patternId, severity, verdict, evidence, fixRef));
            }
        }
        return findings;
    }

    // evidence_json is the small JSON wrapper {"text":"..."} written by
    // InsertAsync. Unwrap back to the bare Evidence string; tolerate a legacy /
    // malformed value by returning it verbatim rather than throwing.
    private static string ParseEvidence(string evidenceJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(evidenceJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("text", out var t) &&
                t.ValueKind == JsonValueKind.String)
                return t.GetString() ?? string.Empty;
        }
        catch (JsonException) { /* fall through to verbatim */ }
        return evidenceJson;
    }

    private static ScanRecord ReadRow(SqliteDataReader r) => new ScanRecord(
        AgentAddress: r.IsDBNull(0) ? null : r.GetString(0),
        BaseUrl: r.GetString(1),
        ResolvedVia: r.GetString(2),
        Score: r.GetInt32(3),
        Grade: r.GetString(4),
        ObservableCount: r.GetInt32(5),
        FindingCount: r.GetInt32(6),
        Verdict: r.GetString(7),
        CorpusVersion: r.GetString(8),
        ScannedAtUtc: DateTime.Parse(r.GetString(9), null, DateTimeStyles.RoundtripKind));
}
