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
