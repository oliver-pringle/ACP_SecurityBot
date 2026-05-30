using Microsoft.Data.Sqlite;

namespace SecurityBot.Api.Data;

// Append-only log of email delivery attempts for the paid scan's optional
// emailReport tier. One row per attempt, recording the resolved recipient, the
// agent it scanned (nullable — baseUrl-only scans have no agent), the scan id it
// belongs to (nullable — defensive, the scan is always persisted first), the
// EmailResult.Status, and a timestamp. The email_log table + ix_email_agent
// index live in Db.InitializeSchemaAsync. Read back in Task 12's emailHistory
// Resource.
public sealed class EmailLogRepository
{
    private readonly Db _db;

    public EmailLogRepository(Db db)
    {
        _db = db;
    }

    public async Task InsertAsync(
        string toAddress, string? agentAddress, long? scanId, string status, DateTime sentAt)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO email_log (to_address, agent_address, scan_id, status, sent_at)
            VALUES ($to, $agent, $scan, $status, $sent);";
        cmd.Parameters.AddWithValue("$to", toAddress);
        cmd.Parameters.AddWithValue("$agent", (object?)agentAddress ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$scan", (object?)scanId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$status", status);
        // ISO-8601 round-trip so ORDER BY sent_at sorts chronologically.
        cmd.Parameters.AddWithValue("$sent", sentAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }
}
