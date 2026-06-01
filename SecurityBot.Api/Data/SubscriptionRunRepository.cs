using SecurityBot.Api.Models;
using Microsoft.Data.Sqlite;

namespace SecurityBot.Api.Data;

public class SubscriptionRunRepository
{
    private readonly Db _db;
    public SubscriptionRunRepository(Db db) => _db = db;

    public async Task<long> InsertPendingAsync(string subscriptionId, int tickNumber, DateTime scheduledAt, string payloadJson)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        // Audit (P59 clone-backport): idempotent on the UNIQUE(subscription_id,
        // tick_number) constraint. A plain INSERT throws on a re-poll/retry that
        // re-derives the same (sub,tick), and last_insert_rowid() returns 0/stale
        // when the insert is ignored — so use INSERT OR IGNORE plus an explicit
        // SELECT id by (sub,tick) to always return the canonical run id.
        cmd.CommandText = @"
            INSERT OR IGNORE INTO subscription_runs
                (subscription_id, tick_number, scheduled_at, payload_json, delivery_status, attempts)
            VALUES ($s, $t, $sa, $p, 'pending', 0);
            SELECT id FROM subscription_runs WHERE subscription_id = $s AND tick_number = $t;";
        cmd.Parameters.AddWithValue("$s", subscriptionId);
        cmd.Parameters.AddWithValue("$t", tickNumber);
        cmd.Parameters.AddWithValue("$sa", scheduledAt.ToString("O"));
        cmd.Parameters.AddWithValue("$p", payloadJson);
        return (long)(await cmd.ExecuteScalarAsync())!;
    }

    public async Task MarkDeliveredAsync(long runId, DateTime at)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE subscription_runs
            SET delivery_status='delivered',
                last_attempt_at=$at,
                next_attempt_at=NULL
            WHERE id=$id";
        cmd.Parameters.AddWithValue("$at", at.ToString("O"));
        cmd.Parameters.AddWithValue("$id", runId);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task MarkRetryingAsync(long runId, int attempts, DateTime nextAttemptAt, string lastError)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE subscription_runs
            SET delivery_status='retrying',
                attempts=$a,
                next_attempt_at=$na,
                last_attempt_at=$at,
                last_error=$err
            WHERE id=$id";
        cmd.Parameters.AddWithValue("$a", attempts);
        cmd.Parameters.AddWithValue("$na", nextAttemptAt.ToString("O"));
        cmd.Parameters.AddWithValue("$at", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$err", Truncate(lastError, 1024));
        cmd.Parameters.AddWithValue("$id", runId);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task MarkDeadAsync(long runId, int attempts, string lastError)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE subscription_runs
            SET delivery_status='dead',
                attempts=$a,
                next_attempt_at=NULL,
                last_attempt_at=$at,
                last_error=$err
            WHERE id=$id";
        cmd.Parameters.AddWithValue("$a", attempts);
        cmd.Parameters.AddWithValue("$at", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$err", Truncate(lastError, 1024));
        cmd.Parameters.AddWithValue("$id", runId);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<List<SubscriptionRun>> GetRetryDueAsync(DateTime now, int limit)
    {
        var rows = new List<SubscriptionRun>();
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT id, subscription_id, tick_number, scheduled_at, payload_json,
                   delivery_status, attempts, next_attempt_at, last_attempt_at, last_error
            FROM subscription_runs
            WHERE delivery_status='retrying' AND next_attempt_at <= $now
            ORDER BY next_attempt_at LIMIT $limit";
        cmd.Parameters.AddWithValue("$now", now.ToString("O"));
        cmd.Parameters.AddWithValue("$limit", limit);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync()) rows.Add(Read(reader));
        return rows;
    }

    public async Task<SubscriptionRun?> GetByIdAsync(long id)
    {
        await using var conn = _db.OpenConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT id, subscription_id, tick_number, scheduled_at, payload_json,
                   delivery_status, attempts, next_attempt_at, last_attempt_at, last_error
            FROM subscription_runs WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        await using var reader = await cmd.ExecuteReaderAsync();
        return await reader.ReadAsync() ? Read(reader) : null;
    }

    private static SubscriptionRun Read(SqliteDataReader r) => new(
        Id: r.GetInt64(0),
        SubscriptionId: r.GetString(1),
        TickNumber: r.GetInt32(2),
        ScheduledAt: DateTime.Parse(r.GetString(3)).ToUniversalTime(),
        PayloadJson: r.GetString(4),
        DeliveryStatus: r.GetString(5),
        Attempts: r.GetInt32(6),
        NextAttemptAt: r.IsDBNull(7) ? null : DateTime.Parse(r.GetString(7)).ToUniversalTime(),
        LastAttemptAt: r.IsDBNull(8) ? null : DateTime.Parse(r.GetString(8)).ToUniversalTime(),
        LastError: r.IsDBNull(9) ? null : r.GetString(9)
    );

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
