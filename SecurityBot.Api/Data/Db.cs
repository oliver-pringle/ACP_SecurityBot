using Microsoft.Data.Sqlite;

namespace SecurityBot.Api.Data;

public class Db
{
    private readonly string _connectionString;

    public Db(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("ConnectionStrings:Sqlite not configured");
    }

    public SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        // busy_timeout is per-connection (resets on each Open). Wait up to 5s
        // on writer contention instead of throwing SQLITE_BUSY immediately.
        // Especially important for BSB: the TickScheduler worker writes
        // concurrently with sidecar-driven hires through SubscriptionRepository.
        // WAL mode is file-level and set once in InitializeSchemaAsync.
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    public async Task InitializeSchemaAsync()
    {
        await using var conn = OpenConnection();
        await using var cmd = conn.CreateCommand();
        // WAL is persistent at the file level — set once, sticks across
        // restarts. Lets readers and writers run concurrently (only
        // writer-writer is serialised through a small WAL file). Critical
        // for BSB because the TickScheduler fans out up to MaxConcurrent=8
        // webhook deliveries in parallel, each writing back run state.
        // Requires the SQLite file to live on local disk (not NFS/SMB).
        cmd.CommandText = "PRAGMA journal_mode = WAL;";
        await cmd.ExecuteNonQueryAsync();

        // webhook_url / webhook_secret stay NOT NULL on disk for backwards
        // compat with existing dev databases — inJobStream rows persist empty
        // strings instead of NULL, and the repository projects empty → null
        // on read so callers see Subscription.WebhookUrl as nullable.
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS subscriptions (
                id                   TEXT PRIMARY KEY,
                job_id               TEXT NOT NULL UNIQUE,
                buyer_agent          TEXT NOT NULL,
                offering_name        TEXT NOT NULL,
                requirement_json     TEXT NOT NULL,
                webhook_url          TEXT NOT NULL,
                webhook_secret       TEXT NOT NULL,
                interval_seconds     INTEGER NOT NULL,
                ticks_purchased      INTEGER NOT NULL,
                ticks_delivered      INTEGER NOT NULL DEFAULT 0,
                created_at           TEXT NOT NULL,
                expires_at           TEXT NOT NULL,
                last_run_at          TEXT,
                next_run_at          TEXT NOT NULL,
                status               TEXT NOT NULL,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                push_mode            TEXT NOT NULL DEFAULT 'webhook',
                stream_chain_id      INTEGER,
                stream_job_id        TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_subs_due ON subscriptions(status, next_run_at);

            CREATE TABLE IF NOT EXISTS subscription_runs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
                tick_number     INTEGER NOT NULL,
                scheduled_at    TEXT NOT NULL,
                payload_json    TEXT NOT NULL,
                delivery_status TEXT NOT NULL,
                attempts        INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                last_attempt_at TEXT,
                last_error      TEXT,
                UNIQUE(subscription_id, tick_number)
            );
            CREATE INDEX IF NOT EXISTS ix_runs_retry ON subscription_runs(delivery_status, next_attempt_at);

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
            CREATE INDEX IF NOT EXISTS ix_email_agent ON email_log(agent_address);";
        await cmd.ExecuteNonQueryAsync();

        // Idempotent in-place migrations for databases created before PushMode
        // landed. PRAGMA table_info is cheap and ALTER TABLE ADD COLUMN with a
        // default is non-destructive on SQLite.
        await EnsureColumnAsync(conn, "subscriptions", "push_mode",       "TEXT NOT NULL DEFAULT 'webhook'");
        await EnsureColumnAsync(conn, "subscriptions", "stream_chain_id", "INTEGER");
        await EnsureColumnAsync(conn, "subscriptions", "stream_job_id",   "TEXT");
    }

    private static async Task EnsureColumnAsync(
        SqliteConnection conn, string table, string column, string definition)
    {
        await using (var check = conn.CreateCommand())
        {
            check.CommandText = $"PRAGMA table_info({table});";
            await using var reader = await check.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                    return;
            }
        }
        await using var alter = conn.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {definition};";
        await alter.ExecuteNonQueryAsync();
    }
}
