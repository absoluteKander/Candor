//! Local SQLite index of synced message metadata. The daemon is the sole
//! writer (WAL mode lets the GUI read concurrently without blocking it).
//! Message bodies are not stored here — only what's needed to render a
//! message list; bodies are fetched on demand when a message is opened.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

pub fn db_path() -> Result<PathBuf> {
    dirs::data_dir()
        .map(|p| p.join("candor").join("candor.db"))
        .context("could not resolve XDG data directory")
}

pub fn open() -> Result<Connection> {
    let path = db_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating data dir {}", dir.display()))?;
    }

    let conn = Connection::open(&path)
        .with_context(|| format!("opening database at {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enabling WAL mode")?;

    apply_schema(&conn)?;
    Ok(conn)
}

/// Creates every table (if not already present) and applies best-effort
/// migrations — split out from `open()` so tests can apply the exact
/// same schema to an in-memory connection instead of a real on-disk
/// database. WAL mode is deliberately not part of this (it's
/// meaningless for a single in-process `:memory:` connection, and
/// `open()` already sets it up separately for the real on-disk case).
fn apply_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS folder_state (
            account_id   TEXT NOT NULL,
            folder       TEXT NOT NULL,
            uid_validity INTEGER,
            last_uid     INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (account_id, folder)
        );

        CREATE TABLE IF NOT EXISTS messages (
            account_id   TEXT NOT NULL,
            folder       TEXT NOT NULL,
            uid          INTEGER NOT NULL,
            message_id   TEXT,
            subject      TEXT,
            from_name    TEXT,
            from_address TEXT,
            date         INTEGER,
            seen         INTEGER NOT NULL DEFAULT 0,
            flagged      INTEGER NOT NULL DEFAULT 0,
            size         INTEGER,
            pending_push   INTEGER NOT NULL DEFAULT 0,
            snoozed_until  INTEGER,
            PRIMARY KEY (account_id, folder, uid)
        );

        CREATE INDEX IF NOT EXISTS messages_by_date
            ON messages (account_id, folder, date DESC);

        CREATE TABLE IF NOT EXISTS pending_moves (
            account_id TEXT NOT NULL,
            folder     TEXT NOT NULL,
            uid        INTEGER NOT NULL,
            to_folder  TEXT NOT NULL,
            PRIMARY KEY (account_id, folder, uid)
        );

        -- Searchable plain-text body cache, keyed by `message_id` (not
        -- folder/uid — a move assigns a brand-new uid at the
        -- destination, but message_id survives unchanged; see
        -- `cache_message_body`'s doc comment). `date` is the message's
        -- own date (receipt date for incoming mail, send time for
        -- outgoing), used by `evict_expired_bodies` for age-based
        -- retention — not when the row was cached. `exempt` rows
        -- (starred mail, anything the user sent) are never evicted by
        -- `evict_expired_bodies` regardless of age/size settings.
        CREATE TABLE IF NOT EXISTS message_bodies (
            account_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            body       TEXT NOT NULL,
            date       INTEGER,
            exempt     INTEGER NOT NULL DEFAULT 0,
            cached_at  INTEGER NOT NULL,
            PRIMARY KEY (account_id, message_id)
        );

        -- Messages queued for lazy background body-caching after being
        -- starred (see `queue_body_cache`) — picked up by the same
        -- pending-push background loop that already pushes flag/move
        -- changes, never fetched synchronously from a flag-change
        -- D-Bus call itself.
        CREATE TABLE IF NOT EXISTS pending_body_cache (
            account_id TEXT NOT NULL,
            folder     TEXT NOT NULL,
            uid        INTEGER NOT NULL,
            PRIMARY KEY (account_id, folder, uid)
        );

        -- Contacts for compose autocomplete (Group 6) — `address` is
        -- the lookup key (case-insensitive: email addresses aren't
        -- meaningfully case-sensitive in practice). `source` is
        -- informational only ('sent'/'manual'/'csv'), not a ranking
        -- factor — see `upsert_contact`'s doc comment for why. Every
        -- write path (sent-mail auto-harvest, the reading pane's
        -- opt-in add button, CSV import) goes through the same
        -- `upsert_contact` function.
        CREATE TABLE IF NOT EXISTS contacts (
            account_id TEXT NOT NULL,
            address    TEXT NOT NULL COLLATE NOCASE,
            name       TEXT,
            source     TEXT NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 0,
            last_seen  INTEGER,
            PRIMARY KEY (account_id, address)
        );
        ",
    )
    .context("creating schema")?;

    // Best-effort migration for DBs created before special_use existed —
    // SQLite has no "ADD COLUMN IF NOT EXISTS", so just ignore the
    // "duplicate column" error on a DB that already has it.
    let _ = conn.execute("ALTER TABLE folder_state ADD COLUMN special_use TEXT", []);
    let _ =
        conn.execute("ALTER TABLE messages ADD COLUMN pending_push INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN snoozed_until INTEGER", []);

    Ok(())
}

#[cfg(test)]
fn test_conn() -> Connection {
    let conn = Connection::open_in_memory().expect("opening in-memory test database");
    apply_schema(&conn).expect("applying schema to in-memory test database");
    conn
}

#[derive(Debug, Clone, Default)]
pub struct FolderState {
    pub uid_validity: Option<u32>,
    pub last_uid: u32,
    /// The IMAP SPECIAL-USE attribute (RFC 6154), e.g. `\Sent`/`\Drafts`/
    /// `\Trash`, if the server tagged this folder with one. Used to label
    /// and order standard folders consistently regardless of what the
    /// provider actually named them (Gmail's "[Gmail]/Sent Mail" vs. a
    /// generic server's "Sent Items", etc.) — `None` for a folder with no
    /// recognized special use (a user-created label/folder).
    pub special_use: Option<String>,
}

pub fn folder_state(conn: &Connection, account_id: &str, folder: &str) -> Result<Option<FolderState>> {
    conn.query_row(
        "SELECT uid_validity, last_uid, special_use FROM folder_state WHERE account_id = ?1 AND folder = ?2",
        params![account_id, folder],
        |row| {
            Ok(FolderState {
                uid_validity: row.get(0)?,
                last_uid: row.get(1)?,
                special_use: row.get(2)?,
            })
        },
    )
    .optional()
    .context("reading folder state")
}

pub fn set_folder_state(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    state: FolderState,
) -> Result<()> {
    conn.execute(
        "INSERT INTO folder_state (account_id, folder, uid_validity, last_uid, special_use)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(account_id, folder) DO UPDATE SET
            uid_validity = excluded.uid_validity,
            last_uid = excluded.last_uid,
            special_use = excluded.special_use",
        params![account_id, folder, state.uid_validity, state.last_uid, state.special_use],
    )
    .context("saving folder state")?;
    Ok(())
}

/// Wipes cached messages for a folder — used when the server's UIDVALIDITY
/// changes, meaning previously cached UIDs no longer mean anything.
pub fn clear_folder(conn: &Connection, account_id: &str, folder: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM messages WHERE account_id = ?1 AND folder = ?2",
        params![account_id, folder],
    )
    .context("clearing folder")?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct FolderInfo {
    pub name: String,
    pub special_use: Option<String>,
    pub unread: u32,
}

/// Every folder that has been synced at least once for this account, with
/// its SPECIAL-USE tag (if any) and unread count — in whatever order the
/// server reports them; callers normalize names/ordering for display.
pub fn list_folders(conn: &Connection, account_id: &str) -> Result<Vec<FolderInfo>> {
    let mut stmt = conn
        .prepare(
            "SELECT fs.folder, fs.special_use, COALESCE(u.unread, 0)
             FROM folder_state fs
             LEFT JOIN (
                 SELECT folder, COUNT(*) AS unread FROM messages
                 WHERE account_id = ?1 AND seen = 0
                     AND (snoozed_until IS NULL OR snoozed_until <= strftime('%s','now'))
                 GROUP BY folder
             ) u ON u.folder = fs.folder
             WHERE fs.account_id = ?1
             ORDER BY fs.folder",
        )
        .context("preparing folder list query")?;

    let rows = stmt
        .query_map(params![account_id], |row| {
            Ok(FolderInfo {
                name: row.get(0)?,
                special_use: row.get(1)?,
                unread: row.get(2)?,
            })
        })
        .context("querying folders")?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading folder rows")
}

#[derive(Debug, Clone, Default)]
pub struct NewMessage {
    pub uid: u32,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from_name: Option<String>,
    pub from_address: Option<String>,
    pub date: Option<i64>,
    pub seen: bool,
    pub flagged: bool,
    pub size: Option<u32>,
}

/// Every UID currently cached for this account+folder, most recent
/// first and capped at `limit` — used to re-check flags for messages
/// already synced (see `sync::sync_once`'s flag-refresh pass). Capped
/// rather than unbounded since re-fetching flags for a folder's entire
/// history on every sync would only get more expensive as the cache
/// grows, for UIDs that have long since scrolled out of what the GUI
/// even shows.
pub fn recent_uids(conn: &Connection, account_id: &str, folder: &str, limit: u32) -> Result<Vec<u32>> {
    let mut stmt = conn
        .prepare(
            "SELECT uid FROM messages WHERE account_id = ?1 AND folder = ?2
             ORDER BY date DESC LIMIT ?3",
        )
        .context("preparing recent-UIDs query")?;
    let rows = stmt
        .query_map(params![account_id, folder, limit], |row| row.get::<_, u32>(0))
        .context("querying recent UIDs")?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading UID rows")
}

/// Updates just the `\Seen`/`\Flagged` state for an already-cached
/// message — unlike `upsert_message`, this never touches subject/from/
/// date/etc., since a flags-only `UID FETCH ... (FLAGS)` (see
/// `sync::sync_once`) never has those values to begin with, and
/// overwriting them with nothing would blank out data a fuller fetch
/// already captured.
pub fn update_flags(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    uid: u32,
    seen: bool,
    flagged: bool,
) -> Result<()> {
    // Never overwrite a row the GUI has queued a not-yet-pushed local
    // change for (`pending_push = 1`) — this is what a server-side
    // flag-refresh (see `sync::sync_once`) writes, and without this
    // guard it would silently revert an optimistic local star/read
    // toggle back to the stale pre-change server state for however
    // long it takes `push_pending_flags` to actually get around to
    // pushing it.
    conn.execute(
        "UPDATE messages SET seen = ?1, flagged = ?2
         WHERE account_id = ?3 AND folder = ?4 AND uid = ?5 AND pending_push = 0",
        params![seen as i64, flagged as i64, account_id, folder, uid],
    )
    .context("updating message flags")?;
    Ok(())
}

/// A single message's current `(seen, flagged)` — needed before queuing
/// a pending flag change for just *one* of the two (e.g. `mark_read`
/// only ever means to touch `\Seen`), since `update_flags_pending`
/// writes both columns and would otherwise clobber whichever one the
/// caller didn't mean to change.
pub fn get_flags(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<Option<(bool, bool)>> {
    conn.query_row(
        "SELECT seen, flagged FROM messages WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
        params![account_id, folder, uid],
        |row| Ok((row.get::<_, i64>(0)? != 0, row.get::<_, i64>(1)? != 0)),
    )
    .optional()
    .context("reading message flags")
}

/// Sets a message's `seen`/`flagged` state locally *and* marks it
/// `pending_push` — the optimistic-update half of the local-first flag
/// flow: the GUI sees this instantly (one local write, no network),
/// and `push_pending_flags` picks it up on its own unhurried schedule
/// to actually tell the server.
pub fn update_flags_pending(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    uid: u32,
    seen: bool,
    flagged: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE messages SET seen = ?1, flagged = ?2, pending_push = 1
         WHERE account_id = ?3 AND folder = ?4 AND uid = ?5",
        params![seen as i64, flagged as i64, account_id, folder, uid],
    )
    .context("queuing pending message flags")?;
    Ok(())
}

/// Every `(folder, uid, seen, flagged)` still waiting to be pushed to
/// the server for this account, across all folders.
pub fn pending_pushes(conn: &Connection, account_id: &str) -> Result<Vec<(String, u32, bool, bool)>> {
    let mut stmt = conn
        .prepare(
            "SELECT folder, uid, seen, flagged FROM messages
             WHERE account_id = ?1 AND pending_push = 1",
        )
        .context("preparing pending-pushes query")?;
    let rows = stmt
        .query_map(params![account_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, i64>(3)? != 0,
            ))
        })
        .context("querying pending pushes")?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading pending-push rows")
}

/// Clears `pending_push` once `push_pending_flags` has confirmed the
/// server actually has the change — takes a UID set rather than one at
/// a time since a whole batch gets cleared together after one
/// successful `STORE`.
pub fn clear_pending_push(conn: &Connection, account_id: &str, folder: &str, uids: &[u32]) -> Result<()> {
    for uid in uids {
        conn.execute(
            "UPDATE messages SET pending_push = 0
             WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
            params![account_id, folder, uid],
        )
        .context("clearing pending_push")?;
    }
    Ok(())
}

/// Schedules a message to disappear from view until `wake_at` (unix
/// seconds), then resurface — "an alarm for email". Purely local: no
/// IMAP flag or folder corresponds to "snoozed", so this never touches
/// the network at all, in either direction. `list_messages`/
/// `list_folders`' unread count both already filter out anything whose
/// `snoozed_until` is still in the future, so setting this is enough
/// on its own to hide the message immediately.
pub fn snooze_message(conn: &Connection, account_id: &str, folder: &str, uid: u32, wake_at: i64) -> Result<()> {
    conn.execute(
        "UPDATE messages SET snoozed_until = ?1 WHERE account_id = ?2 AND folder = ?3 AND uid = ?4",
        params![wake_at, account_id, folder, uid],
    )
    .context("snoozing message")?;
    Ok(())
}

/// Cancels a pending snooze, making the message visible again right away.
pub fn unsnooze_message(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<()> {
    conn.execute(
        "UPDATE messages SET snoozed_until = NULL WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
        params![account_id, folder, uid],
    )
    .context("unsnoozing message")?;
    Ok(())
}

/// Clears `snoozed_until` for every message whose wake time has passed,
/// and marks each one unread again — the "alarm went off" moment: a
/// snoozed message resurfacing silently wouldn't actually draw any
/// attention back to it, which defeats the point. `list_messages`
/// already hides anything not-yet-due on its own (via a `snoozed_until
/// <= now` check in the query), so this isn't what makes a message
/// reappear — it's what makes it demand attention once it does.
/// Returns how many were woken, for logging.
pub fn wake_due_snoozes(conn: &Connection, account_id: &str) -> Result<usize> {
    let count = conn.execute(
        "UPDATE messages SET snoozed_until = NULL, seen = 0
         WHERE account_id = ?1 AND snoozed_until IS NOT NULL AND snoozed_until <= strftime('%s','now')",
        params![account_id],
    )
    .context("waking due snoozes")?;
    Ok(count)
}

/// A message currently waiting to wake up — the "Snoozed" view's whole
/// reason for existing is being able to see (and cancel) these before
/// they fire, since once a message is snoozed it's otherwise invisible
/// everywhere until it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnoozedMessage {
    /// The real folder the message actually lives in (a snooze spans
    /// every folder, not just one, so — unlike `list_messages`, which
    /// is already scoped to a single folder by its caller — each row
    /// here has to carry its own).
    pub folder: String,
    pub uid: u32,
    pub subject: Option<String>,
    pub wake_at: i64,
}

/// Every currently-snoozed message for this account, across every
/// folder, soonest-waking first.
pub fn list_snoozed(conn: &Connection, account_id: &str) -> Result<Vec<SnoozedMessage>> {
    let mut stmt = conn
        .prepare(
            "SELECT folder, uid, subject, snoozed_until FROM messages
             WHERE account_id = ?1 AND snoozed_until IS NOT NULL
             ORDER BY snoozed_until ASC",
        )
        .context("preparing snoozed-messages query")?;
    let rows = stmt
        .query_map(params![account_id], |row| {
            Ok(SnoozedMessage {
                folder: row.get(0)?,
                uid: row.get(1)?,
                subject: row.get(2)?,
                wake_at: row.get(3)?,
            })
        })
        .context("querying snoozed messages")?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading snoozed-message rows")
}

pub fn upsert_message(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    msg: &NewMessage,
) -> Result<()> {
    conn.execute(
        "INSERT INTO messages
            (account_id, folder, uid, message_id, subject, from_name, from_address, date, seen, flagged, size)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(account_id, folder, uid) DO UPDATE SET
            message_id = excluded.message_id,
            subject = excluded.subject,
            from_name = excluded.from_name,
            from_address = excluded.from_address,
            date = excluded.date,
            seen = excluded.seen,
            flagged = excluded.flagged,
            size = excluded.size",
        params![
            account_id,
            folder,
            msg.uid,
            msg.message_id,
            msg.subject,
            msg.from_name,
            msg.from_address,
            msg.date,
            msg.seen as i64,
            msg.flagged as i64,
            msg.size,
        ],
    )
    .context("upserting message")?;
    Ok(())
}

/// Queues a move to `to_folder` and removes the message from its
/// current folder's local cache immediately — the same local-first
/// trade as `update_flags_pending`: from the GUI's perspective the
/// message is just gone from this list right away (no waiting on a
/// live IMAP `MOVE`), and `push_pending_moves` does the actual network
/// work later. Safe to let the row simply vanish rather than also
/// inserting it into the target folder's cache: the target folder's
/// own next regular sync will pick it up on its own, the same way any
/// other new-to-that-folder message would.
pub fn queue_move(conn: &Connection, account_id: &str, folder: &str, uid: u32, to_folder: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO pending_moves (account_id, folder, uid, to_folder) VALUES (?1,?2,?3,?4)
         ON CONFLICT(account_id, folder, uid) DO UPDATE SET to_folder = excluded.to_folder",
        params![account_id, folder, uid, to_folder],
    )
    .context("queuing pending move")?;
    conn.execute(
        "DELETE FROM messages WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
        params![account_id, folder, uid],
    )
    .context("removing moved message from local cache")?;
    Ok(())
}

/// Every queued-but-not-yet-pushed move for this account:
/// `(from_folder, uid, to_folder)`.
pub fn pending_moves(conn: &Connection, account_id: &str) -> Result<Vec<(String, u32, String)>> {
    let mut stmt = conn
        .prepare("SELECT folder, uid, to_folder FROM pending_moves WHERE account_id = ?1")
        .context("preparing pending-moves query")?;
    let rows = stmt
        .query_map(params![account_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?, row.get::<_, String>(2)?))
        })
        .context("querying pending moves")?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading pending-move rows")
}

/// Clears queued moves once `push_pending_moves` has confirmed the
/// server actually has them — a UID set per `(from_folder, to_folder)`
/// pair, since that's how they get pushed (one batched `UID MOVE` per
/// pair) and cleared together.
pub fn clear_pending_moves(
    conn: &Connection,
    account_id: &str,
    from_folder: &str,
    uids: &[u32],
) -> Result<()> {
    for uid in uids {
        conn.execute(
            "DELETE FROM pending_moves WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
            params![account_id, from_folder, uid],
        )
        .context("clearing pending move")?;
    }
    Ok(())
}

/// Removes specific messages from the local cache outright — used when
/// a sync confirms they no longer exist in the folder on the server
/// (deleted/archived/spam-marked through Gmail's web UI, another
/// client, anything other than this app's own queued moves, which
/// already remove the local row themselves). Without this, a message
/// gone from the server just sits in the local cache forever, showing
/// up as a message that "isn't really there."
pub fn delete_messages(conn: &Connection, account_id: &str, folder: &str, uids: &[u32]) -> Result<()> {
    for uid in uids {
        conn.execute(
            "DELETE FROM messages WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
            params![account_id, folder, uid],
        )
        .context("deleting stale cached message")?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    pub uid: u32,
    pub subject: Option<String>,
    pub from_name: Option<String>,
    pub from_address: Option<String>,
    pub date: Option<i64>,
    pub seen: bool,
    pub flagged: bool,
}

/// A message's `message_id`/`date` by `(folder, uid)` — the lookup
/// every body-caching call site uses to get the canonical join key for
/// `message_bodies`, rather than trusting a freshly re-parsed
/// `Message-ID` header from the GUI's own MIME parse. Those two don't
/// necessarily agree on formatting (e.g. whether it's wrapped in angle
/// brackets), so anything that writes into `message_bodies` reads the
/// key back from here instead. Returns `None` if the message isn't
/// cached, or has no `Message-ID` header at all (rare, but then there's
/// no stable key to cache its body under).
pub fn message_id_for(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    uid: u32,
) -> Result<Option<(String, Option<i64>)>> {
    conn.query_row(
        "SELECT message_id, date FROM messages
         WHERE account_id = ?1 AND folder = ?2 AND uid = ?3 AND message_id IS NOT NULL",
        params![account_id, folder, uid],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
    )
    .optional()
    .context("reading message_id for body cache")
}

/// Caches a message's extracted plain-text body for search, keyed by
/// `message_id` so it survives an ordinary move (which assigns a new
/// uid at the destination folder — see the `message_bodies` schema
/// comment). `exempt` is sticky: once a row is marked exempt (cached via
/// starring or via the user's own sent/reply/reply-all mail), a later
/// call with `exempt = false` (e.g. caching the same message again via
/// the ordinary open-to-read path) never downgrades it back to
/// evictable — there's no case where the user asked for that, and
/// erring toward "stays searchable longer" is the safer default.
pub fn cache_message_body(
    conn: &Connection,
    account_id: &str,
    message_id: &str,
    body: &str,
    date: Option<i64>,
    exempt: bool,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO message_bodies (account_id, message_id, body, date, exempt, cached_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(account_id, message_id) DO UPDATE SET
            body = excluded.body,
            date = excluded.date,
            exempt = exempt OR excluded.exempt,
            cached_at = excluded.cached_at",
        params![account_id, message_id, body, date, exempt as i64, now],
    )
    .context("caching message body")?;
    Ok(())
}

/// Removes a message's cached body (if any) — used when a message is
/// trashed or moved to Junk. A no-op if nothing was cached for it,
/// which is the common case (most messages never get opened, starred,
/// or sent).
pub fn purge_message_body(conn: &Connection, account_id: &str, message_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM message_bodies WHERE account_id = ?1 AND message_id = ?2",
        params![account_id, message_id],
    )
    .context("purging message body")?;
    Ok(())
}

/// Queues `(folder, uid)` for lazy background body-caching — written
/// when a message is starred, picked up later by the same background
/// loop that pushes flag/move changes (`push_pending_flags`'s sibling;
/// see `candor-daemon`'s `PENDING_PUSH_INTERVAL` loop), never fetched
/// synchronously from the `mark_flagged` D-Bus call itself.
pub fn queue_body_cache(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<()> {
    conn.execute(
        "INSERT INTO pending_body_cache (account_id, folder, uid) VALUES (?1, ?2, ?3)
         ON CONFLICT(account_id, folder, uid) DO NOTHING",
        params![account_id, folder, uid],
    )
    .context("queuing body cache")?;
    Ok(())
}

/// Every `(folder, uid)` still waiting for its body to be cached.
pub fn pending_body_cache(conn: &Connection, account_id: &str) -> Result<Vec<(String, u32)>> {
    let mut stmt = conn
        .prepare("SELECT folder, uid FROM pending_body_cache WHERE account_id = ?1")
        .context("preparing pending-body-cache query")?;
    let rows = stmt
        .query_map(params![account_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })
        .context("querying pending body cache")?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading pending-body-cache rows")
}

/// Clears one queued body-cache entry, whether or not the fetch actually
/// succeeded in caching anything — a message that's since been deleted,
/// moved to Junk, or otherwise vanished before the background loop got
/// to it just drops out of the queue rather than being retried forever.
pub fn clear_pending_body_cache(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<()> {
    conn.execute(
        "DELETE FROM pending_body_cache WHERE account_id = ?1 AND folder = ?2 AND uid = ?3",
        params![account_id, folder, uid],
    )
    .context("clearing pending body cache")?;
    Ok(())
}

/// Local full-text-ish search (plain `LIKE`, not FTS5 — revisit only if
/// this is ever actually slow) over subject/from/body. `folder = None`
/// searches every folder for the account; `Some(folder)` scopes to just
/// that one — the user-facing breadth toggle. Matches on body only for
/// messages that happen to have a cached one (most won't — see
/// `message_bodies`'s caching policy); subject/from matching never
/// depends on caching at all. Capped at `limit`, newest first, same
/// shape as `list_messages`.
pub fn search_messages(
    conn: &Connection,
    account_id: &str,
    folder: Option<&str>,
    query: &str,
    limit: u32,
) -> Result<Vec<MessageSummary>> {
    let pattern = format!("%{}%", query.replace('%', "%%"));
    let sql = "SELECT m.uid, m.subject, m.from_name, m.from_address, m.date, m.seen, m.flagged
         FROM messages m
         LEFT JOIN message_bodies b ON b.account_id = m.account_id AND b.message_id = m.message_id
         WHERE m.account_id = ?1
             AND (?2 IS NULL OR m.folder = ?2)
             AND (m.snoozed_until IS NULL OR m.snoozed_until <= strftime('%s','now'))
             AND (m.subject LIKE ?3 OR m.from_name LIKE ?3 OR m.from_address LIKE ?3 OR b.body LIKE ?3)
         ORDER BY m.date DESC LIMIT ?4";

    let mut stmt = conn.prepare(sql).context("preparing search query")?;
    let rows = stmt
        .query_map(params![account_id, folder, pattern, limit], |row| {
            Ok(MessageSummary {
                uid: row.get(0)?,
                subject: row.get(1)?,
                from_name: row.get(2)?,
                from_address: row.get(3)?,
                date: row.get(4)?,
                seen: row.get::<_, i64>(5)? != 0,
                flagged: row.get::<_, i64>(6)? != 0,
            })
        })
        .context("querying search results")?;

    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading search rows")
}

/// Applies the retention sweep: deletes non-exempt cached bodies older
/// than `max_age_days` (by the message's own `date`, i.e. "days after
/// receipt" — not when it was cached), then, if `max_size_bytes` is
/// set and the non-exempt total is still over it, deletes the oldest
/// (by `date`) non-exempt rows one at a time until it isn't. Either cap
/// left as `None` is simply skipped. Exempt rows (starred, sent) are
/// never touched by either pass. Returns the number of rows evicted.
pub fn evict_expired_bodies(
    conn: &Connection,
    account_id: &str,
    max_age_days: Option<u32>,
    max_size_bytes: Option<u64>,
) -> Result<usize> {
    let mut evicted = 0usize;

    if let Some(days) = max_age_days {
        let cutoff_secs = days as i64 * 86_400;
        evicted += conn
            .execute(
                "DELETE FROM message_bodies
                 WHERE account_id = ?1 AND exempt = 0
                     AND date IS NOT NULL AND date < (strftime('%s','now') - ?2)",
                params![account_id, cutoff_secs],
            )
            .context("evicting aged-out bodies")?;
    }

    if let Some(cap) = max_size_bytes {
        loop {
            let total: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(LENGTH(body)), 0) FROM message_bodies
                     WHERE account_id = ?1 AND exempt = 0",
                    params![account_id],
                    |row| row.get(0),
                )
                .context("summing cached body size")?;
            if total as u64 <= cap {
                break;
            }

            let oldest: Option<String> = conn
                .query_row(
                    "SELECT message_id FROM message_bodies
                     WHERE account_id = ?1 AND exempt = 0
                     ORDER BY date ASC LIMIT 1",
                    params![account_id],
                    |row| row.get(0),
                )
                .optional()
                .context("finding oldest cached body")?;
            let Some(message_id) = oldest else { break };

            conn.execute(
                "DELETE FROM message_bodies WHERE account_id = ?1 AND message_id = ?2",
                params![account_id, message_id],
            )
            .context("evicting oldest body for size cap")?;
            evicted += 1;
        }
    }

    Ok(evicted)
}

pub fn list_messages(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    limit: u32,
) -> Result<Vec<MessageSummary>> {
    let mut stmt = conn
        .prepare(
            "SELECT uid, subject, from_name, from_address, date, seen, flagged
             FROM messages WHERE account_id = ?1 AND folder = ?2
                 AND (snoozed_until IS NULL OR snoozed_until <= strftime('%s','now'))
             ORDER BY date DESC LIMIT ?3",
        )
        .context("preparing message list query")?;

    let rows = stmt
        .query_map(params![account_id, folder, limit], |row| {
            Ok(MessageSummary {
                uid: row.get(0)?,
                subject: row.get(1)?,
                from_name: row.get(2)?,
                from_address: row.get(3)?,
                date: row.get(4)?,
                seen: row.get::<_, i64>(5)? != 0,
                flagged: row.get::<_, i64>(6)? != 0,
            })
        })
        .context("querying messages")?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading message rows")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub address: String,
    pub name: Option<String>,
    pub times_seen: u32,
}

/// Records that `address` was seen (sent to, explicitly added from the
/// reading pane, or imported from a CSV) — every contact-writing path
/// in this app goes through this one function. `source` is kept purely
/// as metadata (`'sent'`/`'manual'`/`'csv'`) and never affects ranking
/// or eviction: unlike the mark-read-vs-starred distinction in
/// `message_bodies`, there's no noisy-source problem left to solve
/// here, since the one noisy path (auto-harvesting Reply/Reply-All
/// recipients) was deliberately never built — see
/// `candor_group6_contacts_plan` in memory for why. `name` only
/// overwrites the stored name when a non-empty one is given, so a
/// later call that doesn't know the name (e.g. CSV rows with no name
/// column) never blanks out one already on file.
pub fn upsert_contact(
    conn: &Connection,
    account_id: &str,
    address: &str,
    name: Option<&str>,
    source: &str,
    seen_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO contacts (account_id, address, name, source, times_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, 1, ?5)
         ON CONFLICT(account_id, address) DO UPDATE SET
            name = COALESCE(NULLIF(excluded.name, ''), name),
            times_seen = times_seen + 1,
            last_seen = MAX(COALESCE(last_seen, 0), excluded.last_seen)",
        params![account_id, address, name, source, seen_at],
    )
    .context("upserting contact")?;
    Ok(())
}

/// Autocomplete lookup — matches `query` against either the address or
/// the name, ranked by how often/recently that contact's been seen
/// (regardless of which path put them there). Empty `query` returns
/// the account's most-contacted people, which is also a reasonable
/// thing to show the moment the To field gets focus, before any
/// typing.
pub fn search_contacts(conn: &Connection, account_id: &str, query: &str, limit: u32) -> Result<Vec<Contact>> {
    let pattern = format!("%{}%", query.replace('%', "%%"));
    let mut stmt = conn
        .prepare(
            "SELECT address, name, times_seen FROM contacts
             WHERE account_id = ?1 AND (?2 = '' OR address LIKE ?3 OR name LIKE ?3)
             ORDER BY times_seen DESC, last_seen DESC LIMIT ?4",
        )
        .context("preparing contact search query")?;
    let rows = stmt
        .query_map(params![account_id, query, pattern, limit], |row| {
            Ok(Contact {
                address: row.get(0)?,
                name: row.get(1)?,
                times_seen: row.get::<_, i64>(2)? as u32,
            })
        })
        .context("querying contacts")?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("reading contact rows")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "acct1";

    fn msg(uid: u32, subject: &str, date: i64) -> NewMessage {
        NewMessage {
            uid,
            message_id: Some(format!("<{uid}@example.com>")),
            subject: Some(subject.to_string()),
            from_name: Some("Someone".to_string()),
            from_address: Some("someone@example.com".to_string()),
            date: Some(date),
            seen: false,
            flagged: false,
            size: Some(100),
        }
    }

    #[test]
    fn folder_state_round_trips() {
        let conn = test_conn();
        assert!(folder_state(&conn, ACCOUNT, "INBOX").unwrap().is_none());

        set_folder_state(
            &conn,
            ACCOUNT,
            "INBOX",
            FolderState { uid_validity: Some(1), last_uid: 42, special_use: Some("\\Inbox".to_string()) },
        )
        .unwrap();
        let state = folder_state(&conn, ACCOUNT, "INBOX").unwrap().unwrap();
        assert_eq!(state.uid_validity, Some(1));
        assert_eq!(state.last_uid, 42);
        assert_eq!(state.special_use.as_deref(), Some("\\Inbox"));

        // Re-saving updates in place rather than erroring on the
        // existing primary key.
        set_folder_state(
            &conn,
            ACCOUNT,
            "INBOX",
            FolderState { uid_validity: Some(1), last_uid: 50, special_use: None },
        )
        .unwrap();
        assert_eq!(folder_state(&conn, ACCOUNT, "INBOX").unwrap().unwrap().last_uid, 50);
    }

    #[test]
    fn upsert_message_inserts_then_updates() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "Hello", 1000)).unwrap();

        let messages = list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].subject.as_deref(), Some("Hello"));
        assert!(!messages[0].seen);

        // A second upsert for the same (account, folder, uid) updates
        // the existing row rather than inserting a duplicate.
        let mut updated = msg(1, "Hello (edited)", 1000);
        updated.seen = true;
        upsert_message(&conn, ACCOUNT, "INBOX", &updated).unwrap();

        let messages = list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].subject.as_deref(), Some("Hello (edited)"));
        assert!(messages[0].seen);
    }

    #[test]
    fn list_messages_orders_newest_first_and_respects_limit() {
        let conn = test_conn();
        for (uid, date) in [(1, 100), (2, 300), (3, 200)] {
            upsert_message(&conn, ACCOUNT, "INBOX", &msg(uid, "s", date)).unwrap();
        }

        let messages = list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap();
        assert_eq!(messages.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![2, 3, 1]);

        let limited = list_messages(&conn, ACCOUNT, "INBOX", 2).unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn update_flags_pending_never_clobbered_by_a_plain_flag_refresh() {
        // This is the core local-first-instant guarantee: a server-side
        // flag refresh (`update_flags`) must never silently revert a
        // locally-queued, not-yet-pushed change (`update_flags_pending`)
        // back to the stale pre-change state.
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "s", 100)).unwrap();

        update_flags_pending(&conn, ACCOUNT, "INBOX", 1, true, true).unwrap();
        assert_eq!(get_flags(&conn, ACCOUNT, "INBOX", 1).unwrap(), Some((true, true)));

        // A sync's flag-refresh pass reports the server still thinks
        // it's unseen/unflagged — this must be ignored while the local
        // change is still pending.
        update_flags(&conn, ACCOUNT, "INBOX", 1, false, false).unwrap();
        assert_eq!(
            get_flags(&conn, ACCOUNT, "INBOX", 1).unwrap(),
            Some((true, true)),
            "a plain flag refresh must not clobber a pending local change"
        );

        // Once pushed and cleared, a refresh is free to apply again.
        clear_pending_push(&conn, ACCOUNT, "INBOX", &[1]).unwrap();
        update_flags(&conn, ACCOUNT, "INBOX", 1, false, false).unwrap();
        assert_eq!(get_flags(&conn, ACCOUNT, "INBOX", 1).unwrap(), Some((false, false)));
    }

    #[test]
    fn pending_pushes_tracks_and_clears() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "s", 100)).unwrap();
        assert!(pending_pushes(&conn, ACCOUNT).unwrap().is_empty());

        update_flags_pending(&conn, ACCOUNT, "INBOX", 1, true, false).unwrap();
        let pending = pending_pushes(&conn, ACCOUNT).unwrap();
        assert_eq!(pending, vec![("INBOX".to_string(), 1, true, false)]);

        clear_pending_push(&conn, ACCOUNT, "INBOX", &[1]).unwrap();
        assert!(pending_pushes(&conn, ACCOUNT).unwrap().is_empty());
    }

    #[test]
    fn queue_move_removes_row_immediately_and_tracks_pending() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "s", 100)).unwrap();

        queue_move(&conn, ACCOUNT, "INBOX", 1, "Archive").unwrap();

        // Local-first: the row vanishes from its source folder right
        // away, before any network push has happened.
        assert!(list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap().is_empty());
        assert_eq!(
            pending_moves(&conn, ACCOUNT).unwrap(),
            vec![("INBOX".to_string(), 1, "Archive".to_string())]
        );

        clear_pending_moves(&conn, ACCOUNT, "INBOX", &[1]).unwrap();
        assert!(pending_moves(&conn, ACCOUNT).unwrap().is_empty());
    }

    #[test]
    fn delete_messages_removes_stale_rows() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "s", 100)).unwrap();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(2, "s", 100)).unwrap();

        delete_messages(&conn, ACCOUNT, "INBOX", &[1]).unwrap();

        let remaining = list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap();
        assert_eq!(remaining.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn snoozed_messages_are_hidden_until_due() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "s", 100)).unwrap();

        let far_future = 4_102_444_800; // year 2100 — never due in this test
        snooze_message(&conn, ACCOUNT, "INBOX", 1, far_future).unwrap();

        assert!(list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap().is_empty());
        let snoozed = list_snoozed(&conn, ACCOUNT).unwrap();
        assert_eq!(snoozed.len(), 1);
        assert_eq!(snoozed[0].wake_at, far_future);

        unsnooze_message(&conn, ACCOUNT, "INBOX", 1).unwrap();
        assert_eq!(list_messages(&conn, ACCOUNT, "INBOX", 10).unwrap().len(), 1);
        assert!(list_snoozed(&conn, ACCOUNT).unwrap().is_empty());
    }

    #[test]
    fn wake_due_snoozes_only_wakes_the_past() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "due", 100)).unwrap();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(2, "not due", 100)).unwrap();

        snooze_message(&conn, ACCOUNT, "INBOX", 1, 1).unwrap(); // long past
        snooze_message(&conn, ACCOUNT, "INBOX", 2, 4_102_444_800).unwrap(); // year 2100

        let woken = wake_due_snoozes(&conn, ACCOUNT).unwrap();
        assert_eq!(woken, 1);

        let snoozed = list_snoozed(&conn, ACCOUNT).unwrap();
        assert_eq!(snoozed.len(), 1);
        assert_eq!(snoozed[0].uid, 2);
    }

    #[test]
    fn message_body_cache_upsert_is_sticky_exempt() {
        let conn = test_conn();
        cache_message_body(&conn, ACCOUNT, "<a@example.com>", "first body", Some(100), false).unwrap();
        cache_message_body(&conn, ACCOUNT, "<a@example.com>", "starred now", Some(100), true).unwrap();

        // A later non-exempt write (e.g. simply re-opening the message)
        // must never downgrade a row that's already exempt — see
        // `cache_message_body`'s doc comment.
        cache_message_body(&conn, ACCOUNT, "<a@example.com>", "re-opened", Some(100), false).unwrap();
        assert!(
            is_exempt(&conn, "<a@example.com>"),
            "a later non-exempt write must not clear an already-exempt row"
        );

        // Confirmed behaviorally too: a same-day age cap would evict
        // every non-exempt cached body, but this one survives.
        let evicted = evict_expired_bodies(&conn, ACCOUNT, Some(0), None).unwrap();
        assert_eq!(evicted, 0);
        assert!(body_exists(&conn, "<a@example.com>"));
    }

    fn is_exempt(conn: &Connection, message_id: &str) -> bool {
        conn.query_row(
            "SELECT exempt FROM message_bodies WHERE account_id = ?1 AND message_id = ?2",
            params![ACCOUNT, message_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            != 0
    }

    #[test]
    fn search_messages_matches_subject_from_and_cached_body() {
        let conn = test_conn();
        upsert_message(&conn, ACCOUNT, "INBOX", &msg(1, "Quarterly report", 100)).unwrap();
        upsert_message(&conn, ACCOUNT, "Archive", &msg(2, "Totally unrelated", 200)).unwrap();
        cache_message_body(&conn, ACCOUNT, "<2@example.com>", "mentions rollover somewhere", Some(200), false)
            .unwrap();

        // Subject match, no body cached for it.
        let by_subject = search_messages(&conn, ACCOUNT, None, "quarterly", 10).unwrap();
        assert_eq!(by_subject.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![1]);

        // Body-only match, via the message_bodies join.
        let by_body = search_messages(&conn, ACCOUNT, None, "rollover", 10).unwrap();
        assert_eq!(by_body.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![2]);

        // Folder-scoped search excludes a match in a different folder.
        let scoped = search_messages(&conn, ACCOUNT, Some("INBOX"), "rollover", 10).unwrap();
        assert!(scoped.is_empty());
    }

    #[test]
    fn evict_expired_bodies_respects_age_and_size_caps() {
        let conn = test_conn();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        cache_message_body(&conn, ACCOUNT, "<old@example.com>", "old", Some(now - 100 * 86_400), false).unwrap();
        cache_message_body(&conn, ACCOUNT, "<new@example.com>", "new", Some(now), false).unwrap();

        let evicted = evict_expired_bodies(&conn, ACCOUNT, Some(30), None).unwrap();
        assert_eq!(evicted, 1, "only the 100-day-old body should be evicted by a 30-day cap");

        // Size cap: two more bodies (`<new@example.com>` from above is
        // still cached, size 3), total over a tiny cap — the oldest by
        // date goes first.
        cache_message_body(&conn, ACCOUNT, "<a@example.com>", "aaaaaaaaaa", Some(now - 1000), false).unwrap();
        cache_message_body(&conn, ACCOUNT, "<b@example.com>", "bbbbbbbbbb", Some(now), false).unwrap();
        let evicted = evict_expired_bodies(&conn, ACCOUNT, None, Some(15)).unwrap();
        assert_eq!(evicted, 1, "evicting just the oldest row should be enough to get under a 15-byte cap");
        assert!(!body_exists(&conn, "<a@example.com>"), "the oldest (by date) row should be the one evicted");
        assert!(body_exists(&conn, "<new@example.com>"));
        assert!(body_exists(&conn, "<b@example.com>"));
    }

    fn body_exists(conn: &Connection, message_id: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM message_bodies WHERE account_id = ?1 AND message_id = ?2",
            params![ACCOUNT, message_id],
            |_| Ok(()),
        )
        .optional()
        .unwrap()
        .is_some()
    }

    #[test]
    fn pending_body_cache_queue_is_idempotent_and_clears() {
        let conn = test_conn();
        queue_body_cache(&conn, ACCOUNT, "INBOX", 1).unwrap();
        queue_body_cache(&conn, ACCOUNT, "INBOX", 1).unwrap(); // duplicate, no error
        queue_body_cache(&conn, ACCOUNT, "INBOX", 2).unwrap();

        let mut pending = pending_body_cache(&conn, ACCOUNT).unwrap();
        pending.sort_by_key(|(_, uid)| *uid);
        assert_eq!(pending, vec![("INBOX".to_string(), 1), ("INBOX".to_string(), 2)]);

        clear_pending_body_cache(&conn, ACCOUNT, "INBOX", 1).unwrap();
        let pending = pending_body_cache(&conn, ACCOUNT).unwrap();
        assert_eq!(pending, vec![("INBOX".to_string(), 2)]);
    }

    #[test]
    fn upsert_contact_increments_and_keeps_existing_name() {
        let conn = test_conn();
        upsert_contact(&conn, ACCOUNT, "a@example.com", Some("Alice"), "sent", 100).unwrap();
        upsert_contact(&conn, ACCOUNT, "a@example.com", None, "sent", 200).unwrap();

        let found = search_contacts(&conn, ACCOUNT, "alice", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.as_deref(), Some("Alice"), "a later call with no name must not blank it out");
        assert_eq!(found[0].times_seen, 2);
    }

    #[test]
    fn search_contacts_matches_address_or_name_case_insensitively() {
        let conn = test_conn();
        upsert_contact(&conn, ACCOUNT, "Bob@Example.com", Some("Bob Smith"), "manual", 100).unwrap();

        assert_eq!(search_contacts(&conn, ACCOUNT, "bob@example", 10).unwrap().len(), 1);
        assert_eq!(search_contacts(&conn, ACCOUNT, "SMITH", 10).unwrap().len(), 1);
        assert_eq!(search_contacts(&conn, ACCOUNT, "nobody", 10).unwrap().len(), 0);
    }

    #[test]
    fn contacts_are_scoped_per_account() {
        let conn = test_conn();
        upsert_contact(&conn, "acct1", "shared@example.com", None, "sent", 100).unwrap();
        upsert_contact(&conn, "acct2", "shared@example.com", None, "sent", 100).unwrap();

        assert_eq!(search_contacts(&conn, "acct1", "", 10).unwrap().len(), 1);
        assert_eq!(search_contacts(&conn, "acct2", "", 10).unwrap().len(), 1);
    }
}
