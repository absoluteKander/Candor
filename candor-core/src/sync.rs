//! Pulls message headers for every selectable folder into the local
//! SQLite index. Bodies are not fetched here — only what a message list
//! needs; a message's body is fetched on demand (see [`crate::body`]).
//!
//! [`run`] is the long-lived background loop: connect once, sync every
//! folder, then IMAP IDLE on INBOX for push notifications (most servers
//! only push notifications for the selected folder, so INBOX — the one
//! that matters most for responsiveness — is what stays watched between
//! full resyncs), reconnecting with backoff if the connection drops.
//! [`sync_all`] is a one-shot connect-sync-disconnect, for a manual
//! "sync now" trigger.

use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result};
use mail_parser::MessageParser;
use native_tls::TlsStream;

use crate::body;
use crate::config::{AccountConfig, Security};
use crate::store::{self, FolderState, NewMessage};

const INBOX: &str = "INBOX";

/// Cap on how many historical messages a brand-new folder sync pulls in,
/// so the first sync of a large, years-old mailbox (or a folder like
/// Gmail's "All Mail") doesn't try to pull its entire history.
const INITIAL_SYNC_LIMIT: u32 = 200;

/// How many of a folder's most-recently-cached messages get their flags
/// re-checked on every sync (see `sync_once`'s flag-refresh pass).
/// Matches `candor-gui`'s own `MESSAGE_LIST_LIMIT` in spirit — no point
/// re-checking flags for messages the list view can't even show.
const FLAG_REFRESH_LIMIT: u32 = 100;

/// IMAP servers typically cap an IDLE session around 30 minutes; renew
/// comfortably before that regardless of whether a notification arrived.
const IDLE_TIMEOUT: Duration = Duration::from_secs(25 * 60);

pub(crate) type ImapSession = imap::Session<TlsStream<TcpStream>>;

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub new_or_updated: usize,
    /// True if the server's UIDVALIDITY changed, meaning previously cached
    /// messages (and any cached bodies) were wiped and this was
    /// effectively a fresh sync.
    pub resynced: bool,
    /// Newly-arrived messages from this sync that are still unread —
    /// the raw material for a desktop notification. Only ever populated
    /// for messages that just landed in the "genuinely new UID" loop in
    /// `sync_once`, never from the separate flag-refresh pass, so a
    /// message doesn't get notified about again just because its read
    /// state changed on another client.
    pub new_unseen: Vec<NewMailSummary>,
}

/// Enough about one newly-arrived, still-unread message to put in a
/// desktop notification — not the full `NewMessage`, since nothing past
/// this needs to reach `run`'s caller.
#[derive(Debug, Clone)]
pub struct NewMailSummary {
    pub subject: Option<String>,
    pub from_name: Option<String>,
    pub from_address: Option<String>,
}

/// One-shot connect, sync every folder, disconnect. Used for a manual
/// trigger. Returns `(folder, report)` for each folder synced.
pub async fn sync_all(account: AccountConfig, password: String) -> Result<Vec<(String, SyncReport)>> {
    tokio::task::spawn_blocking(move || {
        let mut session = connect_and_login(&account, &password)?;
        let reports = sync_all_folders(&mut session, &account)?;
        let _ = session.logout();
        Ok(reports)
    })
    .await
    .context("sync task panicked")?
}

/// One-shot connect, sync just this one folder, disconnect — for when
/// only one folder's state actually needs to be current right now (e.g.
/// right after saving a draft, where the new message only shows up in
/// Drafts). A full `sync_all` would mean waiting on every *other*
/// folder's sync too — fine for an explicit "Sync now", but needless
/// latency when only one folder's change is actually what someone's
/// waiting to see.
pub async fn sync_one_folder(account: AccountConfig, password: String, folder: String) -> Result<SyncReport> {
    tokio::task::spawn_blocking(move || {
        let mut session = connect_and_login(&account, &password)?;
        // `None` here is fine, not a loss of the folder's SPECIAL-USE
        // tag — `sync_once` falls back to whatever was already stored
        // for it when not given one explicitly.
        let report = sync_once(&mut session, &account, &folder, None)?;
        let _ = session.logout();
        Ok(report)
    })
    .await
    .context("single-folder sync task panicked")?
}

/// Runs forever: connect, sync every folder, IDLE on INBOX for changes,
/// resync, repeat. Reconnects with exponential backoff if the connection
/// drops. Intended to be spawned once as a background task for the
/// lifetime of the daemon. Whenever a sync finds new unread mail in
/// INBOX, the summaries go out on `new_mail_tx` — the caller decides
/// what to do with them (candor-daemon turns them into a desktop
/// notification); `run` itself knows nothing about D-Bus or
/// notifications, same reasoning as every other candor-core/candor-
/// daemon split in this codebase.
pub async fn run(account: AccountConfig, password: String, new_mail_tx: tokio::sync::mpsc::UnboundedSender<Vec<NewMailSummary>>) {
    let mut backoff = Duration::from_secs(5);
    loop {
        let acc = account.clone();
        let pw = password.clone();
        let tx = new_mail_tx.clone();

        let result = tokio::task::spawn_blocking(move || run_blocking(&acc, &pw, &tx)).await;

        match result {
            Ok(Ok(())) => unreachable!("run_blocking's loop only exits via Err"),
            Ok(Err(e)) => tracing::warn!(error = %e, "sync connection lost, reconnecting"),
            Err(e) => tracing::warn!(error = %e, "sync task panicked, reconnecting"),
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(300));
    }
}

/// Connects once, then loops sync+IDLE until the connection fails.
fn run_blocking(
    account: &AccountConfig,
    password: &str,
    new_mail_tx: &tokio::sync::mpsc::UnboundedSender<Vec<NewMailSummary>>,
) -> Result<()> {
    let mut session = connect_and_login(account, password)?;

    loop {
        for (folder, report) in sync_all_folders(&mut session, account)? {
            if report.new_or_updated > 0 || report.resynced {
                tracing::info!(
                    folder = %folder,
                    new_or_updated = report.new_or_updated,
                    resynced = report.resynced,
                    "folder synced"
                );
            }
            // Only INBOX — the same reasoning `sync_once`'s doc comment
            // gives for IDLE-watching it specifically: it's the one
            // folder worth interrupting someone for. Notifying for
            // every new Junk/Trash/other-folder message landing would
            // be noise, not signal.
            if folder == INBOX && !report.new_unseen.is_empty() {
                let _ = new_mail_tx.send(report.new_unseen);
            }
        }

        // IDLE watches whichever folder is currently selected; re-select
        // INBOX specifically since most servers only push notifications
        // for the selected mailbox and INBOX is the one worth watching
        // live between full resyncs.
        session
            .select(INBOX)
            .map_err(|e| anyhow::anyhow!("selecting INBOX failed: {e}"))?;

        let idle = session
            .idle()
            .map_err(|e| anyhow::anyhow!("entering IDLE failed: {e}"))?;
        idle.wait_with_timeout(idle_timeout())
            .map_err(|e| anyhow::anyhow!("IDLE wait failed: {e}"))?;
    }
}

/// `AppSettings::idle_timeout_minutes` if set, else `IDLE_TIMEOUT`'s
/// built-in default — re-read on every IDLE cycle (not cached once at
/// startup) so a change in Preferences takes effect on the very next
/// cycle without needing to restart the daemon, same as every other
/// settings field this app reads live. Falls back to the default on
/// any config-load failure rather than erroring the whole sync loop
/// over a settings file problem.
fn idle_timeout() -> Duration {
    crate::config::load()
        .ok()
        .and_then(|cfg| cfg.settings.idle_timeout_minutes)
        .map(|m| Duration::from_secs(m as u64 * 60))
        .unwrap_or(IDLE_TIMEOUT)
}

/// Pushes every locally-queued `pending_push` flag change (star,
/// mark-read, mark-unread — see `store::update_flags_pending`) to the
/// server, batched per folder per direction: at most four `STORE`
/// commands per folder no matter how many messages are queued, since
/// every UID headed the same direction on the same flag goes in one
/// `UID STORE` call. This is what makes those actions feel instant
/// from the GUI's side — it only ever writes locally; this is the
/// unhurried background piece that actually tells the server, on
/// whatever cadence `candor-daemon`'s background task calls it on.
pub async fn push_pending_flags(account: AccountConfig, password: String) -> Result<()> {
    tokio::task::spawn_blocking(move || push_pending_flags_blocking(&account, &password))
        .await
        .context("pending-flag push task panicked")?
}

fn push_pending_flags_blocking(account: &AccountConfig, password: &str) -> Result<()> {
    let db = store::open()?;
    let pending = store::pending_pushes(&db, &account.id)?;
    if pending.is_empty() {
        return Ok(());
    }

    let mut folders: Vec<String> = pending.iter().map(|(f, ..)| f.clone()).collect();
    folders.sort();
    folders.dedup();

    let mut session = connect_and_login(account, password)?;

    for folder in folders {
        session.select(&folder).map_err(|e| anyhow::anyhow!("selecting {folder} failed: {e}"))?;

        let items: Vec<&(String, u32, bool, bool)> =
            pending.iter().filter(|(f, ..)| f == &folder).collect();

        let mut seen_true = Vec::new();
        let mut seen_false = Vec::new();
        let mut flagged_true = Vec::new();
        let mut flagged_false = Vec::new();
        let mut touched_uids = Vec::new();
        for (_, uid, seen, flagged) in &items {
            touched_uids.push(*uid);
            if *seen {
                seen_true.push(*uid)
            } else {
                seen_false.push(*uid)
            }
            if *flagged {
                flagged_true.push(*uid)
            } else {
                flagged_false.push(*uid)
            }
        }

        for (uids, query) in [
            (&seen_true, "+FLAGS (\\Seen)"),
            (&seen_false, "-FLAGS (\\Seen)"),
            (&flagged_true, "+FLAGS (\\Flagged)"),
            (&flagged_false, "-FLAGS (\\Flagged)"),
        ] {
            if uids.is_empty() {
                continue;
            }
            let uid_set = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
            session
                .uid_store(&uid_set, query)
                .map_err(|e| anyhow::anyhow!("pushing pending flags for {folder} failed: {e}"))?;
        }

        store::clear_pending_push(&db, &account.id, &folder, &touched_uids)?;
    }

    let _ = session.logout();
    Ok(())
}

/// Runs a live IMAP `SEARCH` for `query` against `folder` (or every
/// selectable folder, when `None`) — the explicit "search the server
/// too" action a local search can broaden out to, since the local
/// cache only ever covers subject/from always and body text
/// opportunistically (see `store::search_messages`'s doc comment).
/// Anything found gets upserted into the local index exactly like a
/// normal sync would, so it's immediately visible to a follow-up local
/// search/`list_messages` call — there's no separate "server search
/// results" representation to maintain. Returns how many messages were
/// found/updated.
pub async fn search_server(
    account: AccountConfig,
    password: String,
    folder: Option<String>,
    query: String,
) -> Result<u32> {
    tokio::task::spawn_blocking(move || search_server_blocking(&account, &password, folder.as_deref(), &query))
        .await
        .context("server search task panicked")?
}

fn search_server_blocking(
    account: &AccountConfig,
    password: &str,
    folder: Option<&str>,
    query: &str,
) -> Result<u32> {
    let db = store::open()?;
    let folders: Vec<String> = match folder {
        Some(f) => vec![f.to_string()],
        None => store::list_folders(&db, &account.id)?.into_iter().map(|f| f.name).collect(),
    };

    let mut session = connect_and_login(account, password)?;
    let parser = MessageParser::default();
    let escaped = query.replace('\\', "\\\\").replace('"', "\\\"");
    let mut total = 0u32;

    for folder in folders {
        session.select(&folder).map_err(|e| anyhow::anyhow!("selecting {folder} failed: {e}"))?;

        // `TEXT` matches subject/body/from/to, server-implementation
        // dependent — good enough for a deliberately broad "search
        // beyond what's cached" action, not meant to be precise.
        let uids = session
            .uid_search(format!("TEXT \"{escaped}\""))
            .map_err(|e| anyhow::anyhow!("UID SEARCH in {folder} failed: {e}"))?;
        if uids.is_empty() {
            continue;
        }

        let uid_set = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let fetches = session
            .uid_fetch(&uid_set, "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])")
            .map_err(|e| anyhow::anyhow!("UID FETCH in {folder} failed: {e}"))?;

        for fetch in fetches.iter() {
            let Some(uid) = fetch.uid else { continue };
            let parsed = fetch.header().and_then(|h| parser.parse(h));
            let (message_id, subject, from_name, from_address, date) = match &parsed {
                Some(msg) => {
                    let from = msg.from().and_then(|a| a.first());
                    (
                        msg.message_id().map(str::to_string),
                        msg.subject().map(str::to_string),
                        from.and_then(|a| a.name.as_ref()).map(|s| s.to_string()),
                        from.and_then(|a| a.address.as_ref()).map(|s| s.to_string()),
                        msg.date().map(|d| d.to_timestamp()),
                    )
                }
                None => Default::default(),
            };
            let seen = fetch.flags().iter().any(|f| matches!(f, imap::types::Flag::Seen));
            let flagged = fetch.flags().iter().any(|f| matches!(f, imap::types::Flag::Flagged));

            store::upsert_message(
                &db,
                &account.id,
                &folder,
                &NewMessage { uid, message_id, subject, from_name, from_address, date, seen, flagged, size: fetch.size },
            )?;
            total += 1;
        }
    }

    let _ = session.logout();
    Ok(total)
}

/// Pushes every locally-queued archive/delete/move-to-folder (see
/// `store::queue_move`) to the server, batched per `(from_folder,
/// to_folder)` pair — one `UID MOVE` per pair, however many messages
/// are queued for it, rather than one per message. Same local-first
/// framing as `push_pending_flags`: these already vanished from the
/// GUI's view the moment they were queued, so there's no user waiting
/// on this to finish.
pub async fn push_pending_moves(account: AccountConfig, password: String) -> Result<()> {
    tokio::task::spawn_blocking(move || push_pending_moves_blocking(&account, &password))
        .await
        .context("pending-move push task panicked")?
}

fn push_pending_moves_blocking(account: &AccountConfig, password: &str) -> Result<()> {
    let db = store::open()?;
    let pending = store::pending_moves(&db, &account.id)?;
    if pending.is_empty() {
        return Ok(());
    }

    let mut pairs: Vec<(String, String)> =
        pending.iter().map(|(from, _, to)| (from.clone(), to.clone())).collect();
    pairs.sort();
    pairs.dedup();

    let mut session = connect_and_login(account, password)?;

    for (from_folder, to_folder) in pairs {
        let uids: Vec<u32> = pending
            .iter()
            .filter(|(f, _, t)| f == &from_folder && t == &to_folder)
            .map(|(_, uid, _)| *uid)
            .collect();
        if uids.is_empty() {
            continue;
        }

        session
            .select(&from_folder)
            .map_err(|e| anyhow::anyhow!("selecting {from_folder} failed: {e}"))?;
        let uid_set = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        session
            .uid_mv(&uid_set, &to_folder)
            .map_err(|e| anyhow::anyhow!("moving messages {uid_set} to {to_folder} failed: {e}"))?;

        store::clear_pending_moves(&db, &account.id, &from_folder, &uids)?;

        // The moved messages now exist in `to_folder` under brand-new
        // UIDs the server just assigned — nothing else makes this
        // folder's local cache aware of them until its own turn comes
        // up in the main sync loop, which only runs on an INBOX IDLE
        // wake or every `IDLE_TIMEOUT` (25 minutes) regardless of
        // activity. A folder you don't get new mail in often (like a
        // label such as "Important") could easily sit there for most
        // of that window even though the move itself happened in
        // seconds. Syncing it here, immediately, in the same session,
        // is what actually closes that gap — not a cache that was
        // working in Inbox and not elsewhere, both get the exact same
        // treatment; Inbox just also gets synced far more often by
        // its own IDLE wakes.
        if let Err(e) = sync_once(&mut session, account, &to_folder, None) {
            tracing::warn!(error = %e, folder = %to_folder, "failed to sync move target folder");
        }
    }

    let _ = session.logout();
    Ok(())
}

pub(crate) fn connect_and_login(account: &AccountConfig, password: &str) -> Result<ImapSession> {
    let tls = native_tls::TlsConnector::builder()
        .build()
        .context("building TLS connector")?;

    let client = match account.imap_security {
        Security::ImplicitTls => imap::connect(
            (account.imap_host.as_str(), account.imap_port),
            account.imap_host.as_str(),
            &tls,
        )
        .map_err(|e| anyhow::anyhow!("IMAP connect failed: {e}"))?,
        Security::StartTls => imap::connect_starttls(
            (account.imap_host.as_str(), account.imap_port),
            account.imap_host.as_str(),
            &tls,
        )
        .map_err(|e| anyhow::anyhow!("IMAP STARTTLS connect failed: {e}"))?,
    };

    client
        .login(&account.username, password)
        .map_err(|(e, _client)| anyhow::anyhow!("IMAP login failed: {e}"))
}

/// Lists every selectable folder (skips `\Noselect` entries, e.g. pure
/// hierarchy separators some servers expose).
/// `(name, special_use)` per folder — `special_use` is the raw RFC 6154
/// SPECIAL-USE attribute (e.g. `\Sent`), if the server tagged one.
fn list_folders(session: &mut ImapSession) -> Result<Vec<(String, Option<String>)>> {
    let names = session
        .list(None, Some("*"))
        .map_err(|e| anyhow::anyhow!("LIST failed: {e}"))?;

    const KNOWN_SPECIAL_USE: &[&str] = &[
        "\\All", "\\Archive", "\\Drafts", "\\Flagged", "\\Important", "\\Junk", "\\Sent", "\\Trash",
    ];

    Ok(names
        .iter()
        .filter(|n| !n.attributes().contains(&imap::types::NameAttribute::NoSelect))
        .map(|n| {
            let special_use = n.attributes().iter().find_map(|a| match a {
                imap::types::NameAttribute::Custom(raw) => KNOWN_SPECIAL_USE
                    .iter()
                    .find(|known| known.eq_ignore_ascii_case(raw))
                    .map(|known| known.to_string()),
                _ => None,
            });
            (n.name().to_string(), special_use)
        })
        .collect())
}

fn sync_all_folders(
    session: &mut ImapSession,
    account: &AccountConfig,
) -> Result<Vec<(String, SyncReport)>> {
    let folders = list_folders(session)?;
    let mut reports = Vec::with_capacity(folders.len());

    for (folder, special_use) in folders {
        let report = sync_once(session, account, &folder, special_use.as_deref())?;
        reports.push((folder, report));
    }

    Ok(reports)
}

fn sync_once(
    session: &mut ImapSession,
    account: &AccountConfig,
    folder: &str,
    special_use: Option<&str>,
) -> Result<SyncReport> {
    let mailbox = session
        .select(folder)
        .map_err(|e| anyhow::anyhow!("selecting {folder} failed: {e}"))?;

    let db = store::open()?;
    let prior = store::folder_state(&db, &account.id, folder)?.unwrap_or_default();

    let uid_validity = mailbox.uid_validity;
    let uid_next = mailbox.uid_next.unwrap_or(1);

    let mut resynced = false;
    let mut last_uid = prior.last_uid;

    // A changed UIDVALIDITY means the server reassigned UIDs out from under
    // us — cached UIDs (and any cached bodies keyed by UID) no longer mean
    // anything, so start this folder over.
    if prior.uid_validity.is_some() && prior.uid_validity != uid_validity {
        store::clear_folder(&db, &account.id, folder)?;
        if let Err(e) = body::clear_cache(&account.id, folder) {
            tracing::warn!(error = %e, folder = %folder, "failed to clear stale body cache");
        }
        last_uid = 0;
        resynced = true;
    }

    // A folder's first-ever sync (new account, or just reset above by a
    // UIDVALIDITY change) can pull in up to `INITIAL_SYNC_LIMIT` "new"
    // messages at once — backfill, not mail that just arrived, so none
    // of it belongs in `new_unseen`. Without this, adding an account
    // would fire a notification for (or about) every unread message
    // already sitting in the mailbox.
    let is_initial_sync = last_uid == 0;

    let range_start = if last_uid == 0 {
        uid_next.saturating_sub(INITIAL_SYNC_LIMIT).max(1)
    } else {
        last_uid + 1
    };

    let mut new_or_updated = 0;
    let mut new_unseen = Vec::new();

    if range_start < uid_next {
        let range_end = uid_next.saturating_sub(1).max(range_start);
        let uid_set = format!("{range_start}:{range_end}");

        let fetches = session
            .uid_fetch(&uid_set, "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])")
            .map_err(|e| anyhow::anyhow!("UID FETCH failed: {e}"))?;

        let parser = MessageParser::default();

        for fetch in fetches.iter() {
            let Some(uid) = fetch.uid else { continue };

            let parsed = fetch.header().and_then(|h| parser.parse(h));

            let (message_id, subject, from_name, from_address, date) = match &parsed {
                Some(msg) => {
                    let from = msg.from().and_then(|a| a.first());
                    (
                        msg.message_id().map(str::to_string),
                        msg.subject().map(str::to_string),
                        from.and_then(|a| a.name.as_ref()).map(|s| s.to_string()),
                        from.and_then(|a| a.address.as_ref()).map(|s| s.to_string()),
                        msg.date().map(|d| d.to_timestamp()),
                    )
                }
                None => Default::default(),
            };

            let seen = fetch
                .flags()
                .iter()
                .any(|f| matches!(f, imap::types::Flag::Seen));
            let flagged = fetch
                .flags()
                .iter()
                .any(|f| matches!(f, imap::types::Flag::Flagged));

            if !is_initial_sync && !seen {
                new_unseen.push(NewMailSummary {
                    subject: subject.clone(),
                    from_name: from_name.clone(),
                    from_address: from_address.clone(),
                });
            }

            store::upsert_message(
                &db,
                &account.id,
                folder,
                &NewMessage {
                    uid,
                    message_id,
                    subject,
                    from_name,
                    from_address,
                    date,
                    seen,
                    flagged,
                    size: fetch.size,
                },
            )?;

            last_uid = last_uid.max(uid);
            new_or_updated += 1;
        }
    }

    // The loop above only ever looks at UIDs it's never seen before, so
    // a `\Seen`/`\Flagged` change on a message it already has — from
    // this app's own mark-read/mark-unread/star actions, another
    // client, or webmail — would otherwise never make it back into the
    // local store no matter how many times this runs. Re-checking just
    // the flags (not a full header re-fetch) for the most recently
    // cached messages catches that, bounded to `FLAG_REFRESH_LIMIT` so
    // this stays cheap regardless of how large the folder's full
    // history has grown.
    let recent_uids = store::recent_uids(&db, &account.id, folder, FLAG_REFRESH_LIMIT)?;
    if !recent_uids.is_empty() {
        let uid_set = recent_uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let flag_fetches = session
            .uid_fetch(&uid_set, "(UID FLAGS)")
            .map_err(|e| anyhow::anyhow!("UID FETCH (flags) failed: {e}"))?;

        let mut returned_uids = std::collections::HashSet::with_capacity(flag_fetches.len());
        for fetch in flag_fetches.iter() {
            let Some(uid) = fetch.uid else { continue };
            returned_uids.insert(uid);
            let seen = fetch.flags().iter().any(|f| matches!(f, imap::types::Flag::Seen));
            let flagged = fetch.flags().iter().any(|f| matches!(f, imap::types::Flag::Flagged));
            store::update_flags(&db, &account.id, folder, uid, seen, flagged)?;
        }

        // A UID we explicitly asked about that didn't come back no
        // longer exists in this folder — deleted, archived, or spam-
        // marked through Gmail's web UI or another client, not through
        // this app's own queued moves (which already clean up their
        // own local row). Left alone, it would just sit in the local
        // cache forever: a message the GUI shows that isn't actually
        // there anymore, crowding out genuinely-present messages in
        // the GUI's own top-`MESSAGE_LIST_LIMIT` view in the process.
        let gone: Vec<u32> = recent_uids.into_iter().filter(|uid| !returned_uids.contains(uid)).collect();
        if !gone.is_empty() {
            store::delete_messages(&db, &account.id, folder, &gone)?;
        }
    }

    store::set_folder_state(
        &db,
        &account.id,
        folder,
        FolderState {
            uid_validity,
            last_uid,
            // Fall back to whatever was already stored when the caller
            // doesn't have it handy (see `push_pending_moves_blocking`,
            // which syncs a single target folder right after a move and
            // has no reason to re-derive its SPECIAL-USE attribute) —
            // otherwise a `None` here would silently blank out a
            // folder's Archive/Trash/etc. identity on every such call.
            special_use: special_use.map(str::to_string).or(prior.special_use.clone()),
        },
    )?;

    Ok(SyncReport {
        new_or_updated,
        resynced,
        new_unseen,
    })
}
