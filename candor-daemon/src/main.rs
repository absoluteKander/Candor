mod notify;

use std::collections::HashMap;
use std::sync::Mutex;

use candor_core::account::{
    self, AddAccountOutcome, ManualServerSettings, NewAccountRequest, NewOAuthAccountRequest,
};
use candor_core::config::{self, Security};
use candor_core::oauth;
use candor_core::sync;
use zbus::connection::Builder;
use zbus::interface;
use zeroize::Zeroizing;

/// How often the background task checks for queued star/mark-read/
/// mark-unread/archive/delete/move changes to push — see
/// `start_account`'s doc comment. Nothing about this needs to be fast:
/// the whole point of queuing these locally is that the user never
/// waits on it.
const PENDING_PUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// One account's live background work — the IMAP IDLE sync loop, the
/// loop that pushes locally-queued changes back to the server, and the
/// one that turns new mail into desktop notifications. Every
/// configured account gets its own `AccountRuntime`, running
/// concurrently and independently of which account (if any) the GUI
/// currently has focused — mail arrives at random times per account
/// regardless of UI state, so background sync never pauses for an
/// account just because its tab isn't the one being looked at right
/// now.
struct AccountRuntime {
    sync_task: Option<tokio::task::JoinHandle<()>>,
    pending_push_task: Option<tokio::task::JoinHandle<()>>,
    notify_task: Option<tokio::task::JoinHandle<()>>,
}

impl AccountRuntime {
    fn abort_all(&mut self) {
        if let Some(handle) = self.sync_task.take() {
            handle.abort();
        }
        if let Some(handle) = self.pending_push_task.take() {
            handle.abort();
        }
        if let Some(handle) = self.notify_task.take() {
            handle.abort();
        }
    }
}

struct DaemonService {
    /// Keyed by `account_id` — one entry per currently-running
    /// account, independent of every other one. Replacing a running
    /// account's entry (re-adding it, effectively) aborts the old
    /// tasks before starting new ones; removing an account removes
    /// its entry entirely, same reasoning as the old single-account
    /// `stop_sync` had (a removed account must not keep syncing in
    /// the background with credentials no longer stored anywhere).
    runtimes: Mutex<HashMap<String, AccountRuntime>>,
}

impl DaemonService {
    fn new() -> Self {
        Self { runtimes: Mutex::new(HashMap::new()) }
    }

    /// Starts (or restarts, if already running) one account's
    /// background work — every other account's runtime is untouched.
    /// Built fully before taking the lock, so the lock is only ever
    /// held for the quick insert/replace, not for the duration of
    /// setting up three tasks.
    /// Does not take a credential — `sync::run` and the pending-push
    /// loop below both resolve their own, fresh, on every reconnect/
    /// interval (see `sync::run`'s doc comment for why: these run for
    /// the daemon's whole lifetime, far longer than an OAuth2 access
    /// token is valid for).
    fn start_account(&self, account: config::AccountConfig) {
        let (new_mail_tx, mut new_mail_rx) = tokio::sync::mpsc::unbounded_channel();
        let sync_task = tokio::spawn(sync::run(account.clone(), new_mail_tx));
        let notify_task = tokio::spawn(async move {
            while let Some(mail) = new_mail_rx.recv().await {
                if let Err(e) = notify::send_new_mail_notification(&mail).await {
                    tracing::warn!(error = %e, "failed to send new-mail notification");
                }
            }
        });

        let push_account = account.clone();
        let pending_push_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(PENDING_PUSH_INTERVAL).await;
                if let Err(e) = sync::push_pending_flags(push_account.clone()).await {
                    tracing::warn!(error = %e, account = %push_account.id, "failed to push queued flag changes");
                }
                if let Err(e) = sync::push_pending_moves(push_account.clone()).await {
                    tracing::warn!(error = %e, account = %push_account.id, "failed to push queued moves");
                }
                // Purely local (see `store::wake_due_snoozes`'s doc
                // comment) — no network call, so no reason to spawn it
                // separately from the two above.
                match candor_core::store::open()
                    .and_then(|db| candor_core::store::wake_due_snoozes(&db, &push_account.id))
                {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(account = %push_account.id, count = n, "woke due snoozes"),
                    Err(e) => tracing::warn!(error = %e, "failed to check due snoozes"),
                }
                if let Err(e) = fill_pending_body_cache(&push_account).await {
                    tracing::warn!(error = %e, "failed to fill pending body cache");
                }
                if let Err(e) = run_retention_sweep(&push_account.id) {
                    tracing::warn!(error = %e, "failed to run body-cache retention sweep");
                }
            }
        });

        let runtime = AccountRuntime {
            sync_task: Some(sync_task),
            pending_push_task: Some(pending_push_task),
            notify_task: Some(notify_task),
        };

        let mut runtimes = self.runtimes.lock().unwrap();
        if let Some(mut old) = runtimes.insert(account.id, runtime) {
            old.abort_all();
        }
    }

    fn stop_account(&self, account_id: &str) {
        let mut runtimes = self.runtimes.lock().unwrap();
        if let Some(mut runtime) = runtimes.remove(account_id) {
            runtime.abort_all();
        }
    }
}

/// Looks up one specific account by id — the shared resolution helper
/// every per-account D-Bus method below uses instead of each grabbing
/// "whichever account happens to be first" the way this daemon did
/// before Group 7. Returns an error (not a bool-shaped "not found") if
/// `account_id` doesn't match anything configured: unlike the old
/// single-account world, where "no account configured yet" was a
/// normal, expected v1 state, a caller in the multi-account world is
/// expected to already have a real id (from `list_accounts`) before
/// calling any of these — a mismatch here means something's actually
/// wrong (a stale id, a race with account removal), not a routine case
/// to special-case quietly.
fn resolve_account(account_id: &str) -> zbus::fdo::Result<config::AccountConfig> {
    let cfg = config::load().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
    cfg.accounts
        .into_iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| zbus::fdo::Error::Failed(format!("no account '{account_id}' configured")))
}

#[interface(name = "dev.candor.Daemon1")]
impl DaemonService {
    /// Adds a new account — does not replace any existing ones (see
    /// `account::add_account`'s own doc comment: the old "v1: single
    /// account only" gate is gone). Leave `manual_imap_host` empty to
    /// try autodiscovery first; if that returns `(false, _)`, prompt
    /// the user for server settings and call again with the manual_*
    /// fields filled in and `added` will be true on success.
    async fn add_account(
        &self,
        display_name: String,
        email: String,
        username: String,
        password: String,
        manual_imap_host: String,
        manual_imap_port: u16,
        manual_imap_implicit_tls: bool,
        manual_smtp_host: String,
        manual_smtp_port: u16,
        manual_smtp_implicit_tls: bool,
    ) -> zbus::fdo::Result<(bool, String)> {
        let manual = if manual_imap_host.is_empty() {
            None
        } else {
            Some(ManualServerSettings {
                imap_host: manual_imap_host,
                imap_port: manual_imap_port,
                imap_security: security_from_bool(manual_imap_implicit_tls),
                smtp_host: manual_smtp_host,
                smtp_port: manual_smtp_port,
                smtp_security: security_from_bool(manual_smtp_implicit_tls),
            })
        };

        let req = NewAccountRequest {
            display_name,
            email,
            username,
            password: Zeroizing::new(password),
            manual,
        };

        match account::add_account(req).await {
            Ok(AddAccountOutcome::Added(acc)) => {
                tracing::info!(account = %acc.id, "account added");
                if let Err(e) = oauth::resolve_credential(&acc) {
                    tracing::warn!(error = %e, account = %acc.id, "could not read back credential right after adding");
                }
                self.start_account(acc.clone());
                Ok((true, acc.id))
            }
            Ok(AddAccountOutcome::NeedsManualSettings) => {
                tracing::info!("autodiscovery found nothing usable; manual settings needed");
                Ok((false, String::new()))
            }
            Err(e) => {
                tracing::warn!(error = %e, "add_account failed");
                Err(zbus::fdo::Error::Failed(format!("{e:#}")))
            }
        }
    }

    /// Adds a new account authenticating via Microsoft OAuth2 instead
    /// of a password — the GUI runs the actual interactive sign-in
    /// itself (opening the browser, catching the redirect; see
    /// `candor_core::oauth::interactive_sign_in`, which needs no
    /// credential access and so has no reason to go through the
    /// daemon), then hands the resulting token here to be verified
    /// against the real server and persisted, the same shape as
    /// `add_account` does for a password. Same `manual_*` fallback
    /// convention: empty `manual_imap_host` tries autodiscovery first.
    async fn add_oauth_account(
        &self,
        display_name: String,
        email: String,
        username: String,
        access_token: String,
        refresh_token: String,
        expires_at: i64,
        manual_imap_host: String,
        manual_imap_port: u16,
        manual_imap_implicit_tls: bool,
        manual_smtp_host: String,
        manual_smtp_port: u16,
        manual_smtp_implicit_tls: bool,
    ) -> zbus::fdo::Result<(bool, String)> {
        let manual = if manual_imap_host.is_empty() {
            None
        } else {
            Some(ManualServerSettings {
                imap_host: manual_imap_host,
                imap_port: manual_imap_port,
                imap_security: security_from_bool(manual_imap_implicit_tls),
                smtp_host: manual_smtp_host,
                smtp_port: manual_smtp_port,
                smtp_security: security_from_bool(manual_smtp_implicit_tls),
            })
        };

        let req = NewOAuthAccountRequest {
            display_name,
            email,
            username,
            access_token: Zeroizing::new(access_token),
            refresh_token: Zeroizing::new(refresh_token),
            expires_at,
            manual,
        };

        match account::add_oauth_account(req).await {
            Ok(AddAccountOutcome::Added(acc)) => {
                tracing::info!(account = %acc.id, "OAuth account added");
                if let Err(e) = oauth::resolve_credential(&acc) {
                    tracing::warn!(error = %e, account = %acc.id, "could not read back credential right after adding");
                }
                self.start_account(acc.clone());
                Ok((true, acc.id))
            }
            Ok(AddAccountOutcome::NeedsManualSettings) => {
                tracing::info!("autodiscovery found nothing usable; manual settings needed");
                Ok((false, String::new()))
            }
            Err(e) => {
                tracing::warn!(error = %e, "add_oauth_account failed");
                Err(zbus::fdo::Error::Failed(format!("{e:#}")))
            }
        }
    }

    async fn has_account(&self) -> zbus::fdo::Result<bool> {
        let cfg = config::load().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        Ok(!cfg.accounts.is_empty())
    }

    /// Every configured account, as parallel vectors (D-Bus has no
    /// native "array of structs" that zbus's simple method-return
    /// style reaches for) — `(id, email, display_name, locked, muted,
    /// tab_order, color, short_name, is_default)`. What the GUI's
    /// top-level tab-bar startup enumeration calls to find out which
    /// `AccountTab`s to create — the real multi-account replacement for
    /// the old single-account `account_summary`, which is gone now that
    /// something actually calls this instead.
    #[allow(clippy::type_complexity)]
    async fn list_accounts(
        &self,
    ) -> zbus::fdo::Result<(
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<bool>,
        Vec<bool>,
        Vec<u32>,
        Vec<String>,
        Vec<String>,
        Vec<bool>,
    )> {
        let accounts = account::list_accounts().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let mut ids = Vec::with_capacity(accounts.len());
        let mut emails = Vec::with_capacity(accounts.len());
        let mut display_names = Vec::with_capacity(accounts.len());
        let mut locked = Vec::with_capacity(accounts.len());
        let mut muted = Vec::with_capacity(accounts.len());
        let mut tab_orders = Vec::with_capacity(accounts.len());
        let mut colors = Vec::with_capacity(accounts.len());
        let mut short_names = Vec::with_capacity(accounts.len());
        let mut is_defaults = Vec::with_capacity(accounts.len());
        for acc in accounts {
            ids.push(acc.id);
            emails.push(acc.email);
            display_names.push(acc.display_name);
            locked.push(acc.locked);
            muted.push(acc.muted);
            tab_orders.push(acc.tab_order);
            colors.push(format!("{:?}", acc.color));
            short_names.push(acc.short_name);
            is_defaults.push(acc.is_default);
        }
        Ok((ids, emails, display_names, locked, muted, tab_orders, colors, short_names, is_defaults))
    }

    /// Flips one account's send lock — the only place this is ever
    /// allowed to change (never automatically, never on a timer, never
    /// as a side effect of anything else). See `AccountConfig::locked`'s
    /// own doc comment for the full reasoning. Returns `false` if no
    /// account with that id is configured.
    async fn set_account_locked(&self, account_id: String, locked: bool) -> zbus::fdo::Result<bool> {
        let mut cfg = config::load().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let Some(acc) = cfg.accounts.iter_mut().find(|a| a.id == account_id) else {
            return Ok(false);
        };
        acc.locked = locked;
        config::save(&cfg).map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        Ok(true)
    }

    /// Flips one account's notification mute — same shape and same
    /// "only this explicit call ever changes it" reasoning as
    /// `set_account_locked`, for `AccountConfig::muted` instead. Returns
    /// `false` if no account with that id is configured.
    async fn set_account_muted(&self, account_id: String, muted: bool) -> zbus::fdo::Result<bool> {
        let mut cfg = config::load().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let Some(acc) = cfg.accounts.iter_mut().find(|a| a.id == account_id) else {
            return Ok(false);
        };
        acc.muted = muted;
        config::save(&cfg).map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        Ok(true)
    }

    /// Removes one account (credential + config) and stops its
    /// background runtime. Returns `false` if no account with that id
    /// is configured — the real multi-account version, now that an
    /// `AccountTab` closing its own account is a real caller.
    async fn remove_account(&self, account_id: String) -> zbus::fdo::Result<bool> {
        let removed = account::remove_account(&account_id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        if removed {
            self.stop_account(&account_id);
        }
        Ok(removed)
    }

    /// One-shot manual sync trigger for one account, independent of
    /// its background IDLE loop. Returns `(synced, new_or_updated_count)`.
    async fn sync_now(&self, account_id: String) -> zbus::fdo::Result<(bool, u32)> {
        let acc = resolve_account(&account_id)?;
        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let reports = sync::sync_all(acc, password)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let total: u32 = reports.iter().map(|(_, r)| r.new_or_updated as u32).sum();
        Ok((true, total))
    }

    /// Same as `sync_now`, but for one named folder instead of every
    /// folder — for when only that folder's state actually needs to be
    /// current right now (see `sync::sync_one_folder`'s doc comment).
    async fn sync_folder(&self, account_id: String, folder: String) -> zbus::fdo::Result<(bool, u32)> {
        let acc = resolve_account(&account_id)?;
        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let report = sync::sync_one_folder(acc, password, folder)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok((true, report.new_or_updated as u32))
    }

    /// Fetches (and caches) a message's extracted display content —
    /// see `body::CachedMessage`'s doc comment: never the raw MIME
    /// bytes, specifically never attachment content, even though
    /// verifying DKIM (also done here) requires fetching all of it
    /// over the network to compute. Returns the local path to the
    /// small cached JSON.
    async fn fetch_body(&self, account_id: String, folder: String, uid: u32) -> zbus::fdo::Result<(bool, String)> {
        let acc = resolve_account(&account_id)?;
        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let path = candor_core::body::fetch_body(acc, password, folder, uid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok((true, path.display().to_string()))
    }

    /// Fetches a message's attachments fresh and writes them straight
    /// to `dest_dir` — the one explicit, user-initiated path attachment
    /// *content* ever travels over the network or touches disk at all
    /// (see `body::fetch_and_save_attachments`'s doc comment). Never
    /// cached, never triggered by anything but this call.
    async fn save_attachments(
        &self,
        account_id: String,
        folder: String,
        uid: u32,
        dest_dir: String,
    ) -> zbus::fdo::Result<(bool, u32)> {
        let acc = resolve_account(&account_id)?;
        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let saved = candor_core::body::fetch_and_save_attachments(
            acc,
            password,
            folder,
            uid,
            std::path::PathBuf::from(dest_dir),
        )
        .await
        .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok((true, saved as u32))
    }

    /// Archives, deletes (moves to Trash), or moves a message to an
    /// explicit folder — the GUI decides the target from the locally-
    /// synced SPECIAL-USE attributes, or directly for "Move to…".
    /// Local-only/instant: queues the move and removes the message
    /// from the local cache of `from_folder` right away (see
    /// `store::queue_move`'s doc comment); `push_pending_moves` is what
    /// actually issues the IMAP `MOVE`, on its own unhurried schedule.
    async fn move_message(
        &self,
        account_id: String,
        from_folder: String,
        uid: u32,
        to_folder: String,
    ) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        // Purge both caches (if anything was cached) when the message
        // is actually leaving the mailbox for good — Trash or Junk.
        // Archive does NOT purge: on Gmail specifically, "archive" just
        // removes the Inbox label (see `move_message_by_uid` in
        // candor-gui, which already falls back to `\All` for exactly
        // this reason) — the message isn't gone, so there's no reason
        // either cache should be purged either. Looked up *before*
        // `queue_move`, which deletes the source row immediately.
        if matches!(to_folder.as_str(), "\\Trash" | "\\Junk") {
            if let Ok(Some((message_id, _))) =
                candor_core::store::message_id_for(&db, &acc.id, &from_folder, uid)
            {
                let _ = candor_core::store::purge_message_body(&db, &acc.id, &message_id);
            }
            let _ = candor_core::body::purge_cached_message(&acc.id, &from_folder, uid);
        }

        candor_core::store::queue_move(&db, &acc.id, &from_folder, uid, &to_folder)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }

    /// The explicit "search the server too" action — broadens a local
    /// search out to a live IMAP `SEARCH`, merging anything found into
    /// the local index (see `sync::search_server`'s doc comment).
    /// `folder` empty means every folder.
    async fn search_server(&self, account_id: String, folder: String, query: String) -> zbus::fdo::Result<(bool, u32)> {
        let acc = resolve_account(&account_id)?;
        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let folder = (!folder.is_empty()).then_some(folder);
        let count = sync::search_server(acc, password, folder, query)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok((true, count))
    }

    /// Caches a message's already-fetched, already-parsed plain-text
    /// body for search — called right after `candor-gui`'s `open_message`
    /// parses it for display, since the fetch already happened and this
    /// is free. Never exempt from retention (only starring/sending are) —
    /// looks up the canonical `message_id`/`date` from the already-synced
    /// row rather than trusting a freshly re-parsed value (see
    /// `store::message_id_for`'s doc comment for why). A no-op (returns
    /// `false`) if the message isn't cached locally, has no `Message-ID`
    /// header to key the cache under, or is in Junk.
    async fn cache_opened_body(&self, account_id: String, folder: String, uid: u32, body: String) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let folders = candor_core::store::list_folders(&db, &acc.id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let is_junk =
            folders.iter().any(|f| f.name == folder && f.special_use.as_deref() == Some("\\Junk"));
        if is_junk {
            return Ok(false);
        }

        let Some((message_id, date)) =
            candor_core::store::message_id_for(&db, &acc.id, &folder, uid)
                .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?
        else {
            return Ok(false);
        };

        candor_core::store::cache_message_body(&db, &acc.id, &message_id, &body, date, false)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }

    /// Caches the body of a message the user just sent (new compose,
    /// Reply, or Reply All) — called right after a successful send,
    /// using the body text already in hand client-side, so this never
    /// touches the network. Always exempt from retention (see
    /// `message_bodies`'s exemption rules) — this is deliberate content
    /// the user wrote, not incidental cached-while-reading text.
    /// `message_id` is the exact value generated client-side for this
    /// send (`send::generate_message_id`), not re-derived here.
    async fn cache_sent_body(&self, account_id: String, message_id: String, body: String, date: i64) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        candor_core::store::cache_message_body(&db, &acc.id, &message_id, &body, Some(date), true)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }

    /// Records one contact — the shared write path for every source
    /// (sent-mail auto-harvest, the reading pane's opt-in "Add to
    /// contacts" button, and `import_contacts_csv` below, which just
    /// calls this once per parsed row). `source` is `"sent"`,
    /// `"manual"`, or `"csv"` — purely informational, see
    /// `store::upsert_contact`'s doc comment.
    async fn add_contact(&self, account_id: String, address: String, name: String, source: String) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let name = (!name.is_empty()).then_some(name);

        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        candor_core::store::upsert_contact(&db, &acc.id, &address, name.as_deref(), &source, now)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }

    /// Parses a user-picked CSV export (Google/Nextcloud/Outlook/etc.)
    /// and upserts every row with a usable address — a one-time import,
    /// not a live sync: real CardDAV/contacts-service integration would
    /// mean connecting to yet another account-specific service
    /// directly, which this app otherwise deliberately never does.
    /// File I/O and parsing happen here, not in the GUI, same
    /// daemon-is-the-writer reasoning as everything else that touches
    /// the database. Returns `(true, imported_count)`, or `(false, 0)`
    /// if the file couldn't be parsed at all (no plausible email column).
    async fn import_contacts_csv(&self, account_id: String, path: String) -> zbus::fdo::Result<(bool, u32)> {
        let acc = resolve_account(&account_id)?;
        let contacts = candor_core::contacts_import::parse_contacts_csv(std::path::Path::new(&path))
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let mut imported = 0u32;
        for (name, address) in contacts {
            candor_core::store::upsert_contact(&db, &acc.id, &address, name.as_deref(), "csv", now)
                .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
            imported += 1;
        }

        Ok((true, imported))
    }

    /// Clears the `\Seen` flag on a message. Writes locally only and
    /// returns immediately — see `queue_flag_change`'s doc comment for
    /// why.
    async fn mark_unread(&self, account_id: String, folder: String, uid: u32) -> zbus::fdo::Result<bool> {
        queue_flag_change(&account_id, &folder, uid, Some(false), None)
    }

    /// Sets the `\Seen` flag on a message. Local-only/instant, same as
    /// `mark_unread`.
    async fn mark_read(&self, account_id: String, folder: String, uid: u32) -> zbus::fdo::Result<bool> {
        queue_flag_change(&account_id, &folder, uid, Some(true), None)
    }

    /// Sets the `\Flagged` flag (star) on a message. Local-only/
    /// instant, same as `mark_unread`. Also queues the message for
    /// lazy background body-caching (`store::queue_body_cache`) —
    /// starring is a deliberate "keep this findable" signal, but
    /// fetching the body synchronously here would reintroduce exactly
    /// the network-wait-on-a-flag-change problem this whole local-first
    /// design exists to avoid, so the actual fetch happens later, in
    /// the same background loop that already pushes flag/move changes.
    async fn mark_flagged(&self, account_id: String, folder: String, uid: u32) -> zbus::fdo::Result<bool> {
        let ok = queue_flag_change(&account_id, &folder, uid, None, Some(true))?;
        if ok {
            if let Ok(db) = candor_core::store::open() {
                let _ = candor_core::store::queue_body_cache(&db, &account_id, &folder, uid);
            }
        }
        Ok(ok)
    }

    /// Clears the `\Flagged` flag on a message. Local-only/instant,
    /// same as `mark_unread`.
    async fn mark_unflagged(&self, account_id: String, folder: String, uid: u32) -> zbus::fdo::Result<bool> {
        queue_flag_change(&account_id, &folder, uid, None, Some(false))
    }

    /// Snoozes a message until `wake_at` (unix seconds) — it disappears
    /// from every list/unread-count until then, then reappears marked
    /// unread. Purely local (see `store::snooze_message`'s doc comment)
    /// — instant, no network involved at all.
    async fn schedule_message(&self, account_id: String, folder: String, uid: u32, wake_at: i64) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        candor_core::store::snooze_message(&db, &acc.id, &folder, uid, wake_at)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }

    /// Cancels a pending snooze, making the message visible again right
    /// away.
    async fn unschedule_message(&self, account_id: String, folder: String, uid: u32) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        candor_core::store::unsnooze_message(&db, &acc.id, &folder, uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }

    /// Sends a plain-text message, optionally with file attachments.
    /// `in_reply_to`/`references` are the original message's `Message-ID`
    /// when replying — pass empty strings for a new message. `attachments`
    /// is a list of local file paths to read and attach as-is.
    /// `message_id` is generated client-side by the caller
    /// (`send::generate_message_id`) before this call, rather than
    /// inside `build_message` as it used to be — the caller needs that
    /// exact string back afterward to call `cache_sent_body` under the
    /// same key the message will later sync back under.
    ///
    /// Refuses outright — before anything else, including the network
    /// round trip — if this account is locked. This is the real
    /// enforcement point for the send lock (see `AccountConfig::locked`'s
    /// own doc comment): the GUI also disables/unfocuses the Send
    /// control while locked, but "no way to force it, period" means the
    /// block has to exist here too, not just at the UI layer — the same
    /// defense-in-depth reasoning behind `cache_opened_body`'s own Junk
    /// check above, so a bypass of one layer alone was never enough to
    /// defeat the lock.
    async fn send_message(
        &self,
        account_id: String,
        to: String,
        subject: String,
        body: String,
        in_reply_to: String,
        references: String,
        attachments: Vec<String>,
        message_id: String,
    ) -> zbus::fdo::Result<()> {
        let acc = resolve_account(&account_id)?;
        if acc.locked {
            return Err(zbus::fdo::Error::Failed(format!(
                "account '{account_id}' is locked — unlock it from its tab before sending"
            )));
        }

        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let msg = candor_core::send::OutgoingMessage {
            to,
            subject,
            body,
            in_reply_to: (!in_reply_to.is_empty()).then_some(in_reply_to),
            references: (!references.is_empty()).then_some(references),
            attachments: attachments.into_iter().map(std::path::PathBuf::from).collect(),
            message_id,
        };

        candor_core::send::send(&acc, &password, msg)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        tracing::info!(account = %acc.id, "message sent");
        Ok(())
    }

    /// Saves a message to the account's `\Drafts` folder via IMAP
    /// `APPEND` instead of sending it — this is the "back out of
    /// compose and it's waiting for you later" behavior. Unlike the
    /// flag/move actions, this is a real network round trip, same as
    /// `send_message`: there's no sensible local-only stand-in for "a
    /// brand new message now exists in Drafts" the way there is for
    /// flipping a flag on a message already cached. Not gated by the
    /// send lock — drafting isn't sending, nothing gets transmitted to
    /// anyone, so there's no wrong-account-send risk to guard against
    /// here.
    async fn save_draft(
        &self,
        account_id: String,
        to: String,
        subject: String,
        body: String,
        in_reply_to: String,
        references: String,
        message_id: String,
    ) -> zbus::fdo::Result<bool> {
        let acc = resolve_account(&account_id)?;
        let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let folders = candor_core::store::list_folders(&db, &acc.id)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
        let Some(drafts_folder) =
            folders.into_iter().find(|f| f.special_use.as_deref() == Some("\\Drafts")).map(|f| f.name)
        else {
            return Ok(false);
        };

        let password = oauth::resolve_credential(&acc)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        let msg = candor_core::send::OutgoingMessage {
            to,
            subject,
            body,
            in_reply_to: (!in_reply_to.is_empty()).then_some(in_reply_to),
            references: (!references.is_empty()).then_some(references),
            attachments: Vec::new(),
            message_id,
        };

        candor_core::send::save_draft(&acc, &password, &drafts_folder, msg)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        Ok(true)
    }
}

/// Writes a `\Seen`/`\Flagged` change locally and queues it for
/// `push_pending_flags` to actually tell the server later — the
/// read/unread/star actions never need to wait on an IMAP round trip,
/// which used to make the whole GUI feel like it had locked up for the
/// several seconds a real `STORE` command over the network can take.
/// `seen`/`flagged` are `None` for whichever one this particular call
/// isn't meant to touch (e.g. `mark_read` only ever means `\Seen`) —
/// the current value for that one is read back from the local store
/// first so it doesn't get clobbered.
fn queue_flag_change(
    account_id: &str,
    folder: &str,
    uid: u32,
    seen: Option<bool>,
    flagged: Option<bool>,
) -> zbus::fdo::Result<bool> {
    let resolved = resolve_account(account_id)?;
    let account_id = resolved.id.as_str();
    let db = candor_core::store::open().map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;
    let (current_seen, current_flagged) =
        candor_core::store::get_flags(&db, account_id, folder, uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?
            .unwrap_or((false, false));

    candor_core::store::update_flags_pending(
        &db,
        account_id,
        folder,
        uid,
        seen.unwrap_or(current_seen),
        flagged.unwrap_or(current_flagged),
    )
    .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

    Ok(true)
}

/// Processes every message queued for lazy body-caching since the last
/// run (`store::queue_body_cache` — written by `mark_flagged`, i.e.
/// starring) — fetches each one's body over the network and caches its
/// extracted plain text, exempt from retention. Run from the same
/// `PENDING_PUSH_INTERVAL` background loop that already pushes flag/
/// move changes, never synchronously from the star action itself. A
/// message that's since vanished (deleted, moved away) or landed in
/// Junk just drops out of the queue without being cached — there's
/// nothing wrong with that, it's the same "best effort, catches up
/// eventually" spirit as the rest of this loop.
async fn fill_pending_body_cache(account: &config::AccountConfig) -> anyhow::Result<()> {
    let password = oauth::resolve_credential(account)?;
    let db = candor_core::store::open()?;
    let queued = candor_core::store::pending_body_cache(&db, &account.id)?;
    if queued.is_empty() {
        return Ok(());
    }

    let folders = candor_core::store::list_folders(&db, &account.id)?;

    for (folder, uid) in queued {
        let is_junk = folders
            .iter()
            .any(|f| f.name == folder && f.special_use.as_deref() == Some("\\Junk"));
        let Some((message_id, date)) = candor_core::store::message_id_for(&db, &account.id, &folder, uid)?
        else {
            candor_core::store::clear_pending_body_cache(&db, &account.id, &folder, uid)?;
            continue;
        };
        if is_junk {
            candor_core::store::clear_pending_body_cache(&db, &account.id, &folder, uid)?;
            continue;
        }

        match candor_core::body::fetch_body_text(
            account.clone(),
            password.clone(),
            folder.clone(),
            uid,
        )
        .await
        {
            Ok(Some(text)) => {
                candor_core::store::cache_message_body(&db, &account.id, &message_id, &text, date, true)?;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, folder = %folder, uid, "failed to fetch body for background caching");
                // Leave it queued — worth retrying next interval rather
                // than silently dropping it on a transient network
                // failure.
                continue;
            }
        }
        candor_core::store::clear_pending_body_cache(&db, &account.id, &folder, uid)?;
    }

    Ok(())
}

/// Applies the user's configured retention caps to both caches this
/// app keeps locally — the searchable body cache (`AppSettings::
/// body_cache_max_age_days`/`body_cache_max_bytes`, see
/// `store::evict_expired_bodies`'s doc comment) and the reading-pane
/// display cache (`AppSettings::reading_cache_max_bytes`, see
/// `body::enforce_cache_size_cap`'s doc comment) — two genuinely
/// different caches with their own shapes and caps, not one setting
/// doing double duty. Purely local, no network, so this runs
/// synchronously in the same loop tick rather than needing its own
/// task.
fn run_retention_sweep(account_id: &str) -> anyhow::Result<()> {
    let cfg = config::load()?;

    let db = candor_core::store::open()?;
    let evicted = candor_core::store::evict_expired_bodies(
        &db,
        account_id,
        cfg.settings.body_cache_max_age_days,
        cfg.settings.body_cache_max_bytes,
    )?;
    if evicted > 0 {
        tracing::info!(count = evicted, "evicted cached bodies past retention limits");
    }

    if let Some(max_bytes) = cfg.settings.reading_cache_max_bytes {
        let evicted = candor_core::body::enforce_cache_size_cap(account_id, max_bytes)?;
        if evicted > 0 {
            tracing::info!(count = evicted, "evicted reading-pane cache entries past size cap");
        }
    }

    Ok(())
}

fn security_from_bool(implicit_tls: bool) -> Security {
    if implicit_tls {
        Security::ImplicitTls
    } else {
        Security::StartTls
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = config::load()?;
    tracing::info!(accounts = cfg.accounts.len(), "candor-daemon starting");

    let service = DaemonService::new();

    // Every configured account gets its own runtime at startup, not
    // just the first — background sync is independent per account
    // regardless of which one (if any) the GUI ends up focused on.
    for account in cfg.accounts {
        let id = account.id.clone();
        if let Err(e) = oauth::resolve_credential(&account) {
            tracing::warn!(account = %id, error = %e, "could not read stored credential at startup; will retry in the background");
        }
        service.start_account(account);
        tracing::info!(account = %id, "started account sync");
    }

    let _conn = Builder::session()
        .name("dev.candor.Daemon1")
        .serve_at("/dev/candor/Daemon1", service)
        .build()
        .await?;

    tracing::info!("D-Bus service registered as dev.candor.Daemon1, waiting for requests");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
