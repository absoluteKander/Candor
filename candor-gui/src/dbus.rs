use zbus::proxy;

#[proxy(
    interface = "dev.candor.Daemon1",
    default_service = "dev.candor.Daemon1",
    default_path = "/dev/candor/Daemon1"
)]
pub trait Daemon {
    /// Leave `manual_imap_host` empty to try autodiscovery first. If the
    /// reply is `(false, _)`, autodiscovery found nothing usable — prompt
    /// for server settings and call again with the manual_* fields filled
    /// in.
    fn add_account(
        &self,
        display_name: &str,
        email: &str,
        username: &str,
        password: &str,
        manual_imap_host: &str,
        manual_imap_port: u16,
        manual_imap_implicit_tls: bool,
        manual_smtp_host: &str,
        manual_smtp_port: u16,
        manual_smtp_implicit_tls: bool,
    ) -> zbus::Result<(bool, String)>;

    fn has_account(&self) -> zbus::Result<bool>;

    /// `(has_account, id, email, display_name)` for the first
    /// configured account — still single-account in behavior (see
    /// `candor-daemon`'s own doc comment on this method). `list_accounts`
    /// below is the real multi-account replacement, not yet called from
    /// anywhere in this still-single-account GUI.
    fn account_summary(&self) -> zbus::Result<(bool, String, String, String)>;

    /// Every configured account, as parallel vectors: `(ids, emails,
    /// display_names, locked, tab_orders, colors, short_names,
    /// is_defaults)`. `colors` are `TabColor` variant names
    /// (`"Blue"`/`"Green"`/etc.) as plain strings. Not yet called from
    /// anywhere — added so the daemon side of Group 7 is complete ahead
    /// of the GUI's tab UI, which will be what actually uses this.
    #[allow(clippy::type_complexity)]
    fn list_accounts(
        &self,
    ) -> zbus::Result<(Vec<String>, Vec<String>, Vec<String>, Vec<bool>, Vec<u32>, Vec<String>, Vec<String>, Vec<bool>)>;

    /// Flips one account's send lock — the only place this is ever
    /// allowed to change (see `candor_group7_multiaccount_plan` in
    /// memory: never automatically, never on a timer, only this
    /// explicit call from a deliberate click). `false` if no account
    /// with that id is configured. Not yet called from anywhere.
    fn set_account_locked(&self, account_id: &str, locked: bool) -> zbus::Result<bool>;

    /// Returns `false` if there was no account to remove.
    fn remove_account(&self) -> zbus::Result<bool>;

    /// `(synced, new_or_updated_count)` — `synced` is false if
    /// `account_id` doesn't match a configured account.
    fn sync_now(&self, account_id: &str) -> zbus::Result<(bool, u32)>;

    /// Same as `sync_now`, but for one named folder instead of every
    /// folder. `(synced, new_or_updated_count)`.
    fn sync_folder(&self, account_id: &str, folder: &str) -> zbus::Result<(bool, u32)>;

    /// Fetches (and caches) a message's extracted display content —
    /// never the raw MIME bytes or attachment content (see
    /// `candor_core::body::CachedMessage`). Returns the local path to
    /// the small cached JSON.
    fn fetch_body(&self, account_id: &str, folder: &str, uid: u32) -> zbus::Result<(bool, String)>;

    /// Fetches a message's attachments fresh and writes them to
    /// `dest_dir` — the only path attachment content ever travels over
    /// the network at all, and only from this explicit call. `(true,
    /// saved_count)`.
    fn save_attachments(&self, account_id: &str, folder: &str, uid: u32, dest_dir: &str) -> zbus::Result<(bool, u32)>;

    /// Moves a message between folders via IMAP MOVE — used for both
    /// "archive" and "delete" (move to Trash) with a different
    /// destination folder.
    fn move_message(&self, account_id: &str, from_folder: &str, uid: u32, to_folder: &str) -> zbus::Result<bool>;

    /// Clears the `\Seen` flag on a message.
    fn mark_unread(&self, account_id: &str, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Sets the `\Seen` flag on a message.
    fn mark_read(&self, account_id: &str, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Sets the `\Flagged` flag (star) on a message.
    fn mark_flagged(&self, account_id: &str, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Clears the `\Flagged` flag on a message.
    fn mark_unflagged(&self, account_id: &str, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Snoozes a message until `wake_at` (unix seconds) — hidden from
    /// every list until then, reappears marked unread.
    fn schedule_message(&self, account_id: &str, folder: &str, uid: u32, wake_at: i64) -> zbus::Result<bool>;

    /// Cancels a pending snooze.
    fn unschedule_message(&self, account_id: &str, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Sends a plain-text message, optionally with file attachments.
    /// `in_reply_to`/`references` are the original message's `Message-ID`
    /// when replying — pass empty strings for a new message. `attachments`
    /// is a list of local file paths to read and attach as-is.
    /// `message_id` is this outgoing message's own Message-ID, generated
    /// client-side (`candor_core::send::generate_message_id`) before this
    /// call — the caller needs that exact string back to call
    /// `cache_sent_body` under afterward. Fails outright if the account
    /// is locked (see `AccountConfig::locked`) — this is the real
    /// enforcement point for the send lock, not just a disabled button.
    #[allow(clippy::too_many_arguments)]
    fn send_message(
        &self,
        account_id: &str,
        to: &str,
        subject: &str,
        body: &str,
        in_reply_to: &str,
        references: &str,
        attachments: Vec<String>,
        message_id: &str,
    ) -> zbus::Result<()>;

    /// Saves a message to the account's `\Drafts` folder via IMAP
    /// `APPEND` instead of sending it. `false` if no `\Drafts` folder
    /// has been synced yet. `message_id`: same generate-before-calling
    /// pattern as `send_message`, though a draft save never caches a
    /// body itself — and is never gated by the send lock, since nothing
    /// is transmitted to anyone.
    #[allow(clippy::too_many_arguments)]
    fn save_draft(
        &self,
        account_id: &str,
        to: &str,
        subject: &str,
        body: &str,
        in_reply_to: &str,
        references: &str,
        message_id: &str,
    ) -> zbus::Result<bool>;

    /// The explicit "search the server too" action. `folder` empty
    /// means every folder. `(true, found_count)`.
    fn search_server(&self, account_id: &str, folder: &str, query: &str) -> zbus::Result<(bool, u32)>;

    /// Caches a just-opened message's already-fetched plain-text body
    /// for search — the fetch already happened to display it, so this
    /// is free. `false` if the message isn't locally cached, has no
    /// `Message-ID` to key the cache under, or is in Junk.
    fn cache_opened_body(&self, account_id: &str, folder: &str, uid: u32, body: &str) -> zbus::Result<bool>;

    /// Caches the body of a message just sent (new compose/Reply/Reply
    /// All), exempt from retention forever. `date` is unix seconds (send
    /// time). `message_id` must be the exact value passed to
    /// `send_message` for this same send.
    fn cache_sent_body(&self, account_id: &str, message_id: &str, body: &str, date: i64) -> zbus::Result<bool>;

    /// Records one contact — `source` is `"sent"`, `"manual"`, or
    /// `"csv"` (informational only).
    fn add_contact(&self, account_id: &str, address: &str, name: &str, source: &str) -> zbus::Result<bool>;

    /// Parses and imports a user-picked contacts CSV (Google/Nextcloud/
    /// Outlook export). `(true, imported_count)`, or `(false, 0)` if
    /// nothing in the file looked like an email column.
    fn import_contacts_csv(&self, account_id: &str, path: &str) -> zbus::Result<(bool, u32)>;
}
