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

    /// `(has_account, id, email, display_name)`.
    fn account_summary(&self) -> zbus::Result<(bool, String, String, String)>;

    /// Returns `false` if there was no account to remove.
    fn remove_account(&self) -> zbus::Result<bool>;

    /// `(synced, new_or_updated_count)` — `synced` is false if there's no
    /// account configured.
    fn sync_now(&self) -> zbus::Result<(bool, u32)>;

    /// Same as `sync_now`, but for one named folder instead of every
    /// folder. `(synced, new_or_updated_count)` — `synced` is false if
    /// there's no account configured.
    fn sync_folder(&self, folder: &str) -> zbus::Result<(bool, u32)>;

    /// Fetches (and caches) a message's extracted display content —
    /// never the raw MIME bytes or attachment content (see
    /// `candor_core::body::CachedMessage`). Returns the local path to
    /// the small cached JSON. `(false, "")` if there's no account
    /// configured.
    fn fetch_body(&self, folder: &str, uid: u32) -> zbus::Result<(bool, String)>;

    /// Fetches a message's attachments fresh and writes them to
    /// `dest_dir` — the only path attachment content ever travels over
    /// the network at all, and only from this explicit call. `(true,
    /// saved_count)`, or `(false, 0)` if there's no account configured.
    fn save_attachments(&self, folder: &str, uid: u32, dest_dir: &str) -> zbus::Result<(bool, u32)>;

    /// Moves a message between folders via IMAP MOVE — used for both
    /// "archive" and "delete" (move to Trash) with a different
    /// destination folder. `false` if there's no account configured.
    fn move_message(&self, from_folder: &str, uid: u32, to_folder: &str) -> zbus::Result<bool>;

    /// Clears the `\Seen` flag on a message. `false` if there's no
    /// account configured.
    fn mark_unread(&self, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Sets the `\Seen` flag on a message. `false` if there's no account
    /// configured.
    fn mark_read(&self, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Sets the `\Flagged` flag (star) on a message. `false` if there's
    /// no account configured.
    fn mark_flagged(&self, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Clears the `\Flagged` flag on a message. `false` if there's no
    /// account configured.
    fn mark_unflagged(&self, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Snoozes a message until `wake_at` (unix seconds) — hidden from
    /// every list until then, reappears marked unread. `false` if
    /// there's no account configured.
    fn schedule_message(&self, folder: &str, uid: u32, wake_at: i64) -> zbus::Result<bool>;

    /// Cancels a pending snooze. `false` if there's no account configured.
    fn unschedule_message(&self, folder: &str, uid: u32) -> zbus::Result<bool>;

    /// Sends a plain-text message, optionally with file attachments.
    /// `in_reply_to`/`references` are the original message's `Message-ID`
    /// when replying — pass empty strings for a new message. `attachments`
    /// is a list of local file paths to read and attach as-is.
    /// `message_id` is this outgoing message's own Message-ID, generated
    /// client-side (`candor_core::send::generate_message_id`) before this
    /// call — the caller needs that exact string back to call
    /// `cache_sent_body` under afterward.
    fn send_message(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        in_reply_to: &str,
        references: &str,
        attachments: Vec<String>,
        message_id: &str,
    ) -> zbus::Result<()>;

    /// Saves a message to the account's `\Drafts` folder via IMAP
    /// `APPEND` instead of sending it. `false` if there's no account
    /// configured or no `\Drafts` folder has been synced yet.
    /// `message_id`: same generate-before-calling pattern as
    /// `send_message`, though a draft save never caches a body itself.
    fn save_draft(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        in_reply_to: &str,
        references: &str,
        message_id: &str,
    ) -> zbus::Result<bool>;

    /// The explicit "search the server too" action. `folder` empty
    /// means every folder. `(true, found_count)`, or `(false, 0)` if
    /// there's no account configured.
    fn search_server(&self, folder: &str, query: &str) -> zbus::Result<(bool, u32)>;

    /// Caches a just-opened message's already-fetched plain-text body
    /// for search — the fetch already happened to display it, so this
    /// is free. `false` if the message isn't locally cached or has no
    /// `Message-ID` to key the cache under.
    fn cache_opened_body(&self, folder: &str, uid: u32, body: &str) -> zbus::Result<bool>;

    /// Caches the body of a message just sent (new compose/Reply/Reply
    /// All), exempt from retention forever. `date` is unix seconds (send
    /// time). `message_id` must be the exact value passed to
    /// `send_message` for this same send.
    fn cache_sent_body(&self, message_id: &str, body: &str, date: i64) -> zbus::Result<bool>;

    /// Records one contact — `source` is `"sent"`, `"manual"`, or
    /// `"csv"` (informational only). `false` if there's no account
    /// configured.
    fn add_contact(&self, address: &str, name: &str, source: &str) -> zbus::Result<bool>;

    /// Parses and imports a user-picked contacts CSV (Google/Nextcloud/
    /// Outlook export). `(true, imported_count)`, or `(false, 0)` if
    /// there's no account configured or nothing in the file looked like
    /// an email column.
    fn import_contacts_csv(&self, path: &str) -> zbus::Result<(bool, u32)>;
}
