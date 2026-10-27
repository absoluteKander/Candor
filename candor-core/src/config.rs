//! Account configuration.
//!
//! `AccountConfig` holds only non-secret connection details. Passwords and
//! tokens are never part of this struct and never written to the config
//! file on disk — they live in the OS secret service (keyring) and are
//! looked up at connect time via `CredentialStore`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "candor";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    ImplicitTls,
    StartTls,
}

/// One of a small, fixed set of preset colors a tab can be assigned —
/// deliberately a minimal picker, not a full color wheel (see
/// `candor_group7_multiaccount_plan` in memory). The actual hex/CSS
/// mapping for each preset belongs to `candor-gui`, not here — this
/// crate just stores which one was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabColor {
    Blue,
    Green,
    Purple,
    Orange,
    Red,
    Teal,
    Pink,
    Yellow,
}

impl Default for TabColor {
    fn default() -> Self {
        TabColor::Blue
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    /// Local identifier used as the keyring lookup key, e.g. "personal".
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
    /// Login identity for IMAP/SMTP auth, often the same as `email`.
    pub username: String,
    /// Whether this account's tab can send mail right now — new
    /// compose, reply, reply-all, and forward alike. Defaults to
    /// `true` (locked) for a newly-added account: starting locked
    /// doubles as organic onboarding for a safety feature a new user
    /// might otherwise never discover. Only ever flipped by an
    /// explicit user click on the lock control — never by the app
    /// itself, never on a timer, never any other automatic condition.
    /// Enforced in two places at once: the Send control is disabled/
    /// unfocusable in the GUI, *and* the daemon's own `send_message`
    /// handler refuses to send while this is `true`, so there's no
    /// path that bypasses it by only disabling one button. See
    /// `candor_group7_multiaccount_plan` in memory.
    #[serde(default = "default_locked")]
    pub locked: bool,
    /// Fixed tab position, assigned when the account is added and
    /// changed only through an explicit Settings action — never by
    /// live drag-reordering. Reordering live risks silently swapping
    /// which account is which mid-use, which defeats the entire point
    /// of a fixed position (instant recognition without having to
    /// think about which tab is which).
    #[serde(default)]
    pub tab_order: u32,
    /// One of `TabColor`'s small preset set, shown on this account's
    /// tab as one of the two primary "which account am I in" signals
    /// (alongside `tab_order`'s fixed position).
    #[serde(default)]
    pub color: TabColor,
    /// Short label shown on the tab for fast visual scanning —
    /// alphanumeric characters only, capped at 13 characters (the
    /// length of "entertainment"). Empty means none has been set yet;
    /// the GUI falls back to showing something else (e.g. the display
    /// name) in that case. Validation of the alphanumeric-only/length
    /// rule belongs to whatever sets this (the GUI's settings form),
    /// not this struct.
    #[serde(default)]
    pub short_name: String,
    /// Whether this is the account Candor opens to on launch,
    /// regardless of whatever tab was focused when it was last
    /// closed — deliberately not "restore last session." Exactly one
    /// account should have this set at a time; a caller with none set
    /// (e.g. right after the first account is ever added) should fall
    /// back to the lowest `tab_order`.
    #[serde(default)]
    pub is_default: bool,
}

fn default_locked() -> bool {
    true
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
    #[serde(default)]
    pub settings: AppSettings,
}

/// User-facing preferences. `bulk_select_threshold`/`signature` are
/// local UI behavior only — `candor-gui` reads and writes those
/// directly, no D-Bus round trip. The two `body_cache_*` retention
/// fields below are the exception: the daemon's background loop reads
/// those too, since it's what actually runs the retention sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Below this many selected messages, the inbox list shows a
    /// per-row quick-action pop-out for each one; at or above it, they
    /// collapse into one bulk-action bar. See `candor-gui`'s
    /// `BULK_SELECT_THRESHOLD`-derived behavior.
    #[serde(default = "default_bulk_select_threshold")]
    pub bulk_select_threshold: usize,
    /// Appended to new messages, replies, and forwards when composing —
    /// empty means no signature is added. Plain text only (same as the
    /// rest of this app's v1 compose scope).
    #[serde(default)]
    pub signature: String,
    /// Retention for the searchable body cache (`message_bodies` —
    /// see `store::evict_expired_bodies`): non-exempt cached bodies
    /// older than this many days (since the message's own date, not
    /// when it was cached) are evicted. `None` disables the age-based
    /// cap. Unlike `bulk_select_threshold`/`signature`, this one *is*
    /// read by the daemon (its background push loop runs the retention
    /// sweep), not GUI-only.
    #[serde(default)]
    pub body_cache_max_age_days: Option<u32>,
    /// Retention cap on total disk space used by the non-exempt body
    /// cache, in bytes — whichever non-exempt rows are oldest get
    /// evicted first once this is exceeded. `None` disables the
    /// size-based cap. Also read by the daemon, same as
    /// `body_cache_max_age_days`. Since the cache only ever stores
    /// extracted plain text (never attachments), this goes much
    /// further than the raw number suggests.
    #[serde(default)]
    pub body_cache_max_bytes: Option<u64>,
    /// How long `sync::run`'s IMAP IDLE wait goes before it gives up
    /// and does a full resync of every folder (see `sync.rs`'s
    /// `IDLE_TIMEOUT`) — this is the real "network polling interval"
    /// for anything that isn't INBOX (the only folder actually
    /// IDLE-watched for live push notifications; everything else only
    /// catches up on this cadence, or whenever an INBOX push happens to
    /// trigger a resync as a side effect). `None` uses the built-in
    /// default (25 minutes). Read by the daemon only.
    #[serde(default)]
    pub idle_timeout_minutes: Option<u32>,
    /// Retention cap, in bytes, on the reading-pane cache
    /// (`body::CachedMessage` — extracted display text/HTML/headers,
    /// never attachment content; see `body.rs`'s module doc for why
    /// attachment bytes are never cached at all). Separate from
    /// `body_cache_max_bytes` above: that one caps the *search* body
    /// cache (`message_bodies`, exempt-aware, keyed by message_id);
    /// this one caps the plain per-message display cache the reading
    /// pane reads from, which has no exemptions and is keyed by
    /// folder/uid. `None` disables the cap. Oldest-fetched evicted
    /// first once exceeded.
    #[serde(default)]
    pub reading_cache_max_bytes: Option<u64>,
}

fn default_bulk_select_threshold() -> usize {
    4
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            bulk_select_threshold: default_bulk_select_threshold(),
            signature: String::new(),
            body_cache_max_age_days: None,
            body_cache_max_bytes: None,
            idle_timeout_minutes: None,
            reading_cache_max_bytes: None,
        }
    }
}

pub fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|p| p.join("candor"))
        .context("could not resolve XDG config directory")
}

pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("accounts.toml"))
}

pub fn load() -> Result<AppConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config at {}", path.display()))?;
    toml::from_str(&raw).context("parsing accounts.toml")
}

pub fn save(config: &AppConfig) -> Result<()> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating config dir {}", dir.display()))?;
    let raw = toml::to_string_pretty(config).context("serializing accounts.toml")?;
    std::fs::write(config_path()?, raw).context("writing accounts.toml")
}

/// Looks up and stores account secrets (passwords, OAuth tokens) in the
/// platform secret service. Nothing here ever touches disk directly.
pub struct CredentialStore;

impl CredentialStore {
    pub fn get_password(account_id: &str) -> Result<String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        entry
            .get_password()
            .with_context(|| format!("no credential stored for account '{account_id}'"))
    }

    pub fn set_password(account_id: &str, password: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        entry.set_password(password)?;
        Ok(())
    }

    pub fn delete_password(account_id: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        entry.delete_credential()?;
        Ok(())
    }
}
