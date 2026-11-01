//! Account configuration.
//!
//! `AccountConfig` holds only non-secret connection details. Passwords and
//! tokens are never part of this struct and never written to the config
//! file on disk — they live in the OS secret service (keyring) and are
//! looked up at connect time via `CredentialStore`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "candor";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    ImplicitTls,
    StartTls,
}

/// One of a small, fixed set of preset colors a tab can be assigned —
/// deliberately a minimal picker, not a full color wheel: a handful of
/// clearly-distinct presets are faster to tell apart at a glance than
/// picking from a gradient would be. The actual hex/CSS mapping for
/// each preset belongs to `candor-gui`, not here — this crate just
/// stores which one was chosen.
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

/// How an account authenticates. `Password` (the default) covers every
/// provider that still accepts a plain password or a provider-issued
/// app-specific password — Gmail, Yahoo, iCloud, Fastmail, Zoho. Microsoft
/// is phasing out that kind of login for Outlook.com/Microsoft 365
/// entirely, so `OAuthMicrosoft` is the real OAuth2 Authorization Code +
/// PKCE flow for those accounts — see `oauth.rs`. Either way, the actual
/// secret lives in the keyring under the same key: a plain password
/// string for `Password`, or a JSON-serialized access/refresh token pair
/// for `OAuthMicrosoft`. `CredentialStore` itself doesn't need to know
/// which — only the code that uses the secret to authenticate does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthMethod {
    #[default]
    Password,
    OAuthMicrosoft,
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
    /// path that bypasses it by only disabling one button.
    #[serde(default = "default_locked")]
    pub locked: bool,
    /// Whether this account's tab suppresses the sun/rays new-mail
    /// pulse and (for the default tab) real OS notifications — a
    /// deliberate "last resort" the user reaches for explicitly, not
    /// something the app ever sets on its own. Unlike `locked`, starts
    /// `false` (unmuted) for a newly-added account: there's no safety
    /// reason to default this one closed, and a brand-new account
    /// silently never notifying you would just look broken. Toggled
    /// from the tab strip's own notification icon, not Settings.
    #[serde(default)]
    pub muted: bool,
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
    /// See `AuthMethod`'s own doc comment.
    #[serde(default)]
    pub auth_method: AuthMethod,
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
    /// Whether clicking a system-level new-mail notification (only
    /// ever produced by the default-tab account) also marks that
    /// message read, on top of the flash-to-it-in-the-list behavior it
    /// always does. Default `false`: clicking a notification is
    /// deliberately never itself a "read" action anywhere else in this
    /// app (same as switching tabs or panes), and whether a passive
    /// notification click should be the one exception is explicitly
    /// left to the user rather than assumed either way — see this
    /// field's own design discussion for the user's exact framing
    /// ("im not opposed to it, but its not our decision").
    #[serde(default)]
    pub mark_read_on_notification_click: bool,
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
            mark_read_on_notification_click: false,
        }
    }
}

/// Creates `dir` (and any missing parents) owner-only (`0700`) instead
/// of whatever the process's umask would otherwise leave (commonly
/// `0755`, world-readable and world-traversable). Everything Candor
/// stores locally under a directory like this — the message index,
/// cached bodies, account config — can hold real email content or
/// addresses, not just opaque data, so this isn't optional hardening
/// on a shared/multi-user system; it's the whole point of using the
/// OS keyring for credentials specifically while still caching
/// everything *else* locally.
pub(crate) fn create_private_dir_all(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating directory {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions on {}", dir.display()))
}

/// Writes `contents` to `path` owner-only (`0600`) instead of whatever
/// the process's umask would otherwise leave (commonly `0644`,
/// world-readable). Same reasoning as `create_private_dir_all`.
pub(crate) fn write_private(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))
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
    create_private_dir_all(&dir)?;
    let raw = toml::to_string_pretty(config).context("serializing accounts.toml")?;
    write_private(&config_path()?, raw.as_bytes())
}

/// Looks up and stores account secrets (passwords, OAuth tokens) in the
/// platform secret service. Nothing here ever touches disk directly.
pub struct CredentialStore;

impl CredentialStore {
    /// Returns `Zeroizing<String>`, not a plain `String` — this is the
    /// single point every credential read in the app goes through
    /// (directly, or via `oauth::resolve_credential`), so wrapping it
    /// here is what actually makes the rest of the zeroizing chain
    /// meaningful: without it, every caller would need to immediately
    /// re-wrap a value that already leaked a plain, non-zeroizing copy
    /// into memory on the way out of this function.
    pub fn get_password(account_id: &str) -> Result<Zeroizing<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        entry
            .get_password()
            .map(Zeroizing::new)
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

/// Security regression suite for this file — see the project's
/// `SECURITY.md` for the methodology. These check the actual on-disk
/// permission bits after the fact, not just that the functions run
/// without error — a bug here is exactly the kind that "it compiled
/// and didn't panic" would never catch.
#[cfg(test)]
mod security_regression_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn scratch_path(label: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("candor_config_privacy_test_{label}_{n}"))
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Guards the local-file-permissions fix: before it, directories
    /// Candor creates for its own data were left at whatever the
    /// process umask produced (commonly `0755`, world-readable and
    /// world-traversable) — on a shared machine, any other local
    /// account could read into it.
    #[test]
    fn private_dir_is_actually_owner_only_on_disk() {
        let dir = scratch_path("dir");
        create_private_dir_all(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700, "directory permissions were not tightened");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Same, for the files themselves (commonly `0644` by default).
    #[test]
    fn private_file_is_actually_owner_only_on_disk() {
        let path = scratch_path("file");
        write_private(&path, b"test content").unwrap();
        assert_eq!(mode_of(&path), 0o600, "file permissions were not tightened");
        std::fs::remove_file(&path).ok();
    }
}
