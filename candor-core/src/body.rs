//! On-demand message fetch — a message's body is only pulled down the
//! first time it's actually opened. What gets cached locally is
//! extracted *display* content (subject/from/to/cc/message_id/plain-text
//! body) plus the inspection verdict ([`crate::inspect`]: DKIM/SPF/
//! DMARC, sanitized HTML, attachment *metadata* only) — never the raw
//! MIME bytes, and specifically never attachment *content*.
//!
//! Verifying DKIM still requires fetching the complete raw body over
//! the network — a DKIM signature covers the whole body as one blob,
//! attachments included, so there's no way to validate it from just the
//! text parts. Those raw bytes exist only transiently, in memory, for
//! the one fetch that extracts the above; nothing from them is ever
//! written to disk beyond that small extracted set. Attachment content
//! is fetched fresh, on demand, only when the user explicitly asks to
//! save it ([`fetch_and_save_attachments`]) — never automatically
//! alongside an ordinary open, and never cached either, by design: an
//! attachment is the single most common way a malicious email actually
//! does damage, so "it downloaded the moment I opened the message" is
//! not a sentence this project wants to be true.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mail_parser::MimeHeaders;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::AccountConfig;
use crate::sync::connect_and_login;

fn cache_dir(account_id: &str, folder: &str) -> Result<PathBuf> {
    dirs::data_dir()
        .map(|p| {
            p.join("candor")
                .join("bodies")
                .join(account_id)
                .join(sanitize_folder(folder))
        })
        .context("could not resolve XDG data directory")
}

/// Folder names can contain `/` (IMAP hierarchy separators) — flatten
/// those so each folder maps to exactly one cache directory, not a
/// nested tree mirroring the mailbox's own structure. Also guards
/// against a folder name that's exactly `.`/`..`/empty after
/// flattening: the server is a source this project already treats as
/// trusted (see `discover.rs`'s doc comment), but a folder literally
/// named `".."` would otherwise traverse this cache path up a level
/// when joined, with no `/`/`\` character present for the replacement
/// above to ever catch.
fn sanitize_folder(folder: &str) -> String {
    let flattened: String =
        folder.chars().map(|c| if c == '/' || c == '\\' { '_' } else { c }).collect();
    match flattened.as_str() {
        "" | "." | ".." => "_".to_string(),
        _ => flattened,
    }
}

/// Reduces an attachment's claimed filename — straight from the
/// message's own Content-Disposition header, set by whoever sent the
/// email, not by the user or by us — to a bare basename safe to join
/// onto a caller-chosen save directory. Splits on *both* `/` and `\`
/// manually first, rather than relying on `Path::file_name()` alone:
/// that only recognizes this platform's own separator, so a filename
/// using the other style (`..\..\evil.exe`) would otherwise pass
/// through unsplit — inert as an actual traversal vector on Linux
/// specifically (the filesystem doesn't treat `\` as a separator
/// either), but there's no reason to depend on that distinction
/// holding when normalizing both explicitly is just as simple, and
/// `sanitize_folder` right above already does the same for folder
/// names. Anything that leaves no sane basename at all (empty, ".",
/// "..") falls back to a generic name rather than being silently
/// skipped. Pulled out of `fetch_and_save_attachments` specifically so
/// this one security-critical piece of logic is unit-testable on its
/// own, without the network fetch and file I/O around it.
fn sanitize_attachment_filename(filename: &str) -> String {
    let last_segment = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let candidate = std::path::Path::new(last_segment)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match candidate.as_str() {
        "" | "." | ".." => "attachment".to_string(),
        _ => candidate,
    }
}

fn body_path(account_id: &str, folder: &str, uid: u32) -> Result<PathBuf> {
    Ok(cache_dir(account_id, folder)?.join(format!("{uid}.json")))
}

/// Removes one message's reading-pane cache (display content + DKIM
/// verdict), if either file exists — used wherever a message is
/// confirmed gone from the server, so this cache never outlives the
/// message it describes. A no-op if nothing was cached, which is the
/// common case (most messages are never opened).
pub fn purge_cached_message(account_id: &str, folder: &str, uid: u32) -> Result<()> {
    let path = body_path(account_id, folder, uid)?;
    let vpath = verdict_path(&path);
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("purging cached message at {}", path.display()))?;
    }
    if vpath.exists() {
        std::fs::remove_file(&vpath).with_context(|| format!("purging cached verdict at {}", vpath.display()))?;
    }
    Ok(())
}

/// Wipes the cached bodies for a folder — used when the server's
/// UIDVALIDITY changes, meaning cached UIDs (and so these filenames) no
/// longer refer to the same messages.
pub fn clear_cache(account_id: &str, folder: &str) -> Result<()> {
    let dir = cache_dir(account_id, folder)?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("clearing body cache at {}", dir.display()))?;
    }
    Ok(())
}

/// Reads the cached inspection verdict for an already-fetched message,
/// if one exists.
pub fn read_verdict(body_path: &Path) -> Result<Option<crate::inspect::MessageVerdict>> {
    let vpath = verdict_path(body_path);
    if !vpath.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(&vpath).with_context(|| format!("reading verdict at {}", vpath.display()))?;
    serde_json::from_slice(&raw)
        .map(Some)
        .with_context(|| format!("parsing verdict at {}", vpath.display()))
}

fn verdict_path(body_path: &Path) -> PathBuf {
    let mut p = body_path.to_path_buf();
    p.set_extension("verdict.json");
    p
}

/// Everything about a message the reading pane (or a resumed draft)
/// needs beyond the inspection verdict — extracted once, at fetch time,
/// from the raw bytes while they're still in memory, and cached as this
/// small struct instead of the raw bytes themselves. Deliberately not
/// HTML-sanitized or whitespace-collapsed here — `candor-gui` already
/// applies its own `richtext` sanitization to every field it renders,
/// the same way it did when it re-parsed raw MIME directly; duplicating
/// that logic into `candor-core` just to do it twice isn't worth a new
/// cross-crate dependency.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachedMessage {
    pub subject: Option<String>,
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    /// Comma-joined, same shape `candor-gui`'s own `join_addresses`
    /// used to produce from raw bytes directly.
    pub to: String,
    pub cc: String,
    /// Wrapped in angle brackets already (`<...>`), matching what
    /// `candor-gui` needs for `In-Reply-To`/`References` when replying
    /// — `mail_parser::Message::message_id()` returns it bare.
    pub message_id: Option<String>,
    pub body_text: Option<String>,
}

/// Reads an already-cached message's extracted display content, if any.
pub fn read_cached_message(path: &Path) -> Result<Option<CachedMessage>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(path).with_context(|| format!("reading cached message at {}", path.display()))?;
    serde_json::from_slice(&raw)
        .map(Some)
        .with_context(|| format!("parsing cached message at {}", path.display()))
}

/// Returns the local path to the message's cached display content
/// ([`CachedMessage`]), fetching it from the server first if it isn't
/// already cached. Also ensures an inspection verdict is cached
/// alongside it on a fresh fetch — a failure there is logged but never
/// fails the fetch itself; seeing the body shouldn't be blocked on,
/// say, DNS being down for the DKIM check. A verdict that failed to
/// compute once stays missing until the cache is cleared (e.g. a
/// UIDVALIDITY change) — there's no raw-bytes cache left to retry it
/// from without a fresh network round trip, which is the deliberate
/// trade-off this module makes.
pub async fn fetch_body(
    account: AccountConfig,
    password: Zeroizing<String>,
    folder: String,
    uid: u32,
) -> Result<PathBuf> {
    let path = body_path(&account.id, &folder, uid)?;

    if !path.exists() {
        let (account2, password2, folder2, path2) = (account.clone(), password.clone(), folder.clone(), path.clone());
        let raw = tokio::task::spawn_blocking(move || {
            fetch_and_cache_blocking(&account2, &password2, &folder2, uid, &path2)
        })
        .await
        .context("body fetch task panicked")??;

        if let Err(e) = compute_and_cache_verdict(&path, &raw).await {
            tracing::warn!(error = %e, path = %path.display(), "failed to compute inspection verdict");
        }
    }

    Ok(path)
}

/// Fetches a message's extracted plain-text body only — used by the
/// daemon's background star-triggered body-caching (`candor-daemon`'s
/// `fill_pending_body_cache`), where there's no GUI already holding a
/// parsed copy the way `open_message` does. Just reads `fetch_body`'s
/// already-cached (or freshly fetched) `CachedMessage` rather than
/// re-parsing anything — the extraction already happened once, in
/// `fetch_body`, from the only raw bytes that ever existed for this
/// message.
pub async fn fetch_body_text(
    account: AccountConfig,
    password: Zeroizing<String>,
    folder: String,
    uid: u32,
) -> Result<Option<String>> {
    let path = fetch_body(account, password, folder, uid).await?;
    Ok(read_cached_message(&path)?.and_then(|c| c.body_text))
}

/// Fetches a message's attachments fresh, over the network, and writes
/// each one straight to `dest_dir` — never cached anywhere else, never
/// fetched as a side effect of anything but this one explicit call.
/// The raw bytes this pulls down exist only for the duration of this
/// function; nothing from them persists beyond the files written here.
/// Returns how many attachments were saved.
pub async fn fetch_and_save_attachments(
    account: AccountConfig,
    password: Zeroizing<String>,
    folder: String,
    uid: u32,
    dest_dir: PathBuf,
) -> Result<usize> {
    tokio::task::spawn_blocking(move || {
        let raw = fetch_raw_blocking(&account, &password, &folder, uid)?;
        let parsed =
            mail_parser::MessageParser::default().parse(&raw).context("parsing message for attachments")?;

        let mut saved = 0;
        for part in parsed.attachments() {
            let Some(filename) = part.attachment_name() else {
                continue;
            };
            let safe_name = sanitize_attachment_filename(filename);
            std::fs::write(dest_dir.join(&safe_name), part.contents())
                .with_context(|| format!("writing attachment {safe_name}"))?;
            saved += 1;
        }
        Ok(saved)
    })
    .await
    .context("attachment fetch task panicked")?
}

async fn compute_and_cache_verdict(body_path: &Path, raw: &[u8]) -> Result<()> {
    let vpath = verdict_path(body_path);
    if vpath.exists() {
        return Ok(());
    }

    let verdict = crate::inspect::inspect(raw).await.context("inspecting message")?;

    let json = serde_json::to_vec_pretty(&verdict).context("serializing verdict")?;
    tokio::fs::write(&vpath, json)
        .await
        .with_context(|| format!("writing verdict to {}", vpath.display()))?;
    // Same reasoning as `config::write_private` — this cache holds a
    // real DKIM/sender-authentication verdict for a specific message,
    // not opaque data, so it's tightened past the process umask's
    // default rather than left world-readable.
    tokio::fs::set_permissions(&vpath, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("setting permissions on {}", vpath.display()))?;

    Ok(())
}

/// Fetches the raw bytes, extracts a [`CachedMessage`] from them, and
/// caches *that* (never the raw bytes) at `path` — then hands the raw
/// bytes back so the caller can compute the inspection verdict from
/// them too, without a second fetch or ever writing them anywhere.
fn fetch_and_cache_blocking(
    account: &AccountConfig,
    password: &str,
    folder: &str,
    uid: u32,
    path: &Path,
) -> Result<Vec<u8>> {
    let raw = fetch_raw_blocking(account, password, folder, uid)?;

    let parsed = mail_parser::MessageParser::default().parse(&raw);
    let cached = build_cached_message(parsed.as_ref());

    if let Some(dir) = path.parent() {
        crate::config::create_private_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(&cached).context("serializing cached message")?;
    crate::config::write_private(path, &json)?;

    Ok(raw)
}

fn build_cached_message(parsed: Option<&mail_parser::Message>) -> CachedMessage {
    let Some(msg) = parsed else {
        return CachedMessage::default();
    };
    let from = msg.from().and_then(|a| a.first());
    CachedMessage {
        subject: msg.subject().map(str::to_string),
        from_address: from.and_then(|a| a.address.as_deref()).map(str::to_string),
        from_name: from.and_then(|a| a.name.as_deref()).map(str::to_string),
        to: join_addresses(msg.to()),
        cc: join_addresses(msg.cc()),
        message_id: msg.message_id().map(|s| format!("<{s}>")),
        body_text: msg.body_text(0).map(|s| s.into_owned()),
    }
}

fn join_addresses(addr: Option<&mail_parser::Address>) -> String {
    addr.map(|a| a.iter().filter_map(|x| x.address.as_deref()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

/// Caps total disk usage of this account's display-content cache
/// (`AppSettings::reading_cache_max_bytes` — never attachment bytes,
/// see this module's doc comment) across every folder. Evicts the
/// oldest-modified message groups first — a group being one message's
/// `{uid}.json` plus its `{uid}.verdict.json`, evicted together so a
/// cached message never ends up with one but not the other. Pure
/// filesystem scan, no database involved: this cache was never tracked
/// in SQLite to begin with, unlike `message_bodies`' retention
/// (`store::evict_expired_bodies`), which is a genuinely different cache
/// with its own cap. Returns how many message groups were evicted.
pub fn enforce_cache_size_cap(account_id: &str, max_bytes: u64) -> Result<usize> {
    let root = dirs::data_dir()
        .map(|p| p.join("candor").join("bodies").join(account_id))
        .context("could not resolve XDG data directory")?;
    if !root.exists() {
        return Ok(0);
    }

    // Keyed by (folder dir, uid stem) so `123.json` and
    // `123.verdict.json` land in the same group.
    let mut groups: HashMap<PathBuf, (u64, std::time::SystemTime, Vec<PathBuf>)> = HashMap::new();

    for folder_entry in std::fs::read_dir(&root).context("reading body cache root")?.flatten() {
        let folder_path = folder_entry.path();
        if !folder_path.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&folder_path) else { continue };
        for file_entry in files.flatten() {
            let path = file_entry.path();
            let Ok(meta) = file_entry.metadata() else { continue };
            let Ok(mtime) = meta.modified() else { continue };
            let Some(stem) = path.file_name().and_then(|n| n.to_str()).map(|n| {
                n.split_once('.').map(|(stem, _)| stem.to_string()).unwrap_or_else(|| n.to_string())
            }) else {
                continue;
            };

            let key = folder_path.join(stem);
            let group = groups.entry(key).or_insert((0, mtime, Vec::new()));
            group.0 += meta.len();
            group.1 = group.1.min(mtime);
            group.2.push(path);
        }
    }

    let total: u64 = groups.values().map(|(size, ..)| *size).sum();
    if total <= max_bytes {
        return Ok(0);
    }

    let mut ordered: Vec<_> = groups.into_values().collect();
    ordered.sort_by_key(|(_, mtime, _)| *mtime);

    let mut running = total;
    let mut evicted = 0usize;
    for (size, _, paths) in ordered {
        if running <= max_bytes {
            break;
        }
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
        running = running.saturating_sub(size);
        evicted += 1;
    }

    Ok(evicted)
}

/// The one place that actually talks to IMAP to pull a message's full
/// raw body (`BODY.PEEK[]`, which never sets `\Seen` — fetching bytes
/// isn't the same as the user having read the message). Shared by the
/// cache-building fetch above and the on-demand attachment fetch below
/// — both need the complete raw body, just for different reasons
/// (extracting display content + verifying DKIM, vs. pulling out
/// attachment content), and neither one persists these bytes anywhere
/// beyond its own immediate purpose.
fn fetch_raw_blocking(account: &AccountConfig, password: &str, folder: &str, uid: u32) -> Result<Vec<u8>> {
    let mut session = connect_and_login(account, password)?;

    session
        .select(folder)
        .map_err(|e| anyhow::anyhow!("selecting {folder} failed: {e}"))?;

    let uid_str = uid.to_string();
    let fetches = session
        .uid_fetch(&uid_str, "BODY.PEEK[]")
        .map_err(|e| anyhow::anyhow!("UID FETCH body failed: {e}"))?;

    let bytes = fetches
        .iter()
        .find_map(|f| f.body())
        .context("message not found or server returned no body")?
        .to_vec();

    let _ = session.logout();

    Ok(bytes)
}

/// Security regression suite for this file — see the project's
/// `SECURITY.md` for the methodology these tests are part of. Each
/// test here guards one specific, previously-real failure mode, not a
/// coverage target: if a test here would still pass with the fix it
/// guards reverted, it isn't doing its job.
#[cfg(test)]
mod security_regression_tests {
    use super::*;

    /// Guards the path-traversal fix: an attachment filename is
    /// attacker-controlled (set by whoever sent the email), and used
    /// to be joined onto the save directory unsanitized. Confirmed
    /// against the pre-fix code that every one of these would have
    /// escaped the caller's chosen directory.
    #[test]
    fn attachment_filename_traversal_payloads_are_neutralized() {
        let cases = [
            ("../../../../.bashrc", ".bashrc"),
            ("../../.ssh/authorized_keys", "authorized_keys"),
            ("/etc/cron.d/evil", "evil"),
            ("..\\..\\windows-style\\evil.exe", "evil.exe"),
            ("normal-invoice.pdf", "normal-invoice.pdf"),
        ];
        for (payload, expected) in cases {
            let safe = sanitize_attachment_filename(payload);
            assert_eq!(safe, expected, "payload {payload:?} produced {safe:?}");
            assert!(!safe.contains(".."), "payload {payload:?} still contains .. -> {safe:?}");
            assert!(
                !std::path::Path::new(&safe).is_absolute(),
                "payload {payload:?} still absolute -> {safe:?}"
            );
        }
    }

    /// A degenerate filename (empty, bare "..", or a trailing
    /// separator that leaves nothing after it) must still produce
    /// *something* writable, not silently vanish or panic.
    #[test]
    fn attachment_filename_degenerate_cases_fall_back_to_a_generic_name() {
        for payload in ["", "..", ".", "../", "/"] {
            let safe = sanitize_attachment_filename(payload);
            assert!(!safe.is_empty(), "payload {payload:?} produced an empty name");
            assert_ne!(safe, "..", "payload {payload:?} still resolved to ..");
        }
    }

    /// Guards the narrower, server-side sibling of the same bug: a
    /// folder name (trusted input in this project's threat model, but
    /// hardened anyway) that's exactly ".." would otherwise traverse
    /// the on-disk cache path up one level, since it contains no `/`
    /// or `\` for the flattening step to ever catch.
    #[test]
    fn folder_cache_path_traversal_payloads_are_neutralized() {
        for payload in ["..", ".", ""] {
            let safe = sanitize_folder(payload);
            assert_ne!(safe, "..", "payload {payload:?} still resolved to ..");
            assert_ne!(safe, ".", "payload {payload:?} still resolved to .");
            assert!(!safe.is_empty(), "payload {payload:?} produced an empty name");
        }
        // The common, legitimate case — a real IMAP hierarchy —
        // mustn't be broken by the hardening above.
        assert_eq!(sanitize_folder("Work/2026"), "Work_2026");
    }
}

/// Adversarial-input tests — deliberately distinct from
/// `security_regression_tests` above. Those confirm a specific fix
/// produces the *correct* result; these confirm the sanitizers *fail
/// safely* against input that's malformed or actively hostile in ways
/// no legitimate sender or server would produce, which is still the
/// expected shape of real input per this project's zero-trust policy
/// (see `SECURITY.md`). The only requirement for a test in here is
/// "doesn't panic, and never produces a traversal-capable result" —
/// not a specific expected output string.
#[cfg(test)]
mod adversarial_input_tests {
    use super::*;

    #[test]
    fn attachment_filename_never_panics_or_escapes_regardless_of_input() {
        let cases = [
            String::new(),
            "\0".to_string(),
            "a\0/../../etc/passwd".to_string(),
            "/".repeat(500),
            "../".repeat(500),
            "A".repeat(10_000),
            "😀🔥💀".repeat(200),
            "\u{202E}gpj.exe".to_string(), // right-to-left override trick
            "   ".to_string(),
            "....".to_string(),
            "CON".to_string(), // Windows-reserved name; harmless on Linux, worth confirming no special-case panic
        ];
        for payload in cases {
            let safe = sanitize_attachment_filename(&payload);
            assert!(!safe.is_empty(), "payload {payload:?} produced an empty result");
            assert!(
                !std::path::Path::new(&safe).is_absolute(),
                "payload {payload:?} -> {safe:?} is still absolute"
            );
            // The real property that actually matters: joining onto
            // some directory and immediately asking for that joined
            // path's parent must land back on that same directory,
            // not anywhere else — this is what "can't escape
            // dest_dir" means in practice. A naive `!safe.contains("..")`
            // check used to sit here instead and was simply wrong: a
            // filename like "...." contains the substring ".." without
            // being a traversal at all (only "."/".." as a *complete*
            // path component is special to the filesystem — confirmed
            // empirically, not assumed, after this exact test failed
            // against genuinely safe production behavior).
            let base = std::path::Path::new("/tmp/candor-test-dest");
            let joined = base.join(&safe);
            assert_eq!(
                joined.parent(),
                Some(base),
                "payload {payload:?} -> {safe:?} joined outside dest_dir: {joined:?}"
            );
        }
    }

    #[test]
    fn folder_sanitization_never_panics_or_escapes_regardless_of_input() {
        let cases = [
            String::new(),
            "\0".to_string(),
            "/".repeat(500),
            "../../../".repeat(100),
            "A".repeat(10_000),
            "😀/🔥\\💀".repeat(100),
            "\u{202E}..\u{202E}".to_string(),
        ];
        for payload in cases {
            let safe = sanitize_folder(&payload);
            assert!(!safe.is_empty(), "payload {payload:?} produced an empty result");
            assert_ne!(safe, "..", "payload {payload:?} resolved to ..");
            assert_ne!(safe, ".", "payload {payload:?} resolved to .");
            assert!(
                !safe.contains('/') && !safe.contains('\\'),
                "payload {payload:?} -> {safe:?} still contains a path separator"
            );
        }
    }
}
