//! Runs a synced message's raw bytes through the privacy/security
//! inspection pipeline described in the project's design: sender
//! authenticity, HTML sanitization with default-deny remote content,
//! tracking-pixel heuristics, link anchor-vs-href mismatch detection, and
//! attachment safety checks.
//!
//! This never trusts litehtml (or any future renderer) to be the security
//! boundary — sanitization happens here, independent of rendering, so the
//! [`MessageVerdict::sanitized_html`] handed to a renderer has already had
//! every remote-fetch vector (and `<script>`, forms, iframes, etc.) removed.

use std::sync::{Arc, LazyLock, Mutex};

use ammonia::Builder as HtmlSanitizer;
use anyhow::{Context, Result};
use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};
use mail_parser::{Message, MessageParser, MimeHeaders};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkWarningReason {
    /// The visible link text itself looks like a URL/domain, but it isn't
    /// the domain the link actually points to.
    TextDomainMismatch,
    /// The link target's domain is punycode (contains non-Latin
    /// characters) — not inherently malicious, but a common lookalike-
    /// domain vector worth a user's attention.
    PunycodeDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkWarning {
    pub display_text: String,
    pub href: String,
    pub reason: LinkWarningReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentWarningReason {
    DangerousExtension,
    /// A safe-looking extension immediately followed by a dangerous one,
    /// e.g. `invoice.pdf.exe` — relies on a quick glance only seeing ".pdf".
    DoubleExtension,
    /// A Unicode bidi-override character in the filename, used to make an
    /// extension read differently than the actual bytes on disk.
    BidiOverride,
    /// The file's actual content (sniffed by magic bytes) doesn't match
    /// what its extension claims.
    MismatchedType { claimed: String, detected: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentWarning {
    pub filename: String,
    pub reason: AttachmentWarningReason,
}

/// Every attachment on the message, regardless of whether it triggered a
/// warning — the UI lists these so the user can save any of them; the
/// warnings above are what it calls out before letting that happen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub filename: String,
    pub size: usize,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageVerdict {
    /// `None` if the message has no DKIM-Signature at all.
    pub dkim_verified: Option<bool>,
    /// Whether a *passing* DKIM signature's domain actually aligns with
    /// the visible From address — a message can have a valid DKIM
    /// signature from an unrelated domain and still be spoofing the
    /// display name.
    pub dkim_aligned: Option<bool>,
    /// As reported by the Authentication-Results header our own mail
    /// provider's receiving server already added — we don't re-verify SPF
    /// ourselves, since that requires trusting a self-reported originating
    /// IP from the Received chain, which a client can't do reliably.
    pub spf_pass: Option<bool>,
    /// Same caveat as `spf_pass`.
    pub dmarc_pass: Option<bool>,
    /// The display name contains what looks like a different domain/email
    /// than the real From address (e.g. `"security@paypal.com" <x@evil.ru>`).
    pub sender_display_mismatch: bool,
    pub reply_to_mismatch: bool,
    pub from_domain_is_punycode: bool,
    /// HTML with every remote-fetch vector, `<script>`, form, iframe, and
    /// event handler already stripped. Safe to hand to a renderer as-is.
    pub sanitized_html: Option<String>,
    /// Remote image URLs that were present and got stripped from
    /// `sanitized_html` by default.
    pub blocked_remote_resources: Vec<String>,
    /// Subset of `blocked_remote_resources` that additionally look like
    /// tracking pixels (tiny dimensions or a known tracker domain) — still
    /// blocked either way, this is just extra context if the user opts to
    /// load images for a sender they trust.
    pub suspected_trackers: Vec<String>,
    /// Same sanitization as `sanitized_html` — script, forms, iframes,
    /// event handlers, CSS all still stripped — except `<img src>` is left
    /// in place instead of removed. Never rendered by default; only used
    /// if the user explicitly opts in to loading images for a given
    /// message, at which point those `src` URLs are the ones fetched.
    pub sanitized_html_with_images: Option<String>,
    pub link_warnings: Vec<LinkWarning>,
    pub attachment_warnings: Vec<AttachmentWarning>,
    pub attachments: Vec<AttachmentInfo>,
}

pub async fn inspect(raw: &[u8]) -> Result<MessageVerdict> {
    let message = MessageParser::default()
        .parse(raw)
        .context("parsing message for inspection")?;

    let mut verdict = MessageVerdict::default();

    let from_domain = message
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address.as_deref())
        .and_then(domain_of);

    inspect_sender(&message, from_domain.as_deref(), &mut verdict);
    inspect_provider_auth_results(&message, &mut verdict);
    inspect_dkim(raw, from_domain.as_deref(), &mut verdict).await;

    if let Some(html) = message.body_html(0) {
        inspect_html(&html, &mut verdict);
    }

    inspect_attachments(&message, &mut verdict);

    Ok(verdict)
}

fn domain_of(address: &str) -> Option<String> {
    address.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase())
}

/// A string that's structurally shaped like a domain name: at least two
/// dot-separated labels of alphanumerics/hyphens.
fn domain_like(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.');
    let looks_like_domain = s.split('.').count() >= 2
        && s.split('.')
            .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    looks_like_domain.then(|| s.to_ascii_lowercase())
}

/// A link's visible text is often a full URL ("https://paypal.com/login"),
/// not a bare domain — pull just the host out before checking it.
fn domain_in_link_text(text: &str) -> Option<String> {
    let text = text.trim();
    let after_scheme = text.split_once("://").map(|(_, rest)| rest).unwrap_or(text);
    let host = after_scheme.split(['/', '?', '#']).next().unwrap_or(after_scheme);
    domain_like(host)
}

fn is_punycode(domain: &str) -> bool {
    domain.split('.').any(|label| label.starts_with("xn--"))
}

fn inspect_sender(message: &Message, from_domain: Option<&str>, verdict: &mut MessageVerdict) {
    let Some(from_domain) = from_domain else {
        return;
    };
    verdict.from_domain_is_punycode = is_punycode(from_domain);

    if let Some(name) = message.from().and_then(|a| a.first()).and_then(|a| a.name.as_deref()) {
        verdict.sender_display_mismatch = display_name_embeds_different_domain(name, from_domain);
    }

    if let Some(reply_domain) = message
        .reply_to()
        .and_then(|a| a.first())
        .and_then(|a| a.address.as_deref())
        .and_then(domain_of)
    {
        verdict.reply_to_mismatch = !reply_domain.eq_ignore_ascii_case(from_domain);
    }
}

/// Scans a display name for a domain-like or email-like substring and
/// checks whether it names a different domain than the real sender — the
/// classic `"PayPal <security@paypal.com>" <attacker@evil.ru>` trick.
fn display_name_embeds_different_domain(name: &str, real_domain: &str) -> bool {
    for token in name.split(|c: char| c.is_whitespace() || "<>()[]\"',;:".contains(c)) {
        // Try the token as a bare domain, and — since the classic version
        // of this trick uses a full email address as the display name —
        // also try whatever follows an '@' in it.
        let candidates = [Some(token), token.rsplit_once('@').map(|(_, d)| d)];
        if candidates
            .into_iter()
            .flatten()
            .filter_map(domain_like)
            .any(|candidate| !candidate.eq_ignore_ascii_case(real_domain))
        {
            return true;
        }
    }
    false
}

fn inspect_provider_auth_results(message: &Message, verdict: &mut MessageVerdict) {
    // Multiple Authentication-Results headers can exist (one per relay
    // hop); we trust only the first (topmost), on the standard assumption
    // that it's the one our own receiving provider just added. A client
    // can't reliably tell which hop is actually trustworthy without
    // knowing its own provider's hostname, so this is a best-effort read,
    // not independent verification — unlike the DKIM check below.
    let Some(header) = message.header_raw("Authentication-Results") else {
        return;
    };
    verdict.spf_pass = extract_auth_result(header, "spf");
    verdict.dmarc_pass = extract_auth_result(header, "dmarc");
}

fn extract_auth_result(header: &str, mechanism: &str) -> Option<bool> {
    let needle = format!("{mechanism}=");
    let lower = header.to_ascii_lowercase();
    let idx = lower.find(&needle)?;
    let rest = &header[idx + needle.len()..];
    let word: String = rest.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    match word.to_ascii_lowercase().as_str() {
        "pass" => Some(true),
        "fail" | "softfail" | "none" | "neutral" | "temperror" | "permerror" => Some(false),
        _ => None,
    }
}

/// Independently verifies DKIM ourselves — unlike SPF/DMARC, this needs no
/// trusted IP: it's a cryptographic signature over the message plus a DNS
/// lookup for the signer's public key, both of which we can check directly.
async fn inspect_dkim(raw: &[u8], from_domain: Option<&str>, verdict: &mut MessageVerdict) {
    let Ok(authenticator) = MessageAuthenticator::new_system_conf() else {
        return;
    };
    let Some(authenticated) = AuthenticatedMessage::parse(raw) else {
        return;
    };

    let results = authenticator.verify_dkim(&authenticated).await;
    if results.is_empty() {
        return;
    }

    verdict.dkim_verified = Some(results.iter().any(|r| matches!(r.result(), DkimResult::Pass)));

    if let Some(from_domain) = from_domain {
        verdict.dkim_aligned = Some(results.iter().any(|r| {
            matches!(r.result(), DkimResult::Pass)
                && r.signature().is_some_and(|sig| domain_aligns(&sig.d, from_domain))
        }));
    }
}

/// Relaxed alignment: the signing domain equals, or is a parent of, the
/// visible From domain (e.g. `d=example.com` covers `alerts.example.com`).
fn domain_aligns(signing_domain: &str, from_domain: &str) -> bool {
    let signing_domain = signing_domain.to_ascii_lowercase();
    let from_domain = from_domain.to_ascii_lowercase();
    from_domain == signing_domain || from_domain.ends_with(&format!(".{signing_domain}"))
}

static IMG_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<img\b([^>]*)>").unwrap());
static ANCHOR_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<a\b([^>]*)>(.*?)</a>").unwrap());
static STRIP_TAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<[^>]*>").unwrap());

fn extract_attr(attrs: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"(?is){name}\s*=\s*"([^"]*)""#)).ok()?;
    re.captures(attrs).map(|c| c[1].to_string())
}

/// Known email-tracking services, purely as a secondary signal — the
/// primary defense is that every remote image is blocked by default
/// regardless of whether it matches this (necessarily incomplete) list.
const KNOWN_TRACKER_SUBSTRINGS: &[&str] = &[
    "list-manage.com/track",
    "mailtrack.io",
    "mandrillapp.com/track",
    "sendgrid.net/wf/open",
    "click.e.",
    "trk.klclick",
    "mkto-ab", // Marketo
    "hubspotlinks.com",
];

fn inspect_html(html: &str, verdict: &mut MessageVerdict) {
    // Tracking-pixel heuristics and link-mismatch detection run on the
    // *original* markup — best-effort signals only, allowed to miss edge
    // cases. The actual content-safety enforcement below (sanitization)
    // is HTML-aware (via ammonia/html5ever), not regex-based, and doesn't
    // depend on these heuristics being complete.
    verdict.suspected_trackers = find_tracking_pixels(html);
    verdict.link_warnings = find_link_warnings(html);

    let blocked = Arc::new(Mutex::new(Vec::new()));
    let sanitized = sanitizer(Arc::clone(&blocked)).clean(html).to_string();

    verdict.sanitized_html = Some(sanitized);
    verdict.blocked_remote_resources = Arc::try_unwrap(blocked)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();

    // Same sanitizer, minus the img-src-stripping filter — everything
    // else (script, forms, iframes, event handlers, CSS) is still gone.
    verdict.sanitized_html_with_images = Some(HtmlSanitizer::default().clean(html).to_string());
}

fn sanitizer(blocked: Arc<Mutex<Vec<String>>>) -> HtmlSanitizer<'static> {
    let mut builder = HtmlSanitizer::default();
    // Defaults already strip <script>, <style>, <iframe>, <object>,
    // <embed>, <form>, event-handler attributes, and inline `style=`
    // (CSS is not in the default allowlist at all, which closes the
    // background-image/@import/@font-face vector without needing a
    // litehtml-layer resource interceptor). This filter closes the
    // remaining vector ammonia itself doesn't know is a problem: remote
    // images, which it allows by default since it only cares about XSS,
    // not network-level tracking.
    builder.attribute_filter(move |element, attribute, value| {
        if element == "img" && attribute == "src" {
            blocked.lock().unwrap().push(value.to_string());
            None
        } else {
            Some(value.into())
        }
    });
    builder
}

fn find_tracking_pixels(html: &str) -> Vec<String> {
    IMG_TAG
        .captures_iter(html)
        .filter_map(|cap| {
            let attrs = &cap[1];
            let src = extract_attr(attrs, "src")?;
            let width = extract_attr(attrs, "width").and_then(|w| w.parse::<u32>().ok());
            let height = extract_attr(attrs, "height").and_then(|h| h.parse::<u32>().ok());
            let tiny = matches!((width, height), (Some(w), Some(h)) if w <= 2 && h <= 2);
            let known = KNOWN_TRACKER_SUBSTRINGS.iter().any(|d| src.contains(d));
            (tiny || known).then_some(src)
        })
        .collect()
}

fn find_link_warnings(html: &str) -> Vec<LinkWarning> {
    ANCHOR_TAG
        .captures_iter(html)
        .filter_map(|cap| {
            let attrs = &cap[1];
            let inner = &cap[2];
            let href = extract_attr(attrs, "href")?;
            let href_domain = url::Url::parse(&href).ok().and_then(|u| u.domain().map(str::to_string));
            let text = STRIP_TAGS.replace_all(inner, "").trim().to_string();

            if let Some(text_domain) = domain_in_link_text(&text) {
                if let Some(href_domain) = &href_domain {
                    if !text_domain.eq_ignore_ascii_case(href_domain) {
                        return Some(LinkWarning {
                            display_text: text,
                            href,
                            reason: LinkWarningReason::TextDomainMismatch,
                        });
                    }
                }
            }

            if href_domain.as_deref().is_some_and(is_punycode) {
                return Some(LinkWarning {
                    display_text: text,
                    href,
                    reason: LinkWarningReason::PunycodeDomain,
                });
            }

            None
        })
        .collect()
}

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "msi",
    "msp", "ps1", "ps1xml", "psc1", "reg", "lnk", "jar", "apk", "appimage", "sh", "bash", "deb",
    "rpm", "hta", "chm", "cpl", "msc", "gadget",
];

const SAFE_LOOKING_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt",
    "zip", "csv",
];

fn has_dangerous_extension(filename: &str) -> bool {
    extension_of(filename).is_some_and(|ext| DANGEROUS_EXTENSIONS.contains(&ext.as_str()))
}

fn has_double_extension(filename: &str) -> bool {
    let parts: Vec<&str> = filename.rsplit('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let last = parts[0].to_ascii_lowercase();
    let second_last = parts[1].to_ascii_lowercase();
    DANGEROUS_EXTENSIONS.contains(&last.as_str()) && SAFE_LOOKING_EXTENSIONS.contains(&second_last.as_str())
}

fn contains_bidi_override(filename: &str) -> bool {
    filename
        .chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
}

fn extension_of(filename: &str) -> Option<String> {
    filename.rsplit('.').next().map(|e| e.to_ascii_lowercase())
}

fn normalize_extension(ext: &str) -> String {
    match ext.to_ascii_lowercase().as_str() {
        "jpg" => "jpeg".to_string(),
        "htm" => "html".to_string(),
        other => other.to_string(),
    }
}

fn inspect_attachments(message: &Message, verdict: &mut MessageVerdict) {
    for part in message.attachments() {
        let Some(filename) = part.attachment_name() else {
            continue;
        };
        let filename = filename.to_string();
        let detected_kind = infer::get(part.contents());

        verdict.attachments.push(AttachmentInfo {
            filename: filename.clone(),
            size: part.contents().len(),
            content_type: detected_kind.map(|k| k.mime_type().to_string()),
        });

        if contains_bidi_override(&filename) {
            verdict.attachment_warnings.push(AttachmentWarning {
                filename: filename.clone(),
                reason: AttachmentWarningReason::BidiOverride,
            });
        }
        if has_double_extension(&filename) {
            verdict.attachment_warnings.push(AttachmentWarning {
                filename: filename.clone(),
                reason: AttachmentWarningReason::DoubleExtension,
            });
        }
        if has_dangerous_extension(&filename) {
            verdict.attachment_warnings.push(AttachmentWarning {
                filename: filename.clone(),
                reason: AttachmentWarningReason::DangerousExtension,
            });
        }

        if let (Some(kind), Some(claimed)) = (detected_kind, extension_of(&filename)) {
            let detected = kind.extension().to_string();
            if normalize_extension(&detected) != normalize_extension(&claimed) {
                verdict.attachment_warnings.push(AttachmentWarning {
                    filename: filename.clone(),
                    reason: AttachmentWarningReason::MismatchedType { claimed, detected },
                });
            }
        }
    }
}
