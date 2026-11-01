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
    // hop, and a sender can also just forge one into the original
    // message before it's ever delivered) — we trust only the first
    // (topmost), on the standard assumption that it's the one our own
    // receiving provider just prepended, with anything the message
    // already had pushed further down. A client can't reliably tell
    // which hop is actually trustworthy without knowing its own
    // provider's hostname, so this is a best-effort read, not
    // independent verification — unlike the DKIM check below.
    //
    // `Message::header_raw` was tried here first and empirically
    // confirmed (not assumed) to return the *last* matching header, not
    // the first — the opposite of what this function needs, and exactly
    // backwards from a now-removed comment that had assumed otherwise.
    // `header_values` iterates in document order; `.next()` is the
    // actual topmost occurrence.
    let Some(header) = message.header_values("Authentication-Results").next().and_then(|v| v.as_text())
    else {
        return;
    };
    verdict.spf_pass = extract_auth_result(header, "spf");
    verdict.dmarc_pass = extract_auth_result(header, "dmarc");
}

/// Per RFC 8601, an Authentication-Results header is `;`-separated
/// `resinfo` clauses, each starting with its own `method=result` pair
/// (e.g. `spf=pass smtp.mailfrom=example.com`) — properties like that
/// `smtp.mailfrom=` are allowed to echo back sender-controlled data
/// (the envelope-from address, a header.from value, etc.), so this
/// deliberately checks each clause's *own leading* `method=` token,
/// not a flat substring search across the whole header text. A naive
/// `header.find("spf=")` would also match "spf=" appearing anywhere —
/// including inside some other clause's property value — which isn't
/// exploitable given how the clauses are actually ordered by a
/// well-behaved server, but there's no reason to rely on that when
/// parsing by clause is just as simple and removes the question
/// entirely.
fn extract_auth_result(header: &str, mechanism: &str) -> Option<bool> {
    let needle = format!("{mechanism}=");
    for clause in header.split(';') {
        let clause = clause.trim();
        let lower = clause.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(&needle) {
            let word: String = rest.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            return match word.as_str() {
                "pass" => Some(true),
                "fail" | "softfail" | "none" | "neutral" | "temperror" | "permerror" => Some(false),
                _ => None,
            };
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for a real bug: `inspect_provider_auth_results`
    /// used to read `Message::header_raw`, which — confirmed
    /// empirically against this exact pinned `mail-parser` version, not
    /// assumed from its documentation (which doesn't specify this) —
    /// returns the *last* matching header when a name repeats, not the
    /// first. That's exactly backwards: a forged `Authentication-Results`
    /// header a sender embeds in the original message ends up *below*
    /// the real receiving server's own header once the server prepends
    /// it, so trusting the last occurrence means trusting the forged
    /// one over the real one. This message simulates exactly that
    /// delivery shape — legitimate header on top, forged one beneath —
    /// and asserts the legitimate (first) values win.
    #[test]
    fn auth_results_trusts_the_first_header_not_the_last() {
        let raw = b"From: attacker@evil.com\r\n\
Authentication-Results: legit-server.example.com; spf=pass smtp.mailfrom=attacker.com; dmarc=pass\r\n\
Authentication-Results: forged-by-sender.invalid; spf=fail smtp.mailfrom=victim.com; dmarc=fail\r\n\
Subject: test\r\n\
\r\n\
body\r\n";
        let message = MessageParser::default().parse(raw).unwrap();
        let mut verdict = MessageVerdict::default();
        inspect_provider_auth_results(&message, &mut verdict);

        assert_eq!(verdict.spf_pass, Some(true));
        assert_eq!(verdict.dmarc_pass, Some(true));
    }

    /// `extract_auth_result` parses by `;`-separated clause, matching
    /// only a clause's own leading `method=` token — not a flat
    /// substring search across the whole header. This constructs a
    /// header where the `dkim=` clause's own property happens to
    /// contain the literal text "spf=pass" (plausible if a sender gets
    /// to influence an echoed-back property value, however narrow that
    /// path really is) positioned *before* the real `spf=` clause, and
    /// asserts the real clause's result is still what gets picked up.
    #[test]
    fn auth_result_extraction_is_not_confused_by_substrings_in_other_clauses() {
        let header =
            "mx.example.com; dkim=fail header.d=\"spf=pass lookalike\"; spf=fail smtp.mailfrom=attacker.com";
        assert_eq!(extract_auth_result(header, "spf"), Some(false));
    }

    /// A message with only one Authentication-Results header (the
    /// common case) still needs to parse correctly — makes sure the
    /// fix for the above didn't just special-case the multi-header
    /// scenario.
    #[test]
    fn auth_results_single_header_still_works() {
        let raw = b"From: someone@example.com\r\n\
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=someone@example.com; dmarc=fail\r\n\
Subject: test\r\n\
\r\n\
body\r\n";
        let message = MessageParser::default().parse(raw).unwrap();
        let mut verdict = MessageVerdict::default();
        inspect_provider_auth_results(&message, &mut verdict);

        assert_eq!(verdict.spf_pass, Some(false));
        assert_eq!(verdict.dmarc_pass, Some(false));
    }
}

/// Adversarial-input tests — deliberately distinct from `mod tests`
/// above. Those confirm a specific fix produces the *correct* result;
/// these confirm the inspection pipeline *fails safely* against input
/// that's actively hostile or malformed, which is the expected shape
/// of real email per this project's zero-trust-toward-email-content
/// policy (see `SECURITY.md`). A test in here is supposed to exercise
/// a failure path, not a success path — if one of these ever starts
/// needing a happy assertion to stay meaningful, it's drifted out of
/// this module's purpose and belongs in `mod tests` instead.
#[cfg(test)]
mod adversarial_input_tests {
    use super::*;

    /// Every one of these is either empty, truncated mid-structure, or
    /// outright not a valid email — the inspection pipeline's job is
    /// to not crash on any of it, not to make sense of it. A real
    /// inbox will eventually contain something this malformed, whether
    /// from a broken sender or a deliberately crafted attack, and a
    /// panic here would take down the daemon process handling every
    /// other account's mail too.
    #[test]
    fn garbage_bytes_never_panic_the_parser() {
        let cases: Vec<&[u8]> = vec![
            b"",
            b"\x00\x01\x02\xff\xfe garbage not an email at all",
            b"From: \r\n\r\n",
            b"Authentication-Results: ; spf= dmarc= spf=spf=spf=\r\n\r\n",
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n--x\r\n--x\r\n--x\r\n",
            b"Subject: \xc3\x28 invalid utf8 sequence\r\n\r\n",
            b"From: a@b\r\nFrom: c@d\r\nFrom: e@f\r\n\r\nduplicate From headers",
        ];
        for raw in cases {
            let _ = MessageParser::default().parse(raw);
        }
    }

    /// A message can legitimately nest multipart sections a few levels
    /// deep; nothing legitimate nests them thousands of levels deep.
    /// This is exactly the shape of a resource-exhaustion attack
    /// (a tiny message that's expensive or crash-prone to parse) — the
    /// assertion here is just "this returns in a reasonable time and
    /// doesn't panic," not anything about the parsed result's content.
    #[test]
    fn pathologically_nested_mime_does_not_crash_or_hang() {
        let mut raw = String::from("Content-Type: multipart/mixed; boundary=b0\r\n\r\n");
        for i in 0..2000 {
            raw.push_str(&format!("--b0\r\nContent-Type: multipart/mixed; boundary=b{}\r\n\r\n", i + 1));
        }
        let _ = MessageParser::default().parse(raw.as_bytes());
    }

    /// `extract_auth_result` specifically, fed header text that's
    /// hostile in ways a real mail server would never produce but a
    /// crafted/forged header could: absurdly long, deeply repeated
    /// delimiters, no valid clause at all. The only requirement is
    /// "returns, doesn't panic" — `None` is the correct answer for
    /// all of these, same as for a header this function genuinely
    /// doesn't understand.
    #[test]
    fn auth_result_extraction_never_panics_on_hostile_header_text() {
        let cases = [
            "",
            ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;",
            "spf=",
            "spf=spf=spf=spf=spf=spf=spf=pass",
            &"spf=pass;".repeat(10_000),
            "spf=\u{0}\u{0}\u{0}pass",
            "spf=pásss", // non-ASCII near the result word
        ];
        for header in cases {
            let _ = extract_auth_result(header, "spf");
            let _ = extract_auth_result(header, "dmarc");
        }
    }
}
