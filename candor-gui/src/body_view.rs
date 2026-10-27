//! Turns `richtext::Segment`s into a real, populated `GtkTextBuffer` —
//! and the click handling that goes with it: looking up which link (if
//! any) sits under a click, and building the per-link "where does this
//! actually go" confirmation text. This is the GTK-side half of the
//! rewrite away from rasterizing the message body with litehtml; the
//! other half (`richtext`) only produces plain data so the (comparatively
//! expensive) HTML walk can still happen off the main thread — none of
//! this module's types are safe to touch off it, since `GtkTextBuffer`
//! and friends are not thread-safe.

use gtk::pango;
use gtk::prelude::*;
use relm4::gtk;

use candor_core::inspect::{LinkWarning, LinkWarningReason};

use crate::richtext::{Segment, TextStyle};

/// An inline image placeholder still waiting to be revealed, with enough
/// to build its placeholder widget and, once clicked, fetch the real
/// image.
pub struct PendingImage {
    pub anchor: gtk::TextChildAnchor,
    pub src: String,
    pub alt: String,
}

/// Clears `buffer` and repopulates it from `segments`, returning every
/// inline image placeholder it created. The caller still needs to attach
/// a real placeholder widget to each anchor via
/// `TextView::add_child_at_anchor` — that needs the `TextView`, not just
/// the buffer, which is why it isn't done here.
pub fn populate(buffer: &gtk::TextBuffer, segments: &[Segment]) -> Vec<PendingImage> {
    buffer.set_text("");
    remove_previous_link_tags(buffer);
    let tags = NamedTags::new(buffer);
    let mut images = Vec::new();
    // How many newlines are already at the end of the buffer — lets
    // `Break`/`ParagraphBreak` top up to what they need instead of
    // blindly inserting, which is what collapses runs of consecutive
    // breaks (extremely common: sanitized email HTML is full of empty
    // wrapper `<div>`s) down to at most one blank line, and suppresses
    // leading breaks entirely (starting at 2 as if already at a
    // boundary).
    let mut trailing_newlines: usize = 2;

    for seg in segments {
        match seg {
            Segment::Text { text, styles } => {
                let text = if trailing_newlines > 0 { text.trim_start() } else { text.as_str() };
                if text.is_empty() {
                    continue;
                }
                let tag_owned: Vec<gtk::TextTag> = styles.iter().map(|s| tags.resolve(buffer, s)).collect();
                let tag_refs: Vec<&gtk::TextTag> = tag_owned.iter().collect();
                let mut end = buffer.end_iter();
                buffer.insert_with_tags(&mut end, text, &tag_refs);
                trailing_newlines = 0;
            }
            Segment::Image { src, alt } => {
                let mut end = buffer.end_iter();
                let anchor = buffer.create_child_anchor(&mut end);
                images.push(PendingImage { anchor, src: src.clone(), alt: alt.clone() });
                trailing_newlines = 0;
            }
            Segment::Break => insert_newlines(buffer, &mut trailing_newlines, 1),
            Segment::ParagraphBreak => insert_newlines(buffer, &mut trailing_newlines, 2),
        }
    }

    images
}

fn insert_newlines(buffer: &gtk::TextBuffer, trailing: &mut usize, want: usize) {
    if *trailing >= want {
        return;
    }
    let needed = want - *trailing;
    let mut end = buffer.end_iter();
    buffer.insert(&mut end, &"\n".repeat(needed));
    *trailing += needed;
}

/// Named (reusable) style tags, created once per buffer population and
/// looked up by `TextStyle` variant. Links don't go through this — each
/// one gets its own anonymous tag (see `apply_link_tag`), since each
/// needs to carry its own distinct URL.
struct NamedTags {
    bold: gtk::TextTag,
    italic: gtk::TextTag,
    heading: gtk::TextTag,
    blockquote: gtk::TextTag,
    monospace: gtk::TextTag,
}

impl NamedTags {
    fn new(buffer: &gtk::TextBuffer) -> Self {
        let make = |name: &str, props: &[(&str, &dyn ToValue)]| {
            buffer.tag_table().lookup(name).unwrap_or_else(|| {
                buffer.create_tag(Some(name), props).expect("creating a fresh text tag should not fail")
            })
        };
        Self {
            // Unlike `style` (genuinely a `PangoStyle`-typed property),
            // `weight` is a plain `gint` at the GObject level — handing
            // it the `pango::Weight` enum directly panics at runtime
            // ("expected: 'gint', got: 'PangoWeight'"), confirmed live.
            // `PANGO_WEIGHT_BOLD` is a stable part of Pango's public API.
            bold: make("rt-bold", &[("weight", &PANGO_WEIGHT_BOLD)]),
            italic: make("rt-italic", &[("style", &pango::Style::Italic)]),
            heading: make("rt-heading", &[("weight", &PANGO_WEIGHT_BOLD), ("scale", &1.2_f64)]),
            blockquote: make(
                "rt-blockquote",
                &[("left-margin", &24_i32), ("style", &pango::Style::Italic)],
            ),
            monospace: make("rt-mono", &[("family", &"monospace")]),
        }
    }

    /// Link styles are per-URL, so they're not part of this cache — see
    /// `new_link_tag`. Returns an owned (cheaply-cloned, refcounted)
    /// handle rather than a borrow so link tags don't need a `'static`
    /// lifetime — they're already kept alive correctly by the buffer's
    /// own tag table, which `remove_previous_link_tags` sweeps on each
    /// new message so that lifetime doesn't become an unbounded leak.
    fn resolve(&self, buffer: &gtk::TextBuffer, style: &TextStyle) -> gtk::TextTag {
        match style {
            TextStyle::Bold => self.bold.clone(),
            TextStyle::Italic => self.italic.clone(),
            TextStyle::Heading => self.heading.clone(),
            TextStyle::Blockquote => self.blockquote.clone(),
            TextStyle::Monospace => self.monospace.clone(),
            TextStyle::Link(href) => new_link_tag(buffer, href),
        }
    }
}

/// Creates a fresh tag for this one link occurrence, named so the href
/// can be recovered later from `TextTag::name()` alone (see `href_at`) —
/// avoids a side table or `unsafe` `set_data`/`data` entirely. Tag names
/// must be unique within a `TextTagTable`, and the same href can
/// legitimately appear more than once in one message (e.g. a repeated
/// "view in browser" link), so the name includes a counter, not just the
/// href.
fn new_link_tag(buffer: &gtk::TextBuffer, href: &str) -> gtk::TextTag {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let name = format!("{LINK_TAG_PREFIX}{id}:{href}");
    buffer
        .create_tag(
            Some(&name),
            &[("foreground", &"#1c71d8"), ("underline", &pango::Underline::Single)],
        )
        .expect("creating a fresh link tag should not fail")
}

/// Every call to `populate` creates fresh, uniquely-named link tags (see
/// `new_link_tag`) — `TextBuffer::set_text("")` clears content but not
/// the tag table, so without this, every message opened over a long
/// session would leave its link tags behind forever.
fn remove_previous_link_tags(buffer: &gtk::TextBuffer) {
    let table = buffer.tag_table();
    let mut stale = Vec::new();
    table.foreach(|tag| {
        if tag.name().is_some_and(|n| n.starts_with(LINK_TAG_PREFIX)) {
            stale.push(tag.clone());
        }
    });
    for tag in stale {
        table.remove(&tag);
    }
}

const LINK_TAG_PREFIX: &str = "candor-link-";
const PANGO_WEIGHT_BOLD: i32 = 700;

/// Looks up which link (if any) sits at the given *widget-space*
/// coordinates — converted to buffer coordinates internally, which
/// matters once the view has been scrolled.
pub fn href_at(view: &gtk::TextView, x: f64, y: f64) -> Option<String> {
    let (bx, by) = view.window_to_buffer_coords(gtk::TextWindowType::Widget, x as i32, y as i32);
    let iter = view.iter_at_location(bx, by)?;
    iter.tags().into_iter().find_map(|tag| {
        let name = tag.name()?;
        let rest = name.strip_prefix(LINK_TAG_PREFIX)?;
        rest.split_once(':').map(|(_, href)| href.to_string())
    })
}

/// The registrable domain (eTLD+1 — e.g. `accounts.google.com` ->
/// `google.com`) called out on its own line, so a look-alike subdomain
/// or lookalike path can't visually bury the part that actually
/// determines where the link goes. Falls back to the raw host if the
/// public-suffix lookup can't parse it (unusual, but better to show
/// something than nothing).
pub fn describe_link_destination(url: &str, warning: Option<&LinkWarning>) -> String {
    let parsed = url::Url::parse(url).ok();
    let host = parsed.as_ref().and_then(|u| u.host_str());

    let mut out = String::new();
    if let Some(host) = host {
        let registrable = psl::domain_str(host).unwrap_or(host);
        // Always its own clearly-labeled line now (not a parenthetical
        // tucked under "Going to"), and always shown — even when it's
        // identical to the registrable domain — so its position in the
        // message is consistent rather than something that shifts
        // around depending on the link.
        out.push_str(&format!("GOING TO: {registrable}\n"));
        out.push_str(&format!("Full host: {host}\n"));
    }
    out.push('\n');

    if let Some(w) = warning {
        let note = match w.reason {
            LinkWarningReason::TextDomainMismatch => format!(
                "⚠ This link's visible text (\"{}\") doesn't match where it actually goes.\n\n",
                w.display_text
            ),
            LinkWarningReason::PunycodeDomain => "⚠ This link's domain contains non-Latin \
                characters (punycode) — double-check it's the site you expect.\n\n"
                .to_string(),
        };
        out.push_str(&note);
    }

    let display_url = strip_display_only_tracking_params(url);
    // Bracket just the *first* occurrence of the host — the real one,
    // appearing right after the scheme. A tracking-wrapped link
    // (confirmed live, a real Amazon example) can legitimately contain
    // the same host string again later, URL-encoded inside a query
    // param pointing at the real destination; replacing every
    // occurrence would bracket that one too and imply there are two
    // meaningful hosts instead of one.
    let highlighted = match host {
        Some(h) => display_url.replacen(h, &format!("»{h}«"), 1),
        None => display_url,
    };
    out.push_str("Full link:\n");
    out.push_str(&hard_wrap(&highlighted, 70));
    out
}

/// Just the scheme and host, discarding path/query/fragment — "go
/// straight to the site, not through whatever tracking redirect or
/// deep-link path the email wrapped it in." `None` if the URL can't be
/// parsed or has no host at all (e.g. a `mailto:` link).
pub fn host_only_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(format!("{}://{host}", parsed.scheme()))
}

/// `GtkAlertDialog`'s detail text wraps at word boundaries, same as any
/// label — but a tracking-wrapped URL (confirmed live: a real Amazon
/// click-tracking link) is often one giant run of non-whitespace
/// characters with no word boundaries at all, so nothing in the string
/// is wrappable and the whole dialog just grows to fit it on one
/// enormous line instead. Force line breaks at a fixed width so long
/// URLs can't do that, without needing a custom dialog widget just to
/// get character-level wrapping.
fn hard_wrap(s: &str, width: usize) -> String {
    s.chars()
        .collect::<Vec<_>>()
        .chunks(width)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strips common tracking query parameters for *display* purposes only —
/// this never changes what actually gets opened, it just keeps the
/// confirmation popup from being buried in `utm_*`/`fbclid`/etc. noise.
/// This is deliberately *not* an attempt to unwrap tracking redirects
/// (e.g. `click.example.com/track?url=...`): doing that for real would
/// mean either following the redirect ourselves before the user has
/// agreed to visit anything (a real network request to the tracker,
/// which is exactly what this app's "never contact anything without
/// explicit opt-in" rule exists to prevent), or pattern-matching the
/// subset of trackers that plainly encode the destination in a query
/// param — which would be a different feature making a narrower,
/// explicit promise, not folded silently into this cosmetic cleanup.
fn strip_display_only_tracking_params(url: &str) -> String {
    const TRACKING_PARAMS: &[&str] = &[
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "mc_cid",
        "mc_eid",
    ];

    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| !TRACKING_PARAMS.contains(&k.as_ref()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if kept.len() == parsed.query_pairs().count() {
        return url.to_string(); // nothing stripped, keep the original exactly
    }

    if kept.is_empty() {
        parsed.set_query(None);
    } else {
        parsed.query_pairs_mut().clear().extend_pairs(&kept);
    }
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domain_handles_multi_label_tlds_correctly() {
        let desc = describe_link_destination("https://accounts.google.co.uk/signin", None);
        assert!(desc.contains("GOING TO: google.co.uk"), "{desc}");
    }

    /// Confirmed live: a real Amazon tracking-wrapped link (one long run
    /// of non-whitespace characters, no spaces or hyphens to break at)
    /// made `GtkAlertDialog` grow to the width of the entire string
    /// instead of wrapping, since word-boundary wrapping has nothing to
    /// work with on a string with no word boundaries at all.
    #[test]
    fn describe_link_destination_hard_wraps_long_unbreakable_urls() {
        let long_url = format!("https://example.com/r.html?token={}", "x".repeat(200));
        let desc = describe_link_destination(&long_url, None);
        // `.chars().count()`, not `str::len()` (bytes) — the highlight
        // markers around the host are multi-byte UTF-8 characters, so a
        // line can be exactly 70 *characters* (what actually bounds the
        // dialog's rendered width) while reading as more than 70 bytes.
        let longest_line = desc.lines().map(|l| l.chars().count()).max().unwrap_or(0);
        assert!(longest_line <= 70, "longest line was {longest_line} chars: {desc}");
    }

    #[test]
    fn tracking_params_are_stripped_from_the_displayed_url_only() {
        let desc = describe_link_destination(
            "https://example.com/page?id=5&utm_source=newsletter&fbclid=abc",
            None,
        );
        assert!(desc.contains("id=5"), "{desc}");
        assert!(!desc.contains("utm_source"), "{desc}");
        assert!(!desc.contains("fbclid"), "{desc}");
    }

    #[test]
    fn mismatch_warning_text_is_included_when_present() {
        let warning = LinkWarning {
            href: "https://evil.example".to_string(),
            display_text: "paypal.com".to_string(),
            reason: LinkWarningReason::TextDomainMismatch,
        };
        let desc = describe_link_destination("https://evil.example", Some(&warning));
        assert!(desc.contains("doesn't match where it actually goes"), "{desc}");
    }

    #[test]
    fn full_host_line_is_always_shown_even_when_identical_to_the_registrable_domain() {
        let desc = describe_link_destination("https://example.com/page", None);
        assert!(desc.contains("GOING TO: example.com"), "{desc}");
        assert!(desc.contains("Full host: example.com"), "{desc}");
    }

    #[test]
    fn only_the_real_host_is_bracketed_in_the_full_link_not_a_later_encoded_lookalike() {
        // Shaped like the real Amazon tracking link that prompted this:
        // the real host appears once right after the scheme, and the
        // same host string appears again later, URL-encoded, inside a
        // query param pointing at the actual destination.
        let url = "https://track.example.com/r?U=https%3A%2F%2Ftrack.example.com%2Freal";
        let desc = describe_link_destination(url, None);
        assert_eq!(
            desc.matches("»track.example.com«").count(),
            1,
            "only the real (first) occurrence of the host should be bracketed: {desc}"
        );
    }

    #[test]
    fn host_only_url_drops_path_query_and_fragment() {
        assert_eq!(
            host_only_url("https://track.example.com/r?U=https%3A%2F%2Freal.example.com&x=1#frag"),
            Some("https://track.example.com".to_string())
        );
        assert_eq!(host_only_url("not a url"), None);
    }

    /// Covers two things in one test, deliberately — `gtk::init()` can
    /// only succeed once per process (GTK's main context is exclusive to
    /// whichever thread claims it first), and Rust's test harness runs
    /// tests in parallel threads by default, so a second `#[test]`
    /// calling `gtk::init()` reliably loses that race. Splitting these
    /// into separate tests isn't worth fighting the test harness's
    /// threading model for.
    ///
    /// 1. `create_tag`'s `properties` are only checked against the real
    ///    GObject property types at runtime (confirmed the hard way: this
    ///    exact code panicked live — "property 'weight' of type
    ///    'GtkTextTag' can't be set from the given type (expected:
    ///    'gint', got: 'PangoWeight')" — while `cargo build`/`cargo
    ///    check` saw nothing wrong, since `&dyn ToValue` erases the
    ///    mismatch until `set_properties` actually runs). Every style
    ///    this module can apply needs at least one real `GtkTextBuffer`
    ///    population to catch that class of bug before a live session
    ///    does.
    /// 2. `remove_previous_link_tags` exists specifically so repeated
    ///    `populate` calls (one per message opened) don't leave a
    ///    growing pile of uniquely-named link tags in the buffer's tag
    ///    table forever — asserts that sweep actually keeps the tag
    ///    count bounded across repeated opens, not just that it
    ///    compiles.
    #[test]
    fn populate_applies_every_style_and_does_not_leak_link_tags_across_repeated_opens() {
        gtk::init().expect("gtk::init should succeed in this test environment");

        let segments = vec![
            Segment::Text { text: "plain ".to_string(), styles: vec![] },
            Segment::Text { text: "bold ".to_string(), styles: vec![TextStyle::Bold] },
            Segment::Text { text: "italic ".to_string(), styles: vec![TextStyle::Italic] },
            Segment::Text { text: "heading ".to_string(), styles: vec![TextStyle::Heading] },
            Segment::Text { text: "quoted ".to_string(), styles: vec![TextStyle::Blockquote] },
            Segment::Text { text: "mono ".to_string(), styles: vec![TextStyle::Monospace] },
            Segment::Text {
                text: "a link".to_string(),
                styles: vec![TextStyle::Link("https://example.com".to_string())],
            },
            Segment::ParagraphBreak,
            Segment::Image { src: "https://example.com/pic.png".to_string(), alt: "a cat".to_string() },
            Segment::Break,
            Segment::Text { text: "after the image".to_string(), styles: vec![] },
        ];

        let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        let images = populate(&buffer, &segments);

        assert_eq!(images.len(), 1);
        assert_eq!(images[0].src, "https://example.com/pic.png");
        assert_eq!(images[0].alt, "a cat");

        let start = buffer.start_iter();
        let end = buffer.end_iter();
        let text = buffer.text(&start, &end, false).to_string();
        assert!(text.contains("plain"), "{text}");
        assert!(text.contains("bold"), "{text}");
        assert!(text.contains("a link"), "{text}");
        assert!(text.contains("after the image"), "{text}");

        for _ in 0..4 {
            populate(&buffer, &segments);
        }
        let mut link_tag_count = 0;
        buffer.tag_table().foreach(|tag| {
            if tag.name().is_some_and(|n| n.starts_with(LINK_TAG_PREFIX)) {
                link_tag_count += 1;
            }
        });
        assert_eq!(link_tag_count, 1, "each populate() should sweep away the previous call's link tags");
    }
}
