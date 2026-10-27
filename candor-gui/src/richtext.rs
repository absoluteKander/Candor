//! Walks already-sanitized email HTML into a flat sequence of rich-text
//! segments, which `body_view` then feeds into a real `GtkTextBuffer` —
//! replacing the old approach of rasterizing the whole message to a
//! bitmap via litehtml. This is deliberately not a CSS layout engine:
//! like FairEmail (the explicit reference point for this app), it keeps
//! real selectable text, real clickable links, and per-image placeholders
//! in exchange for *not* attempting pixel-faithful table/float layout —
//! HTML email is almost always just content wrapped in layout tables for
//! client compatibility, and flattening that layout to reading order
//! loses nothing that actually matters for reading it.
//!
//! This module only produces plain, `Send`-safe data (no GTK types) —
//! `GtkTextBuffer` and friends are not thread-safe and must only be
//! touched on the main thread, so the (comparatively expensive) HTML walk
//! can still happen on a background thread; only turning the result into
//! actual widgets needs the main thread.

use scraper::{Html, Node};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TextStyle {
    Bold,
    Italic,
    Heading,
    /// The link's target URL — kept on the style itself (rather than as a
    /// separate side table) so a style-aware consumer never has to
    /// correlate two parallel structures.
    Link(String),
    Blockquote,
    Monospace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Text { text: String, styles: Vec<TextStyle> },
    /// `alt` is shown as a placeholder label before the image is loaded.
    Image { src: String, alt: String },
    /// A single line break (`<br>`, or between flattened table cells).
    Break,
    /// A full paragraph break (blank line) between block-level elements.
    ParagraphBreak,
}

/// Tags whose text content should never contribute to the output, even
/// though `ammonia` should already have stripped them — defense in depth,
/// matching how the rest of this app treats sanitization as the real
/// boundary and everything downstream as not trusting it blindly.
const SKIP_CONTENTS: &[&str] = &["script", "style", "head", "title"];

pub fn html_to_segments(html: &str) -> Vec<Segment> {
    let doc = Html::parse_fragment(html);
    let mut out = Vec::new();
    let mut list_stack: Vec<Option<u32>> = Vec::new(); // None = unordered, Some(n) = next ordinal
    walk(doc.tree.root(), &mut Vec::new(), &mut list_stack, &mut out);
    out
}

/// For messages with no HTML part at all — splits on blank lines into
/// paragraphs rather than routing plain text through HTML escaping and
/// back out through the walker above, which would be a roundabout way of
/// doing the same thing.
pub fn plain_text_segments(text: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    for paragraph in text.split("\n\n") {
        for (i, line) in paragraph.lines().enumerate() {
            if i > 0 {
                out.push(Segment::Break);
            }
            if !line.trim().is_empty() {
                out.push(Segment::Text { text: line.to_string(), styles: Vec::new() });
            }
        }
        out.push(Segment::ParagraphBreak);
    }
    out
}

fn walk(
    node: ego_tree::NodeRef<Node>,
    styles: &mut Vec<TextStyle>,
    list_stack: &mut Vec<Option<u32>>,
    out: &mut Vec<Segment>,
) {
    match node.value() {
        Node::Text(text) => {
            let collapsed = collapse_whitespace(text);
            if !collapsed.is_empty() {
                out.push(Segment::Text { text: collapsed, styles: styles.clone() });
            }
        }
        Node::Element(el) => {
            let name = el.name();
            if SKIP_CONTENTS.contains(&name) {
                return;
            }

            match name {
                "br" => {
                    out.push(Segment::Break);
                    return;
                }
                "img" => {
                    let src = el.attr("src").unwrap_or_default().to_string();
                    if !src.is_empty() {
                        // `alt=""` (present but empty — extremely common
                        // specifically on tracking pixels, which is
                        // exactly the image class most likely to end up
                        // here) must fall back the same as a *missing*
                        // `alt` attribute — otherwise the placeholder
                        // renders its label as a literal empty "[]".
                        let alt = el
                            .attr("alt")
                            .map(str::trim)
                            .filter(|a| !a.is_empty())
                            .unwrap_or("image")
                            .to_string();
                        out.push(Segment::Image { src, alt });
                    }
                    return;
                }
                _ => {}
            }

            let is_block = matches!(
                name,
                "p" | "div"
                    | "tr"
                    | "table"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "blockquote"
                    | "ul"
                    | "ol"
            );
            if is_block {
                out.push(Segment::ParagraphBreak);
            }

            let pushed_style = match name {
                "b" | "strong" => Some(TextStyle::Bold),
                "i" | "em" => Some(TextStyle::Italic),
                "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => Some(TextStyle::Heading),
                "blockquote" => Some(TextStyle::Blockquote),
                "code" | "pre" | "tt" => Some(TextStyle::Monospace),
                "a" => el.attr("href").filter(|h| !h.is_empty()).map(|h| TextStyle::Link(h.to_string())),
                _ => None,
            };
            if let Some(style) = &pushed_style {
                styles.push(style.clone());
            }

            let is_list = matches!(name, "ul" | "ol");
            if is_list {
                list_stack.push(if name == "ol" { Some(1) } else { None });
            }

            if name == "li" {
                let marker = match list_stack.last_mut() {
                    Some(Some(n)) => {
                        let m = format!("{n}. ");
                        *n += 1;
                        m
                    }
                    _ => "• ".to_string(),
                };
                out.push(Segment::Text { text: marker, styles: styles.clone() });
            }

            let mut child = node.first_child();
            while let Some(c) = child {
                walk(c, styles, list_stack, out);
                child = c.next_sibling();
            }

            if is_list {
                list_stack.pop();
            }
            if pushed_style.is_some() {
                styles.pop();
            }

            if matches!(name, "td" | "th" | "li") {
                out.push(Segment::Break);
            }
            if is_block {
                out.push(Segment::ParagraphBreak);
            }
        }
        _ => {
            let mut child = node.first_child();
            while let Some(c) = child {
                walk(c, styles, list_stack, out);
                child = c.next_sibling();
            }
        }
    }
}

/// HTML collapses any run of whitespace (including newlines from the
/// source markup's own indentation) to a single space — without this,
/// the sanitized HTML's formatting whitespace (there's usually a lot of
/// it in template-generated email) would show up as literal blank lines
/// and runs of spaces in the rendered text.
///
/// `pub`, not just used for HTML body text — confirmed live that a
/// message `Subject` header with the same kind of zero-width padding
/// (see `is_invisible_formatting_char`) hung the entire app for
/// *minutes*: `GtkEditable::set_text` on the compose Subject field (fed
/// straight from the original message's raw, unsanitized subject when
/// replying) got stuck inside Pango/HarfBuzz text shaping — the same
/// "some input makes a text/layout library catastrophically slow" shape
/// as litehtml's table-nesting pathology earlier, just a different
/// library. Any header-derived text that reaches a GTK widget needs this
/// pass, not only text that happened to come from HTML.
pub fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for c in s.chars() {
        if is_invisible_formatting_char(c) {
            // Dropped outright, not collapsed to a space — these aren't
            // whitespace, they're commonly used (zero-width join/non-join,
            // bidi marks, byte-order marks) as invisible padding in
            // automated/marketing email, sometimes specifically to defeat
            // spam-filter text analysis. Hundreds of them in a row (seen
            // in real sanitized email HTML) would otherwise show up as a
            // giant blob of junk "text" segments.
            continue;
        }
        if c.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    out
}

/// Strips the same invisible formatting characters as
/// `collapse_whitespace`, without otherwise touching whitespace — for
/// multi-line plain text (quoted reply bodies, `plain_text_segments`'
/// input) where real newlines/paragraph breaks need to survive, unlike
/// `collapse_whitespace`'s single-line-oriented "every whitespace run
/// becomes one space" behavior, which would flatten them.
pub fn strip_invisible_chars(s: &str) -> String {
    s.chars().filter(|c| !is_invisible_formatting_char(*c)).collect()
}

fn is_invisible_formatting_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' // zero width space
        | '\u{200C}' // zero width non-joiner
        | '\u{200D}' // zero width joiner
        | '\u{200E}' // left-to-right mark
        | '\u{200F}' // right-to-left mark
        | '\u{2060}' // word joiner
        | '\u{FEFF}' // byte order mark / zero width no-break space
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paragraph_becomes_a_single_text_segment() {
        let segments = html_to_segments("<html><body><p>Hello world</p></body></html>");
        assert!(segments.iter().any(|s| matches!(
            s,
            Segment::Text { text, styles } if text == "Hello world" && styles.is_empty()
        )));
    }

    #[test]
    fn bold_and_link_styles_apply_to_their_own_text_only() {
        let segments = html_to_segments(
            r#"<p>plain <b>bold</b> <a href="https://example.com/x">a link</a> plain again</p>"#,
        );

        let bold = segments
            .iter()
            .find(|s| matches!(s, Segment::Text { text, .. } if text == "bold"))
            .expect("bold segment");
        assert_eq!(bold, &Segment::Text { text: "bold".to_string(), styles: vec![TextStyle::Bold] });

        let link = segments
            .iter()
            .find(|s| matches!(s, Segment::Text { text, .. } if text == "a link"))
            .expect("link segment");
        assert_eq!(
            link,
            &Segment::Text {
                text: "a link".to_string(),
                styles: vec![TextStyle::Link("https://example.com/x".to_string())]
            }
        );

        // Leading space is correct here, not a bug: there's a real space
        // in the source between `</a>` and "plain again", which HTML
        // whitespace collapsing preserves as exactly one space.
        let plain_again = segments
            .iter()
            .find(|s| matches!(s, Segment::Text { text, .. } if text == " plain again"));
        assert_eq!(
            plain_again,
            Some(&Segment::Text { text: " plain again".to_string(), styles: vec![] }),
            "styling must not leak past the end of the tag that introduced it"
        );
    }

    #[test]
    fn img_with_src_becomes_an_image_segment() {
        let segments = html_to_segments(r#"<p><img src="https://example.com/pic.png" alt="a cat"></p>"#);
        assert!(segments.iter().any(
            |s| matches!(s, Segment::Image { src, alt } if src == "https://example.com/pic.png" && alt == "a cat")
        ));
    }

    /// `alt=""` is extremely common specifically on tracking pixels —
    /// confirmed live: it rendered the inline placeholder's label as a
    /// literal empty "[]" next to a shield icon, with no indication of
    /// what it even was.
    #[test]
    fn img_with_empty_alt_attribute_falls_back_the_same_as_a_missing_one() {
        let segments = html_to_segments(r#"<p><img src="https://example.com/pixel.gif" alt=""></p>"#);
        assert!(segments
            .iter()
            .any(|s| matches!(s, Segment::Image { src, alt } if src == "https://example.com/pixel.gif" && alt == "image")));
    }

    #[test]
    fn img_without_src_is_skipped_rather_than_producing_a_dangling_placeholder() {
        let segments = html_to_segments(r#"<p><img alt="broken"></p>"#);
        assert!(!segments.iter().any(|s| matches!(s, Segment::Image { .. })));
    }

    #[test]
    fn whitespace_and_newlines_in_source_markup_collapse_to_single_spaces() {
        let segments = html_to_segments("<p>line one\n\n     line two\t\ttabbed</p>");
        let text: String = segments
            .iter()
            .filter_map(|s| match s {
                Segment::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "line one line two tabbed");
    }

    /// Automated/marketing email sometimes pads text with runs of
    /// zero-width characters (seen in a real message: hundreds of
    /// U+200C in a row), apparently to defeat spam-filter text analysis.
    /// Confirmed against real sanitized HTML that this used to produce
    /// one giant garbage segment; it should instead vanish entirely
    /// rather than show up as invisible-but-space-occupying junk.
    #[test]
    fn zero_width_padding_characters_are_dropped_not_collapsed_to_spaces() {
        let padded = "\u{200c}".repeat(50);
        let segments = html_to_segments(&format!("<p>before{padded}after</p>"));
        let text: String = segments
            .iter()
            .filter_map(|s| match s {
                Segment::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "beforeafter", "zero-width characters should be dropped, not turned into spaces");
    }

    #[test]
    fn list_items_get_bullet_or_number_prefixes() {
        let ul = html_to_segments("<ul><li>first</li><li>second</li></ul>");
        let ul_text: Vec<&str> = ul
            .iter()
            .filter_map(|s| match s {
                Segment::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(ul_text, vec!["• ", "first", "• ", "second"]);

        let ol = html_to_segments("<ol><li>first</li><li>second</li></ol>");
        let ol_text: Vec<&str> = ol
            .iter()
            .filter_map(|s| match s {
                Segment::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(ol_text, vec!["1. ", "first", "2. ", "second"]);
    }

    #[test]
    fn script_and_style_contents_are_never_emitted() {
        let segments = html_to_segments(
            "<html><head><style>body { color: red; }</style></head><body>\
             <script>alert('x')</script><p>real content</p></body></html>",
        );
        let text: String = segments
            .iter()
            .filter_map(|s| match s {
                Segment::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(text, "real content");
    }

    #[test]
    fn table_cells_flatten_to_one_line_per_row_rather_than_a_grid() {
        let segments = html_to_segments(
            "<table><tr><td>a1</td><td>a2</td></tr><tr><td>b1</td><td>b2</td></tr></table>",
        );
        // Each cell ends in a Break, each row in a ParagraphBreak — this
        // just asserts the flattening doesn't silently drop any cell's
        // content, which is the actual thing worth guarding here.
        let text: Vec<&str> = segments
            .iter()
            .filter_map(|s| match s {
                Segment::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, vec!["a1", "a2", "b1", "b2"]);
    }
}
