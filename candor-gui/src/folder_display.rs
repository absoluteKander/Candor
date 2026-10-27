//! Normalizes a folder's real IMAP name + SPECIAL-USE tag into a display
//! label and sort rank, so the sidebar reads the same regardless of how a
//! given provider actually named/nested its folders (Gmail's
//! "[Gmail]/Sent Mail" vs. a generic server's "Sent Items", etc.).

use candor_core::store::FolderInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderDisplay {
    /// The real IMAP name — still what's used to SELECT/query by.
    pub raw_name: String,
    pub label: String,
    pub unread: u32,
    rank: u8,
}

pub fn normalize(info: &FolderInfo) -> FolderDisplay {
    if info.name.eq_ignore_ascii_case("INBOX") {
        return FolderDisplay {
            raw_name: info.name.clone(),
            label: "Inbox".to_string(),
            unread: info.unread,
            rank: 0,
        };
    }

    if let Some(special_use) = &info.special_use {
        if let Some((label, rank)) = canonical_for(special_use) {
            return FolderDisplay {
                raw_name: info.name.clone(),
                label: label.to_string(),
                unread: info.unread,
                rank,
            };
        }
    }

    FolderDisplay {
        raw_name: info.name.clone(),
        label: strip_known_prefix(&info.name),
        unread: info.unread,
        rank: 100,
    }
}

/// Sorts canonical folders first in a fixed, FairEmail/Mail.app-style
/// order (Inbox, Drafts, Sent, Archive, Junk, Trash, then other
/// special-use folders), then anything else alphabetically by label.
pub fn sort_key(f: &FolderDisplay) -> (u8, String) {
    (f.rank, f.label.to_ascii_lowercase())
}

fn canonical_for(special_use: &str) -> Option<(&'static str, u8)> {
    match special_use {
        s if s.eq_ignore_ascii_case("\\Drafts") => Some(("Drafts", 1)),
        s if s.eq_ignore_ascii_case("\\Sent") => Some(("Sent", 2)),
        s if s.eq_ignore_ascii_case("\\Archive") => Some(("Archive", 3)),
        s if s.eq_ignore_ascii_case("\\Junk") => Some(("Junk", 4)),
        s if s.eq_ignore_ascii_case("\\Trash") => Some(("Trash", 5)),
        s if s.eq_ignore_ascii_case("\\All") => Some(("All Mail", 6)),
        s if s.eq_ignore_ascii_case("\\Flagged") => Some(("Starred", 7)),
        s if s.eq_ignore_ascii_case("\\Important") => Some(("Important", 8)),
        _ => None,
    }
}

/// Fallback for a folder with no recognized SPECIAL-USE tag — strips a
/// known provider container prefix so e.g. Gmail's labels still read
/// cleanly even on the rare folder the server didn't tag (multi-account
/// grouping, which would show *which* account a folder belongs to, is
/// deliberately not this function's job yet — v1 is single-account).
fn strip_known_prefix(name: &str) -> String {
    const PREFIXES: &[&str] = &["[Gmail]/", "[Google Mail]/"];
    for prefix in PREFIXES {
        if let Some(stripped) = name.strip_prefix(prefix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str, special_use: Option<&str>, unread: u32) -> FolderInfo {
        FolderInfo {
            name: name.to_string(),
            special_use: special_use.map(str::to_string),
            unread,
        }
    }

    #[test]
    fn inbox_is_always_first_regardless_of_tag() {
        let d = normalize(&info("INBOX", None, 3));
        assert_eq!(d.label, "Inbox");
        assert_eq!(sort_key(&d).0, 0);
    }

    #[test]
    fn gmail_special_use_folders_get_canonical_labels_and_order() {
        let cases = [
            ("[Gmail]/Drafts", "\\Drafts", "Drafts", 1),
            ("[Gmail]/Sent Mail", "\\Sent", "Sent", 2),
            ("[Gmail]/Spam", "\\Junk", "Junk", 4),
            ("[Gmail]/Trash", "\\Trash", "Trash", 5),
            ("[Gmail]/All Mail", "\\All", "All Mail", 6),
            ("[Gmail]/Starred", "\\Flagged", "Starred", 7),
            ("[Gmail]/Important", "\\Important", "Important", 8),
        ];
        for (raw, special_use, expected_label, expected_rank) in cases {
            let d = normalize(&info(raw, Some(special_use), 0));
            assert_eq!(d.label, expected_label, "wrong label for {raw}");
            assert_eq!(sort_key(&d).0, expected_rank, "wrong rank for {raw}");
            assert_eq!(d.raw_name, raw, "raw_name must stay the real IMAP name for selecting by");
        }
    }

    #[test]
    fn untagged_gmail_folder_still_drops_the_bracket_prefix() {
        let d = normalize(&info("[Gmail]/Something New", None, 0));
        assert_eq!(d.label, "Something New");
    }

    #[test]
    fn custom_folder_keeps_its_own_name_and_sorts_after_canonical_ones() {
        let d = normalize(&info("Receipts", None, 0));
        assert_eq!(d.label, "Receipts");
        assert_eq!(sort_key(&d).0, 100);
    }

    #[test]
    fn full_list_sorts_into_the_expected_order() {
        let infos = [
            info("[Gmail]/Trash", Some("\\Trash"), 0),
            info("Receipts", None, 0),
            info("INBOX", None, 2),
            info("[Gmail]/Sent Mail", Some("\\Sent"), 0),
            info("[Gmail]/Drafts", Some("\\Drafts"), 1),
        ];
        let mut displays: Vec<_> = infos.iter().map(normalize).collect();
        displays.sort_by_key(sort_key);
        let labels: Vec<_> = displays.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(labels, ["Inbox", "Drafts", "Sent", "Trash", "Receipts"]);
    }
}
