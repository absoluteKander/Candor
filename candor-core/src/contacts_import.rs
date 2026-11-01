//! Parses a contacts CSV exported from some other address book (Google
//! Contacts, Nextcloud, Outlook, ...) into `(name, address)` pairs ready
//! for `store::upsert_contact`. Deliberately not a full vCard/CardDAV
//! client — a one-time CSV import needs no ongoing account access or
//! sync credentials from a separate contacts service, consistent with
//! this app never connecting to anything beyond the mail server
//! itself. Real exports vary wildly in column naming (Google's is
//! literally `E-mail 1 - Value`), so this matches headers loosely by
//! substring rather than expecting one fixed schema.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// Picks the most plausible email and name columns from a CSV header
/// row. Looks for "mail" anywhere in the header for the address column
/// (catches `Email`, `E-mail Address`, `E-mail 1 - Value`), and prefers
/// an exact `name`/`display name` match for the name column before
/// falling back to the first header merely containing "name" (so a
/// Google export's `Name` wins over, say, `File As` if both happened to
/// match loosely — though only `Name` actually contains "name" in
/// practice).
fn pick_columns(headers: &csv::StringRecord) -> (Option<usize>, Option<usize>) {
    let mut email_col = None;
    let mut name_col = None;
    let mut name_col_preferred = None;

    for (i, header) in headers.iter().enumerate() {
        let lower = header.to_lowercase();
        if email_col.is_none() && lower.contains("mail") {
            email_col = Some(i);
        }
        if lower == "name" || lower == "display name" {
            name_col_preferred.get_or_insert(i);
        } else if lower.contains("name") {
            name_col.get_or_insert(i);
        }
    }

    (email_col, name_col_preferred.or(name_col))
}

/// Parses `path` into `(name, address)` pairs, skipping any row with no
/// usable address. Returns an error only if the file can't be read or
/// has no column that looks like an email address at all — a row with
/// just a missing/blank name is fine (the address is all
/// `upsert_contact` strictly needs).
pub fn parse_contacts_csv(path: &Path) -> Result<Vec<(Option<String>, String)>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("opening contacts CSV at {}", path.display()))?;

    let (email_col, name_col) = pick_columns(reader.headers().context("reading CSV header row")?);
    let Some(email_col) = email_col else {
        bail!("no column in this CSV looks like an email address");
    };

    let mut contacts = Vec::new();
    for result in reader.records() {
        let record = result.context("reading CSV row")?;
        let Some(address) = record.get(email_col).map(str::trim).filter(|a| a.contains('@')) else {
            continue;
        };
        let name = name_col
            .and_then(|i| record.get(i))
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string);
        contacts.push((name, address.to_string()));
    }

    Ok(contacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Writes `content` to a throwaway file in the OS temp dir and
    /// returns its path — no `tempfile` dependency needed for this.
    fn write_csv(content: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("candor_contacts_import_test_{n}.csv"));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_a_plain_generic_export() {
        let path = write_csv("name,email\nAlice,alice@example.com\nBob,bob@example.com\n");
        let contacts = parse_contacts_csv(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(
            contacts,
            vec![
                (Some("Alice".to_string()), "alice@example.com".to_string()),
                (Some("Bob".to_string()), "bob@example.com".to_string()),
            ]
        );
    }

    #[test]
    fn matches_googles_oddly_named_email_column() {
        // Google Contacts' actual export header for the primary email
        // is literally this — the real-world case this loose matching
        // exists for.
        let path = write_csv(
            "Name,Given Name,E-mail 1 - Value,E-mail 1 - Label\n\
             Jane Doe,Jane,jane.doe@example.com,Work\n",
        );
        let contacts = parse_contacts_csv(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // `Name` (exact match) wins over `Given Name` (loose match).
        assert_eq!(contacts, vec![(Some("Jane Doe".to_string()), "jane.doe@example.com".to_string())]);
    }

    #[test]
    fn skips_rows_with_no_usable_address() {
        let path = write_csv("name,email\nNo Email Here,\nHas One,has@example.com\n");
        let contacts = parse_contacts_csv(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(contacts, vec![(Some("Has One".to_string()), "has@example.com".to_string())]);
    }

    #[test]
    fn missing_name_column_still_imports_addresses() {
        let path = write_csv("email\nsolo@example.com\n");
        let contacts = parse_contacts_csv(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(contacts, vec![(None, "solo@example.com".to_string())]);
    }

    #[test]
    fn errors_when_no_column_looks_like_an_email() {
        let path = write_csv("name,phone\nAlice,555-1234\n");
        let result = parse_contacts_csv(&path);
        std::fs::remove_file(&path).ok();

        assert!(result.is_err());
    }
}
