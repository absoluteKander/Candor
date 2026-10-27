//! Orchestrates adding a new account: discover settings (or use a manual
//! override), verify them against the real server with the real
//! credentials, and only then persist anything. A password that fails
//! verification is never written to the keyring or to disk.

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::config::{self, AccountConfig, CredentialStore, Security};
use crate::connect;
use crate::discover::{self, Discovery, ServerSettings};

#[derive(Debug, Clone)]
pub struct ManualServerSettings {
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
}

pub struct NewAccountRequest {
    pub display_name: String,
    pub email: String,
    pub username: String,
    pub password: Zeroizing<String>,
    /// If set, skips autodiscovery and uses these settings as-is — the
    /// path the UI falls back to after a `NeedsManualSettings` outcome.
    pub manual: Option<ManualServerSettings>,
}

pub enum AddAccountOutcome {
    Added(AccountConfig),
    /// Autodiscovery found nothing usable; caller should prompt for
    /// manual server settings and retry with `manual` set.
    NeedsManualSettings,
}

pub async fn add_account(req: NewAccountRequest) -> Result<AddAccountOutcome> {
    let settings = match req.manual {
        Some(m) => ServerSettings {
            imap_host: m.imap_host,
            imap_port: m.imap_port,
            imap_security: m.imap_security,
            smtp_host: m.smtp_host,
            smtp_port: m.smtp_port,
            smtp_security: m.smtp_security,
        },
        None => {
            let domain = req
                .email
                .split('@')
                .nth(1)
                .context("email address has no domain")?;
            match discover::discover(domain).await {
                Some(Discovery { settings, .. }) => settings,
                None => return Ok(AddAccountOutcome::NeedsManualSettings),
            }
        }
    };

    connect::test_imap(
        &settings.imap_host,
        settings.imap_port,
        settings.imap_security,
        &req.username,
        &req.password,
    )
    .await
    .context("IMAP verification failed")?;

    connect::test_smtp(
        &settings.smtp_host,
        settings.smtp_port,
        settings.smtp_security,
        &req.username,
        &req.password,
    )
    .await
    .context("SMTP verification failed")?;

    let id = slugify(&req.email);

    CredentialStore::set_password(&id, &req.password)
        .context("storing credential in the OS keyring")?;

    let account = AccountConfig {
        id,
        email: req.email,
        display_name: req.display_name,
        imap_host: settings.imap_host,
        imap_port: settings.imap_port,
        imap_security: settings.imap_security,
        smtp_host: settings.smtp_host,
        smtp_port: settings.smtp_port,
        smtp_security: settings.smtp_security,
        username: req.username,
    };

    let mut app_config = config::load().context("loading existing config")?;
    app_config.accounts.clear(); // v1: single account only.
    app_config.accounts.push(account.clone());
    config::save(&app_config).context("saving account config")?;

    Ok(AddAccountOutcome::Added(account))
}

/// Returns `(id, email, display_name)` for the configured account, if any.
/// `id` is the key used for both the keyring entry and the local message
/// index (SQLite), so the GUI needs it to query synced data directly.
pub fn account_summary() -> Result<Option<(String, String, String)>> {
    let cfg = config::load().context("loading config")?;
    Ok(cfg
        .accounts
        .first()
        .map(|a| (a.id.clone(), a.email.clone(), a.display_name.clone())))
}

/// Deletes the configured account's credential from the keyring and clears
/// it from the config file. Returns `false` if there was no account to
/// remove. The keyring deletion is best-effort: a failure there (e.g. the
/// entry was already gone) does not block clearing the config.
pub fn remove_account() -> Result<bool> {
    let mut cfg = config::load().context("loading config")?;
    let Some(account) = cfg.accounts.pop() else {
        return Ok(false);
    };

    if let Err(e) = CredentialStore::delete_password(&account.id) {
        tracing::warn!(error = %e, account = %account.id, "failed to delete credential from keyring");
    }

    config::save(&cfg).context("saving config after removing account")?;
    Ok(true)
}

fn slugify(email: &str) -> String {
    email
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}
