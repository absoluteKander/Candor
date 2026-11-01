//! Orchestrates adding a new account: discover settings (or use a manual
//! override), verify them against the real server with the real
//! credentials, and only then persist anything. A password that fails
//! verification is never written to the keyring or to disk.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::config::{self, AccountConfig, AuthMethod, CredentialStore, Security, TabColor};
use crate::connect;
use crate::discover::{self, Discovery, ServerSettings};
use crate::oauth;

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
        AuthMethod::Password,
    )
    .await
    .context("IMAP verification failed")?;

    connect::test_smtp(
        &settings.smtp_host,
        settings.smtp_port,
        settings.smtp_security,
        &req.username,
        &req.password,
        AuthMethod::Password,
    )
    .await
    .context("SMTP verification failed")?;

    let id = reserve_id(&req.email)?;
    CredentialStore::set_password(&id, &req.password)
        .context("storing credential in the OS keyring")?;

    finish_adding(id, req.email, req.display_name, req.username, settings, AuthMethod::Password)
}

/// A new account authenticating via Microsoft OAuth2 instead of a
/// password — see `oauth.rs`. The caller has already run the
/// interactive sign-in and verified it works; this just verifies the
/// *resulting* token against the real server (same as a password gets
/// verified before being trusted) and persists it the same way.
pub struct NewOAuthAccountRequest {
    pub display_name: String,
    pub email: String,
    pub username: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_at: i64,
    pub manual: Option<ManualServerSettings>,
}

pub async fn add_oauth_account(req: NewOAuthAccountRequest) -> Result<AddAccountOutcome> {
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
        &req.access_token,
        AuthMethod::OAuthMicrosoft,
    )
    .await
    .context("IMAP verification failed")?;

    connect::test_smtp(
        &settings.smtp_host,
        settings.smtp_port,
        settings.smtp_security,
        &req.username,
        &req.access_token,
        AuthMethod::OAuthMicrosoft,
    )
    .await
    .context("SMTP verification failed")?;

    let id = reserve_id(&req.email)?;
    oauth::store_initial_token(&id, &req.access_token, &req.refresh_token, req.expires_at)
        .context("storing OAuth token in the OS keyring")?;

    finish_adding(id, req.email, req.display_name, req.username, settings, AuthMethod::OAuthMicrosoft)
}

/// Claims this email's account id, failing if one's already configured
/// — shared by both the password and OAuth2 add-account paths, done
/// *before* either one writes a secret to the keyring.
fn reserve_id(email: &str) -> Result<String> {
    let id = slugify(email);
    let app_config = config::load().context("loading existing config")?;
    if app_config.accounts.iter().any(|a| a.id == id) {
        // Same email added twice would otherwise produce two
        // `AccountConfig` entries sharing one `id` — breaking every
        // assumption the keyring and the local SQLite index make
        // about `account_id` being a unique key. Rejected here,
        // before anything is written, rather than left to surface
        // confusingly later.
        bail!("an account for {} is already configured", id);
    }
    Ok(id)
}

/// The bookkeeping shared by both add-account paths once a secret has
/// already been verified and stored: assign tab position/color/default
/// status, build the `AccountConfig`, and persist it.
fn finish_adding(
    id: String,
    email: String,
    display_name: String,
    username: String,
    settings: ServerSettings,
    auth_method: AuthMethod,
) -> Result<AddAccountOutcome> {
    let mut app_config = config::load().context("loading existing config")?;

    // The very first account ever added starts as the default tab —
    // there's nothing else for that to mean yet. Later accounts stay
    // non-default until the user explicitly changes it in Settings.
    // Tab order appends to the end, in whatever order accounts were
    // added — also only ever changed afterward through Settings, not
    // automatically.
    let is_default = app_config.accounts.is_empty();
    let tab_order = app_config.accounts.len() as u32;

    let account = AccountConfig {
        id,
        email,
        display_name,
        imap_host: settings.imap_host,
        imap_port: settings.imap_port,
        imap_security: settings.imap_security,
        smtp_host: settings.smtp_host,
        smtp_port: settings.smtp_port,
        smtp_security: settings.smtp_security,
        username,
        // Locked by default — see `AccountConfig::locked`'s doc
        // comment for why.
        locked: true,
        // Unmuted by default — see `AccountConfig::muted`'s doc comment
        // for why this one doesn't mirror `locked`'s default-closed
        // stance.
        muted: false,
        tab_order,
        color: default_color_for(tab_order),
        short_name: String::new(),
        is_default,
        auth_method,
    };

    app_config.accounts.push(account.clone());
    config::save(&app_config).context("saving account config")?;

    Ok(AddAccountOutcome::Added(account))
}

/// Every configured account, in whatever order they're stored in —
/// callers that care about tab order sort by `tab_order` themselves.
/// `id` is the key used for both the keyring entry and the local
/// message index (SQLite).
pub fn list_accounts() -> Result<Vec<AccountConfig>> {
    let cfg = config::load().context("loading config")?;
    Ok(cfg.accounts)
}

/// Deletes one account's credential from the keyring and removes it
/// from the config file. Returns `false` if no account with that id
/// was configured. The keyring deletion is best-effort: a failure
/// there (e.g. the entry was already gone) does not block clearing
/// the config.
pub fn remove_account(account_id: &str) -> Result<bool> {
    let mut cfg = config::load().context("loading config")?;
    let Some(index) = cfg.accounts.iter().position(|a| a.id == account_id) else {
        return Ok(false);
    };
    let account = cfg.accounts.remove(index);

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

/// A starting color for a newly-added account — just rotates through
/// `TabColor`'s preset set by position, so accounts added one after
/// another default to visually distinct colors rather than all
/// starting the same shade. Purely a starting point: the user can
/// change it any time, this only picks what a brand-new account opens
/// with.
fn default_color_for(tab_order: u32) -> TabColor {
    const PALETTE: [TabColor; 8] = [
        TabColor::Blue,
        TabColor::Green,
        TabColor::Purple,
        TabColor::Orange,
        TabColor::Red,
        TabColor::Teal,
        TabColor::Pink,
        TabColor::Yellow,
    ];
    PALETTE[tab_order as usize % PALETTE.len()]
}
