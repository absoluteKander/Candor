//! Microsoft OAuth2 — the Authorization Code + PKCE flow for accounts
//! that can no longer rely on a plain password. Microsoft is phasing out
//! Basic authentication (plain password IMAP/SMTP login) for Outlook.com
//! and Microsoft 365 entirely; this is the real replacement, not a
//! workaround. Every other provider this app supports (Gmail, Yahoo,
//! iCloud, Fastmail, Zoho) still accepts a plain password or a
//! provider-issued app-specific password, so this flow is Microsoft-only
//! — see [`crate::config::AuthMethod`].
//!
//! The wire mechanism, once a token is in hand, is `XOAUTH2` — the SASL
//! mechanism Google originated and Microsoft later adopted for Exchange
//! Online. [`XOAuth2`] implements it for IMAP (via `imap::Authenticator`,
//! used from `sync::connect_and_login`); the SMTP side just sets
//! `lettre`'s existing `Mechanism::Xoauth2` and passes the access token
//! as the password (`send::send`).
//!
//! `CLIENT_ID` below is a placeholder. This is a "public client"
//! (native/desktop) registration, so it has no secret to protect — it
//! only identifies the application, not a user — but it does need to be
//! the real ID of an app actually registered at
//! <https://portal.azure.com> ("App registrations" -> "New registration",
//! supported account types "Accounts in any organizational directory and
//! personal Microsoft accounts", platform "Mobile and desktop
//! applications" with redirect URI `http://localhost`) before this flow
//! can complete end to end. Nothing here will work against the
//! placeholder.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RefreshToken, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{AccountConfig, AuthMethod, CredentialStore};

/// Candor's own registered app (Entra ID, "Any Entra ID Tenant +
/// Personal Microsoft accounts", public client, redirect URI
/// `http://localhost`) — see this module's doc comment.
pub const CLIENT_ID: &str = "3c69bdb8-0e9f-48d3-910d-6537e46472ac";

const AUTH_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// `offline_access` is what actually gets a refresh token back from the
/// v2 endpoint — without it, only a short-lived access token (about an
/// hour) would be issued, and the account would stop working the moment
/// it expired with no way back in short of signing in again.
///
/// Requested under the `outlook.office.com` resource — the actual
/// Exchange Online audience the IMAP/SMTP servers validate tokens
/// against. (A `graph.microsoft.com`-scoped attempt was tried first,
/// since that's where this tenant's app permissions ended up
/// registered; it produced an opaque, non-JWT access token Exchange's
/// IMAP server couldn't recognize at all. Microsoft does expose the
/// same `IMAP.AccessAsUser.All`/`SMTP.Send` *names* under both Graph
/// and the legacy "Office 365 Exchange Online" API, but only a token
/// actually minted for the Exchange resource is one Exchange's IMAP
/// server can use.)
const SCOPES: &[&str] = &[
    "offline_access",
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
];

/// Refresh a little before actual expiry (seconds) rather than racing a
/// token that's about to lapse mid-request.
const REFRESH_SKEW_SECS: i64 = 60;

/// How long `interactive_sign_in` waits for the browser redirect before
/// giving up. A plain blocking `accept()` has no timeout at all — if
/// the user closes the tab, switches away, or the browser just never
/// gets around to it, that call (and the `spawn_blocking` task, and the
/// GUI's own "Signing in…" state awaiting it) would otherwise hang
/// forever with no way to retry short of restarting the app.
const SIGN_IN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The `imap::Authenticator` implementation for XOAUTH2 — IMAP's half of
/// the OAuth2 wire protocol.
pub struct XOAuth2 {
    pub user: String,
    pub access_token: Zeroizing<String>,
}

impl imap::Authenticator for XOAuth2 {
    type Response = String;

    /// XOAUTH2 isn't a real multi-round challenge/response mechanism —
    /// the first call (empty `challenge`) sends the one real SASL-IR
    /// credential string. But on failure, the server doesn't go
    /// straight to a tagged error: it sends a `+` continuation carrying
    /// a base64 JSON diagnostic as `challenge`, and the exchange isn't
    /// considered over until the client replies to *that* with an empty
    /// string — only then does the real tagged `NO`/`BAD` (with the
    /// actual diagnostic) come back. Replying with the credential again
    /// here, instead of empty, leaves the exchange in a broken state and
    /// surfaces only a generic "AUTHENTICATE failed" with none of the
    /// detail that would explain why.
    fn process(&self, challenge: &[u8]) -> Self::Response {
        if challenge.is_empty() {
            format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.access_token.as_str())
        } else {
            // The server's error continuation carries a JSON diagnostic
            // (status/schemes/scope) explaining why XOAUTH2 was
            // rejected — otherwise invisible, since the final tagged
            // response this exchange produces after replying empty is
            // often just a generic "AUTHENTICATE failed" with none of
            // that detail. Logged, not propagated: `Authenticator`
            // doesn't have a way to fail outright, only to answer.
            tracing::warn!(diagnostic = %String::from_utf8_lossy(challenge), "XOAUTH2 rejected");
            String::new()
        }
    }
}

/// What's actually stored in the keyring for an `OAuthMicrosoft` account
/// — serialized to JSON in place of a plain password string.
/// `CredentialStore` itself stays password-shaped and unaware of this;
/// it just stores whatever string it's handed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredOAuthToken {
    access_token: String,
    refresh_token: String,
    /// Unix seconds.
    expires_at: i64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serializes the actual refresh (not every call — see `resolve_credential`'s
/// double-checked read below) across every account. `sync::run`'s
/// background loop and the daemon's periodic push loop each poll
/// independently, so without this, both can decide at once that a
/// token needs refreshing and race to redeem the same refresh token —
/// which can fail outright if Microsoft rotates it on first use and the
/// loser tries to redeem one that's already been superseded. One global
/// lock rather than a per-account registry: refreshes are rare (roughly
/// hourly per account) and fast, so serializing unrelated accounts'
/// refreshes against each other costs nothing worth avoiding the extra
/// bookkeeping for.
static REFRESH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Resolves whatever secret an account actually needs right now, ready
/// to hand straight to `connect_and_login`/`send` — the one function
/// every call site in `candor-daemon` uses instead of reading the
/// keyring directly, so the "refresh before it expires" logic lives in
/// exactly one place rather than being duplicated at every call site.
pub fn resolve_credential(account: &AccountConfig) -> Result<Zeroizing<String>> {
    match account.auth_method {
        AuthMethod::Password => CredentialStore::get_password(&account.id),
        AuthMethod::OAuthMicrosoft => {
            let raw = CredentialStore::get_password(&account.id)
                .context("no OAuth token stored for this account")?;
            let token: StoredOAuthToken =
                serde_json::from_str(&raw).context("stored OAuth token was not valid JSON")?;

            if token.expires_at - now_unix() >= REFRESH_SKEW_SECS {
                return Ok(Zeroizing::new(token.access_token));
            }

            // Needs a refresh — take the lock, then re-read and
            // re-check before actually calling out to Microsoft. If
            // another caller won this race while we were waiting for
            // the lock, the keyring already holds their fresh token by
            // the time we get it, and we just use that instead of
            // redeeming a refresh token that may already be stale.
            let _guard = REFRESH_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let raw = CredentialStore::get_password(&account.id)
                .context("no OAuth token stored for this account")?;
            let mut token: StoredOAuthToken =
                serde_json::from_str(&raw).context("stored OAuth token was not valid JSON")?;

            if token.expires_at - now_unix() < REFRESH_SKEW_SECS {
                token = refresh(&token.refresh_token)?;
                store_token(&account.id, &token)?;
            }

            // `StoredOAuthToken` itself stays plain-`String`-shaped (it
            // round-trips through `serde_json`, which `Zeroizing<T>`
            // doesn't support directly) — wrapped here, at the moment
            // it actually leaves this function as the live credential
            // callers hold onto.
            Ok(Zeroizing::new(token.access_token))
        }
    }
}

fn store_token(account_id: &str, token: &StoredOAuthToken) -> Result<()> {
    let serialized = serde_json::to_string(token).context("serializing OAuth token")?;
    CredentialStore::set_password(account_id, &serialized).context("storing OAuth token")
}

/// Persists the first token pair from a completed interactive sign-in —
/// called once, right after [`complete_interactive_sign_in`] succeeds,
/// by the same account-creation path `CredentialStore::set_password`
/// would otherwise be called from directly for a password account.
pub fn store_initial_token(
    account_id: &str,
    access_token: &str,
    refresh_token: &str,
    expires_at: i64,
) -> Result<()> {
    store_token(
        account_id,
        &StoredOAuthToken {
            access_token: access_token.to_string(),
            refresh_token: refresh_token.to_string(),
            expires_at,
        },
    )
}

fn refresh(refresh_token: &str) -> Result<StoredOAuthToken> {
    let client = BasicClient::new(ClientId::new(CLIENT_ID.to_string()))
        .set_token_uri(TokenUrl::new(TOKEN_URL.to_string()).context("building token URL")?);

    let token_result = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
        .request(&ureq_http_client)
        .map_err(|e| anyhow!("Microsoft token refresh failed: {e}"))?;

    let access_token = token_result.access_token().secret().clone();
    // Microsoft rotates refresh tokens on some grants but not every one
    // — fall back to the token that was just used if a new one wasn't
    // issued this time.
    let refresh_token = token_result
        .refresh_token()
        .map(|t| t.secret().clone())
        .unwrap_or_else(|| refresh_token.to_string());
    let expires_at = now_unix() + token_result.expires_in().map(|d| d.as_secs() as i64).unwrap_or(3600);

    Ok(StoredOAuthToken {
        access_token,
        refresh_token,
        expires_at,
    })
}

/// The result of a completed interactive sign-in, ready to verify
/// against the real server and then persist — mirrors what a typed
/// password is for the ordinary account-creation path.
pub struct FreshToken {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_at: i64,
}

/// Runs the whole interactive dance, blocking until it's done: opens the
/// system browser to Microsoft's consent page, listens on a one-shot
/// local HTTP server for the redirect, and exchanges the resulting code
/// for the first token pair. Call this from a background thread (e.g.
/// `tokio::task::spawn_blocking`), never from the GUI's own event loop —
/// it blocks for as long as the user takes to actually sign in.
pub fn interactive_sign_in() -> Result<FreshToken> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding local OAuth redirect listener")?;
    let port = listener.local_addr().context("reading local listener port")?.port();
    let redirect_uri = format!("http://localhost:{port}");

    let client = BasicClient::new(ClientId::new(CLIENT_ID.to_string()))
        .set_auth_uri(AuthUrl::new(AUTH_URL.to_string()).context("building auth URL")?)
        .set_token_uri(TokenUrl::new(TOKEN_URL.to_string()).context("building token URL")?)
        .set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).context("building redirect URL")?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut auth_request = client.authorize_url(CsrfToken::new_random).set_pkce_challenge(pkce_challenge);
    for scope in SCOPES {
        auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
    }
    let (auth_url, csrf_token) = auth_request.url();

    std::process::Command::new("xdg-open")
        .arg(auth_url.to_string())
        .spawn()
        .context("opening system browser for Microsoft sign-in")?;

    let stream = accept_with_timeout(&listener, SIGN_IN_TIMEOUT)?;
    let (code, state) = read_redirect(stream)?;

    if state != *csrf_token.secret() {
        bail!("OAuth redirect state did not match what was sent — aborting sign-in");
    }

    let token_result = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request(&ureq_http_client)
        .map_err(|e| anyhow!("Microsoft token exchange failed: {e}"))?;

    let access_token = Zeroizing::new(token_result.access_token().secret().clone());
    let refresh_token = Zeroizing::new(
        token_result
            .refresh_token()
            .context("Microsoft did not return a refresh token (missing offline_access scope?)")?
            .secret()
            .clone(),
    );
    let expires_at = now_unix() + token_result.expires_in().map(|d| d.as_secs() as i64).unwrap_or(3600);

    Ok(FreshToken {
        access_token,
        refresh_token,
        expires_at,
    })
}

/// Waits for the one connection `interactive_sign_in`'s listener will
/// ever accept, bounded by `timeout` — plain `TcpListener::accept` has
/// no timeout of its own, so this polls a non-blocking listener instead
/// of risking an unbounded hang if the browser flow is abandoned.
fn accept_with_timeout(listener: &TcpListener, timeout: std::time::Duration) -> Result<TcpStream> {
    listener.set_nonblocking(true).context("setting redirect listener non-blocking")?;
    let deadline = std::time::Instant::now() + timeout;

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted connections don't reliably inherit the
                // listener's non-blocking mode across platforms —
                // `read_redirect` expects ordinary blocking reads.
                stream.set_nonblocking(false).context("resetting accepted stream to blocking")?;
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    bail!(
                        "timed out after {}s waiting for the Microsoft sign-in to complete — \
                         the browser tab may have been closed before finishing",
                        timeout.as_secs()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return Err(e).context("waiting for the Microsoft sign-in redirect"),
        }
    }
}

/// Reads the one raw HTTP GET request the redirect listener will ever
/// see, pulls `code`/`state` (or `error`) out of its query string, and
/// writes back a minimal human-readable response so the browser tab
/// doesn't just hang. There's no real HTTP server here — a loopback
/// redirect is a single one-shot request, not a service to build out.
fn read_redirect(stream: TcpStream) -> Result<(String, String)> {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("reading the OAuth redirect request")?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .context("malformed redirect request line")?;
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    if let Some(err) = params.get("error") {
        // `error` alone (e.g. "access_denied") is ambiguous — it covers
        // both "you declined consent yourself" and "your tenant's admin
        // policy blocks consenting to this app at all." Microsoft's own
        // `error_description` distinguishes the two (look for an
        // AADSTS code in it), which otherwise gets silently dropped.
        let detail = params.get("error_description").map(String::as_str).unwrap_or("no further detail given");
        bail!("Microsoft sign-in was not completed: {err} — {detail}");
    }

    let code = params.get("code").cloned().context("no authorization code in redirect")?;
    let state = params.get("state").cloned().context("no state in redirect")?;

    let body = "<html><body>Signed in. You can close this tab and return to Candor.</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut stream = stream;
    let _ = stream.write_all(response.as_bytes());

    Ok((code, state))
}

/// Bridges `oauth2`'s transport-agnostic HTTP requests onto `ureq`
/// (already a dependency for `discover.rs`'s autoconfig fetch) instead
/// of pulling in `reqwest` just for this. The `oauth2` crate's own docs
/// are explicit that a custom HTTP client must not follow redirects
/// automatically (SSRF hardening — a malicious or compromised endpoint
/// could otherwise redirect the request, code/PKCE verifier or refresh
/// token included, somewhere else entirely). `ureq` *does* follow
/// redirects by default (up to 10, for any method) unless told not to
/// — `max_redirects(0)` below is that explicit opt-out, not a no-op.
fn ureq_http_client(request: oauth2::HttpRequest) -> Result<oauth2::HttpResponse, OAuthTransportError> {
    let uri = request.uri().to_string();
    if request.method() != oauth2::http::Method::POST {
        return Err(OAuthTransportError(format!(
            "unsupported HTTP method {}",
            request.method()
        )));
    }

    let mut builder = ureq::post(&uri).config().http_status_as_error(false).max_redirects(0).build();
    for (name, value) in request.headers() {
        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    let mut response = builder
        .send(request.body().clone())
        .map_err(|e| OAuthTransportError(e.to_string()))?;

    let status = response.status();
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|e| OAuthTransportError(e.to_string()))?;

    let mut out = oauth2::http::Response::builder().status(status);
    for (name, value) in response.headers() {
        out = out.header(name, value);
    }
    out.body(body).map_err(|e| OAuthTransportError(e.to_string()))
}

#[derive(Debug)]
struct OAuthTransportError(String);

impl std::fmt::Display for OAuthTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for OAuthTransportError {}
