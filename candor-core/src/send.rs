//! Plain-text message sending via SMTP, and saving that same message as
//! an IMAP draft instead (or as well, when replacing an
//! already-in-progress one — see `save_draft`). Matches v1 scope: no
//! rich formatting — just compose/reply/forward with a quoted plain
//! text body and, optionally, file attachments.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use lettre::message::{Attachment, Mailbox, Mailboxes, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use zeroize::Zeroizing;

use crate::config::{AccountConfig, AuthMethod, Security};
use crate::sync::connect_and_login;

pub struct OutgoingMessage {
    /// Comma-separated recipient addresses, as typed by the user. May be
    /// empty when building a draft — unlike an actual send, a draft
    /// doesn't need a recipient filled in yet.
    pub to: String,
    pub subject: String,
    pub body: String,
    /// The original message's `Message-ID`, when replying.
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    /// Local file paths picked by the user to attach — read and attached
    /// as-is, never persisted anywhere beyond the outgoing message itself.
    pub attachments: Vec<PathBuf>,
    /// This outgoing message's own `Message-ID` — generated once by the
    /// caller (`generate_message_id`) *before* calling `send`/
    /// `save_draft`, rather than inside `build_message` as before. The
    /// caller needs this exact string back to cache the sent body for
    /// search under the same key the message will later be found under
    /// (see `candor-gui`'s send-success path) — there was previously no
    /// way to recover it after the fact, since nothing outside
    /// `build_message` ever saw the value it generated internally.
    pub message_id: String,
}

/// Builds the actual MIME message — shared by `send` and `save_draft`,
/// since a draft is just this same message headed to IMAP `APPEND`
/// instead of an SMTP transport. `require_recipient` is the only real
/// difference between the two call sites: an actual send has to bail
/// without one, but a draft is allowed to sit there half-finished with
/// no "To" filled in yet.
async fn build_message(account: &AccountConfig, msg: OutgoingMessage, require_recipient: bool) -> Result<Message> {
    let bare_from: Mailbox = account.email.parse().context("invalid From address in account config")?;
    // Attach the account's own display name to the From header (e.g.
    // "Jane Doe <you@gmail.com>") so recipients see a name, not
    // a bare address — `display_name` was captured at account-setup
    // time but never actually used for this until now. Empty is left
    // as no name at all, same as before this existed, rather than
    // showing an empty `"" <you@gmail.com>`.
    let name = (!account.display_name.trim().is_empty()).then(|| account.display_name.clone());
    let from = Mailbox::new(name, bare_from.email);

    let mut builder = Message::builder()
        .from(from.clone())
        .subject(msg.subject)
        .message_id(Some(msg.message_id));

    let mut has_recipient = false;
    if !msg.to.trim().is_empty() {
        let recipients: Mailboxes =
            msg.to.parse().context("couldn't parse the recipient address(es)")?;
        for mailbox in recipients {
            has_recipient = true;
            builder = builder.to(mailbox);
        }
    }
    if require_recipient && !has_recipient {
        bail!("no recipients");
    }
    if !has_recipient {
        // `lettre::Message` is fundamentally built around "this will be
        // transported", so it always derives (or demands) a real SMTP
        // envelope — even for a draft, which is never actually
        // transported; it's only ever `.formatted()` into bytes for an
        // IMAP `APPEND`. Since nothing ever sends this particular
        // `Message`, an explicit envelope that just points back at our
        // own address satisfies that structural requirement without
        // adding any visible "To" header — `.envelope(...)` bypasses
        // deriving one from headers entirely, so this never leaks into
        // the saved draft's actual content.
        builder = builder.envelope(
            lettre::address::Envelope::new(Some(from.email.clone()), vec![from.email])
                .context("building placeholder envelope for a recipient-less draft")?,
        );
    }
    if let Some(id) = msg.in_reply_to {
        builder = builder.in_reply_to(id);
    }
    if let Some(refs) = msg.references {
        builder = builder.references(refs);
    }

    if msg.attachments.is_empty() {
        builder.body(msg.body).context("building outgoing message")
    } else {
        let mut multipart = MultiPart::mixed().singlepart(SinglePart::plain(msg.body));
        for path in &msg.attachments {
            let bytes = tokio::fs::read(path)
                .await
                .with_context(|| format!("reading attachment {}", path.display()))?;
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "attachment".to_string());
            let mime = infer::get(&bytes).map(|k| k.mime_type()).unwrap_or("application/octet-stream");
            let content_type = lettre::message::header::ContentType::parse(mime)
                .unwrap_or_else(|_| lettre::message::header::ContentType::TEXT_PLAIN);
            multipart = multipart.singlepart(Attachment::new(filename).body(bytes, content_type));
        }
        builder.multipart(multipart).context("building outgoing message")
    }
}

/// `secret` is whatever `oauth::resolve_credential` returned for this
/// account — a plain password for `AuthMethod::Password`, or a live
/// Microsoft access token for `AuthMethod::OAuthMicrosoft`.
pub async fn send(account: &AccountConfig, secret: &str, msg: OutgoingMessage) -> Result<()> {
    let email = build_message(account, msg, true).await?;

    let creds = Credentials::new(account.username.clone(), secret.to_string());
    let mut transport_builder = match account.smtp_security {
        Security::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&account.smtp_host),
        Security::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&account.smtp_host),
    }
    .with_context(|| format!("building SMTP transport for {}", account.smtp_host))?;

    if account.auth_method == AuthMethod::OAuthMicrosoft {
        transport_builder = transport_builder.authentication(vec![Mechanism::Xoauth2]);
    }

    let transport: AsyncSmtpTransport<Tokio1Executor> =
        transport_builder.port(account.smtp_port).credentials(creds).build();

    transport.send(email).await.context("sending message")?;
    Ok(())
}

/// Saves a message to the given folder (the account's `\Drafts` folder,
/// resolved by the caller from the locally-synced SPECIAL-USE
/// attributes) via IMAP `APPEND` rather than sending it — this is what
/// actually makes "write something, back out, come back to it" work,
/// the same way every other mail client treats an in-progress compose.
/// Connects fresh, the same one-shot pattern as everything else in
/// `sync.rs` that isn't the long-lived background loop.
pub async fn save_draft(account: &AccountConfig, password: &str, drafts_folder: &str, msg: OutgoingMessage) -> Result<()> {
    let email = build_message(account, msg, false).await?;
    let bytes = email.formatted();

    let account = account.clone();
    let password = Zeroizing::new(password.to_string());
    let drafts_folder = drafts_folder.to_string();
    tokio::task::spawn_blocking(move || {
        let mut session = connect_and_login(&account, &password)?;
        session
            .append(&drafts_folder, &bytes)
            .map_err(|e| anyhow::anyhow!("saving draft to {drafts_folder} failed: {e}"))?;
        let _ = session.logout();
        Ok(())
    })
    .await
    .context("draft save task panicked")?
}

/// Not cryptographically random — a `Message-ID` just needs to be unique,
/// and timestamp + pid is more than enough for that. Public because the
/// caller (`candor-gui`) now generates this once, before calling
/// `send`/`save_draft`, so it has the exact same value back to key the
/// sent-mail body cache under — see `OutgoingMessage::message_id`'s doc
/// comment.
pub fn generate_message_id(from_email: &str) -> String {
    let domain = from_email.rsplit_once('@').map(|(_, d)| d).unwrap_or("localhost");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("<{nanos}.{}@{domain}>", std::process::id())
}
