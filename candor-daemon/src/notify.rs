//! Turns newly-arrived unread INBOX mail into a desktop notification via
//! the standard freedesktop.org notifications D-Bus interface — the same
//! one `notify-send` and every other Linux desktop app use, so this
//! shows up through whatever notification daemon the user's desktop
//! already has running, with no new dependency on candor-core (which
//! knows nothing about D-Bus at all — see `sync::run`'s doc comment).

use candor_core::sync::NewMailSummary;
use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: std::collections::HashMap<&str, zbus::Variant<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// Opens its own short-lived session-bus connection rather than reusing
/// `candor-daemon`'s own service connection — notifications are rare
/// (new mail arriving) and this keeps the sync loop that calls it
/// entirely decoupled from whatever order `main` happens to set up the
/// D-Bus service connection in.
pub async fn send_new_mail_notification(mail: &[NewMailSummary]) -> anyhow::Result<()> {
    let conn = zbus::Connection::session().await?;
    let proxy = NotificationsProxy::new(&conn).await?;

    let (summary, body) = compose(mail);

    proxy
        .notify("Candor", 0, "mail-unread-symbolic", &summary, &body, &[], Default::default(), -1)
        .await?;
    Ok(())
}

fn compose(mail: &[NewMailSummary]) -> (String, String) {
    if let [one] = mail {
        (sender_label(one), one.subject.as_deref().unwrap_or("(no subject)").to_string())
    } else {
        let summary = format!("{} new messages", mail.len());
        let body = mail
            .iter()
            .take(3)
            .map(|m| format!("{} — {}", sender_label(m), m.subject.as_deref().unwrap_or("(no subject)")))
            .collect::<Vec<_>>()
            .join("\n");
        let body = if mail.len() > 3 {
            format!("{body}\n…and {} more", mail.len() - 3)
        } else {
            body
        };
        (summary, body)
    }
}

fn sender_label(m: &NewMailSummary) -> String {
    m.from_name
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| m.from_address.clone())
        .unwrap_or_else(|| "(unknown sender)".to_string())
}
