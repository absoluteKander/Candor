//! Real connectivity + authentication checks against a candidate server
//! configuration, used before an account is ever saved. A password that
//! fails here is never written to the keyring or config file.

use anyhow::{anyhow, bail, Context, Result};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, Tokio1Executor};

use crate::config::Security;

pub async fn test_imap(
    host: &str,
    port: u16,
    security: Security,
    username: &str,
    password: &str,
) -> Result<()> {
    let host = host.to_string();
    let username = username.to_string();
    let password = password.to_string();

    tokio::task::spawn_blocking(move || {
        let tls = native_tls::TlsConnector::builder()
            .build()
            .context("building TLS connector")?;

        let client = match security {
            Security::ImplicitTls => imap::connect((host.as_str(), port), host.as_str(), &tls)
                .map_err(|e| anyhow!("IMAP connect failed: {e}"))?,
            Security::StartTls => {
                imap::connect_starttls((host.as_str(), port), host.as_str(), &tls)
                    .map_err(|e| anyhow!("IMAP STARTTLS connect failed: {e}"))?
            }
        };

        let mut session = client
            .login(&username, &password)
            .map_err(|(e, _client)| anyhow!("IMAP login failed: {e}"))?;
        let _ = session.logout();
        Ok(())
    })
    .await
    .context("IMAP test task panicked")?
}

pub async fn test_smtp(
    host: &str,
    port: u16,
    security: Security,
    username: &str,
    password: &str,
) -> Result<()> {
    let creds = Credentials::new(username.to_string(), password.to_string());

    let builder = match security {
        Security::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
        Security::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host),
    }
    .with_context(|| format!("building SMTP transport for {host}"))?;

    let transport: AsyncSmtpTransport<Tokio1Executor> =
        builder.port(port).credentials(creds).build();

    let ok = transport
        .test_connection()
        .await
        .context("SMTP connection/auth failed")?;

    if !ok {
        bail!("SMTP server did not confirm the connection");
    }
    Ok(())
}
