//! Server-settings autodiscovery for a new account's email domain.
//!
//! Deliberately does **not** query any third-party aggregator (e.g.
//! Mozilla's central ISPDB at autoconfig.thunderbird.net) — every lookup
//! here is tied to a source the user already trusts by using that email
//! address: a local table of well-known providers, the provider's own
//! self-hosted autoconfig endpoint, and DNS SRV records for the user's own
//! domain. Falls back to common hostname guesses, which are verified by an
//! actual TCP probe before being offered.
//!
//! No step here ever returns a plaintext (no-TLS) configuration — if a
//! source recommends one, that source's result is discarded rather than
//! downgraded.

use std::net::TcpStream;

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use quick_xml::de::from_str as xml_from_str;
use serde::Deserialize;

use crate::config::Security;

#[derive(Debug, Clone)]
pub struct ServerSettings {
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    WellKnown,
    ProviderAutoconfig,
    DnsSrv,
    Guessed,
}

#[derive(Debug, Clone)]
pub struct Discovery {
    pub settings: ServerSettings,
    pub method: DiscoveryMethod,
}

pub async fn discover(domain: &str) -> Option<Discovery> {
    if let Some(settings) = well_known(domain) {
        return Some(Discovery {
            settings,
            method: DiscoveryMethod::WellKnown,
        });
    }
    if let Some(settings) = provider_autoconfig(domain).await {
        return Some(Discovery {
            settings,
            method: DiscoveryMethod::ProviderAutoconfig,
        });
    }
    if let Some(settings) = dns_srv(domain).await {
        return Some(Discovery {
            settings,
            method: DiscoveryMethod::DnsSrv,
        });
    }
    if let Some(settings) = guess_and_probe(domain).await {
        return Some(Discovery {
            settings,
            method: DiscoveryMethod::Guessed,
        });
    }
    None
}

struct WellKnownProvider {
    domains: &'static [&'static str],
    imap_host: &'static str,
    imap_port: u16,
    imap_security: Security,
    smtp_host: &'static str,
    smtp_port: u16,
    smtp_security: Security,
}

static WELL_KNOWN: &[WellKnownProvider] = &[
    WellKnownProvider {
        domains: &["gmail.com", "googlemail.com"],
        imap_host: "imap.gmail.com",
        imap_port: 993,
        imap_security: Security::ImplicitTls,
        smtp_host: "smtp.gmail.com",
        smtp_port: 465,
        smtp_security: Security::ImplicitTls,
    },
    WellKnownProvider {
        // Per Microsoft's own current consumer help page (verified
        // 2026-10-31): the SMTP host for a personal Outlook.com/
        // Hotmail/Live/MSN account is `smtp-mail.outlook.com`, NOT
        // `smtp.office365.com` — that one's the Microsoft 365
        // organizational (work/school) endpoint. Using the wrong one
        // here was a real, live-discovered bug: IMAP against
        // `outlook.office365.com` succeeded, but SMTP against the
        // org-tenant hostname produced a confusing auth rejection
        // for a genuine personal account.
        domains: &["outlook.com", "hotmail.com", "live.com", "msn.com"],
        imap_host: "outlook.office365.com",
        imap_port: 993,
        imap_security: Security::ImplicitTls,
        smtp_host: "smtp-mail.outlook.com",
        smtp_port: 587,
        smtp_security: Security::StartTls,
    },
    WellKnownProvider {
        domains: &["yahoo.com", "yahoo.co.uk", "ymail.com"],
        imap_host: "imap.mail.yahoo.com",
        imap_port: 993,
        imap_security: Security::ImplicitTls,
        smtp_host: "smtp.mail.yahoo.com",
        smtp_port: 465,
        smtp_security: Security::ImplicitTls,
    },
    WellKnownProvider {
        domains: &["fastmail.com", "fastmail.fm"],
        imap_host: "imap.fastmail.com",
        imap_port: 993,
        imap_security: Security::ImplicitTls,
        smtp_host: "smtp.fastmail.com",
        smtp_port: 465,
        smtp_security: Security::ImplicitTls,
    },
    WellKnownProvider {
        domains: &["icloud.com", "me.com", "mac.com"],
        imap_host: "imap.mail.me.com",
        imap_port: 993,
        imap_security: Security::ImplicitTls,
        smtp_host: "smtp.mail.me.com",
        smtp_port: 587,
        smtp_security: Security::StartTls,
    },
    WellKnownProvider {
        domains: &["zoho.com"],
        imap_host: "imap.zoho.com",
        imap_port: 993,
        imap_security: Security::ImplicitTls,
        smtp_host: "smtp.zoho.com",
        smtp_port: 465,
        smtp_security: Security::ImplicitTls,
    },
];

fn well_known(domain: &str) -> Option<ServerSettings> {
    let domain = domain.to_ascii_lowercase();
    WELL_KNOWN
        .iter()
        .find(|p| p.domains.contains(&domain.as_str()))
        .map(|p| ServerSettings {
            imap_host: p.imap_host.to_string(),
            imap_port: p.imap_port,
            imap_security: p.imap_security,
            smtp_host: p.smtp_host.to_string(),
            smtp_port: p.smtp_port,
            smtp_security: p.smtp_security,
        })
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    #[serde(rename = "emailProvider")]
    email_provider: EmailProvider,
}

#[derive(Debug, Deserialize)]
struct EmailProvider {
    #[serde(rename = "incomingServer", default)]
    incoming_server: Vec<XmlServer>,
    #[serde(rename = "outgoingServer", default)]
    outgoing_server: Vec<XmlServer>,
}

#[derive(Debug, Deserialize)]
struct XmlServer {
    #[serde(rename = "@type")]
    kind: String,
    hostname: String,
    port: u16,
    #[serde(rename = "socketType")]
    socket_type: String,
}

async fn provider_autoconfig(domain: &str) -> Option<ServerSettings> {
    let domain = domain.to_string();
    tokio::task::spawn_blocking(move || fetch_provider_autoconfig(&domain))
        .await
        .ok()
        .flatten()
}

fn fetch_provider_autoconfig(domain: &str) -> Option<ServerSettings> {
    let urls = [
        format!("https://autoconfig.{domain}/mail/config-v1.1.xml"),
        format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
    ];
    for url in urls {
        let Ok(mut response) = ureq::get(&url).call() else {
            continue;
        };
        let Ok(body) = response.body_mut().read_to_string() else {
            continue;
        };
        if let Some(settings) = parse_autoconfig_xml(&body) {
            return Some(settings);
        }
    }
    None
}

fn parse_autoconfig_xml(xml: &str) -> Option<ServerSettings> {
    let config: ClientConfig = xml_from_str(xml).ok()?;
    let incoming = config
        .email_provider
        .incoming_server
        .into_iter()
        .find(|s| s.kind == "imap")?;
    let outgoing = config
        .email_provider
        .outgoing_server
        .into_iter()
        .find(|s| s.kind == "smtp")?;

    Some(ServerSettings {
        imap_host: incoming.hostname,
        imap_port: incoming.port,
        imap_security: socket_type_to_security(&incoming.socket_type)?,
        smtp_host: outgoing.hostname,
        smtp_port: outgoing.port,
        smtp_security: socket_type_to_security(&outgoing.socket_type)?,
    })
}

/// Rejects anything that isn't TLS outright — an autoconfig entry
/// recommending "plain" is discarded, never downgraded-to.
fn socket_type_to_security(socket_type: &str) -> Option<Security> {
    match socket_type.to_ascii_uppercase().as_str() {
        "SSL" => Some(Security::ImplicitTls),
        "STARTTLS" => Some(Security::StartTls),
        _ => None,
    }
}

async fn dns_srv(domain: &str) -> Option<ServerSettings> {
    let resolver = TokioResolver::builder_tokio().ok()?.build().ok()?;

    let imap = match srv_lookup(&resolver, &format!("_imaps._tcp.{domain}.")).await {
        Some((host, port)) => Some((host, port, Security::ImplicitTls)),
        None => srv_lookup(&resolver, &format!("_imap._tcp.{domain}."))
            .await
            .map(|(host, port)| (host, port, Security::StartTls)),
    }?;

    let smtp = match srv_lookup(&resolver, &format!("_submissions._tcp.{domain}.")).await {
        Some((host, port)) => Some((host, port, Security::ImplicitTls)),
        None => srv_lookup(&resolver, &format!("_submission._tcp.{domain}."))
            .await
            .map(|(host, port)| (host, port, Security::StartTls)),
    }?;

    Some(ServerSettings {
        imap_host: imap.0,
        imap_port: imap.1,
        imap_security: imap.2,
        smtp_host: smtp.0,
        smtp_port: smtp.1,
        smtp_security: smtp.2,
    })
}

async fn srv_lookup(resolver: &TokioResolver, name: &str) -> Option<(String, u16)> {
    let lookup = resolver.lookup(name, RecordType::SRV).await.ok()?;
    lookup.answers().iter().find_map(|record| {
        let RData::SRV(srv) = &record.data else {
            return None;
        };
        let host = srv.target.to_string().trim_end_matches('.').to_string();
        if host.is_empty() {
            // A target of "." means the service is explicitly unavailable.
            return None;
        }
        Some((host, srv.port))
    })
}

async fn guess_and_probe(domain: &str) -> Option<ServerSettings> {
    let imap_host = format!("imap.{domain}");
    let smtp_host = format!("smtp.{domain}");

    let (imap_ok, smtp_ok) = tokio::join!(
        probe_tcp(imap_host.clone(), 993),
        probe_tcp(smtp_host.clone(), 465),
    );

    if imap_ok && smtp_ok {
        Some(ServerSettings {
            imap_host,
            imap_port: 993,
            imap_security: Security::ImplicitTls,
            smtp_host,
            smtp_port: 465,
            smtp_security: Security::ImplicitTls,
        })
    } else {
        None
    }
}

async fn probe_tcp(host: String, port: u16) -> bool {
    tokio::task::spawn_blocking(move || TcpStream::connect((host.as_str(), port)).is_ok())
        .await
        .unwrap_or(false)
}
