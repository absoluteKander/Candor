use candor_core::inspect::{self, AttachmentWarningReason, LinkWarningReason};

const EML: &str = concat!(
    "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil-domain.ru; ",
    "dmarc=fail header.from=evil-domain.ru\r\n",
    "From: \"security@paypal.com\" <attacker@evil-domain.ru>\r\n",
    "Reply-To: other-attacker@another-evil.ru\r\n",
    "To: victim@example.com\r\n",
    "Subject: Your account has been limited\r\n",
    "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n",
    "\r\n",
    "--BOUNDARY\r\n",
    "Content-Type: text/html; charset=\"utf-8\"\r\n",
    "\r\n",
    "<html><body>\r\n",
    "<script>alert('xss')</script>\r\n",
    "<p>Click <a href=\"http://evil-domain.ru/phish\">https://paypal.com/login</a> to verify.</p>\r\n",
    "<img src=\"http://evil-domain.ru/track.gif\" width=\"1\" height=\"1\">\r\n",
    "</body></html>\r\n",
    "--BOUNDARY\r\n",
    "Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n",
    "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n",
    "Content-Transfer-Encoding: base64\r\n",
    "\r\n",
    "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n", // "MZ" DOS header magic bytes (base64), i.e. a real PE executable signature
    "--BOUNDARY--\r\n",
);

#[tokio::test]
async fn flags_a_phishing_style_message() {
    let verdict = inspect::inspect(EML.as_bytes()).await.expect("inspect should not error");

    assert_eq!(verdict.dkim_verified, None, "message has no DKIM-Signature at all");
    assert_eq!(verdict.spf_pass, Some(false), "Authentication-Results said spf=fail");
    assert_eq!(verdict.dmarc_pass, Some(false), "Authentication-Results said dmarc=fail");

    assert!(verdict.sender_display_mismatch, "display name embeds paypal.com but From is evil-domain.ru");
    assert!(verdict.reply_to_mismatch, "Reply-To domain differs from From domain");

    let html = verdict.sanitized_html.as_deref().unwrap_or_default();
    assert!(!html.contains("<script"), "script tag must be stripped: {html}");
    assert!(!html.contains("evil-domain.ru/track.gif"), "tracking pixel src must be stripped: {html}");

    assert_eq!(verdict.blocked_remote_resources, vec!["http://evil-domain.ru/track.gif"]);
    assert_eq!(verdict.suspected_trackers, vec!["http://evil-domain.ru/track.gif"]);

    assert_eq!(verdict.link_warnings.len(), 1);
    assert_eq!(verdict.link_warnings[0].reason, LinkWarningReason::TextDomainMismatch);
    assert_eq!(verdict.link_warnings[0].href, "http://evil-domain.ru/phish");

    let reasons: Vec<_> = verdict
        .attachment_warnings
        .iter()
        .map(|w| w.reason.clone())
        .collect();
    assert!(reasons.contains(&AttachmentWarningReason::DangerousExtension));
    assert!(reasons.contains(&AttachmentWarningReason::DoubleExtension));

    // The images-allowed variant (only ever used after explicit opt-in)
    // must still strip script/etc, but keep img src so the opted-in
    // fetch step knows what to download.
    let with_images = verdict.sanitized_html_with_images.as_deref().unwrap_or_default();
    assert!(!with_images.contains("<script"), "script must still be stripped: {with_images}");
    assert!(
        with_images.contains("evil-domain.ru/track.gif"),
        "img src must survive in the images-allowed variant: {with_images}"
    );
}

#[tokio::test]
async fn clean_message_raises_no_warnings() {
    let clean = concat!(
        "From: Jane Doe <jane@example.com>\r\n",
        "To: bob@example.org\r\n",
        "Subject: Lunch tomorrow?\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Want to grab lunch tomorrow at noon?\r\n",
    );

    let verdict = inspect::inspect(clean.as_bytes()).await.expect("inspect should not error");

    assert!(!verdict.sender_display_mismatch);
    assert!(!verdict.reply_to_mismatch);
    assert!(verdict.link_warnings.is_empty());
    assert!(verdict.attachment_warnings.is_empty());
    assert!(verdict.blocked_remote_resources.is_empty());
}
