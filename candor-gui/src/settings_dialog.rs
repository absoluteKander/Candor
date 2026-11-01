//! The one consolidated app-level Settings dialog — replaces what used
//! to be a `build_preferences_dialog` duplicated identically inside
//! every `AccountTab`'s own Settings menu. A setting that's the same
//! regardless of which account tab happens to be open shouldn't need
//! hunting through a separate menu per tab to change it. Owned by
//! `App` (`main.rs`), not any one tab — see `App::settings`'s doc
//! comment.
//!
//! The global groups (Inbox/Compose/Search/Sync/Notifications) are the
//! same ones `AccountTab` used to build, just reading/writing `App`'s
//! one copy of `AppSettings` instead of a per-tab one. The new
//! "Accounts" group below them is this screen's actual reason for
//! being: `color`/`short_name`/`tab_order`/`is_default` had no editor
//! at all before this — only `locked`/`muted`, toggled from the tab
//! strip itself, were ever live-editable.
//!
//! Written straight to `accounts.toml` from here (`App::move_account`/
//! `mutate_account_config`), no daemon round trip, deliberately
//! consistent with how `AppSettings` itself has always been a
//! GUI-direct-write field — nothing in the daemon enforces or depends
//! on these fields the way `send_message` depends on `locked`, so
//! there's no reason to treat them differently.

use candor_core::config::{self, TabColor};
use relm4::adw;
use relm4::adw::prelude::*;
use relm4::gtk;

use crate::Msg;

const COLORS: [TabColor; 8] = [
    TabColor::Blue,
    TabColor::Green,
    TabColor::Purple,
    TabColor::Orange,
    TabColor::Red,
    TabColor::Teal,
    TabColor::Pink,
    TabColor::Yellow,
];

/// Built fresh each time Settings is opened (not a persistent `App`
/// field) — pre-filled from whatever `settings`/`accounts` were at the
/// moment it opened, and every change saves immediately, matching the
/// rest of this app's local-first-instant feel rather than needing an
/// explicit Save button. `accounts` is expected already sorted by
/// `tab_order` (same order `App::open_settings` reads it in).
pub fn build(
    settings: config::AppSettings,
    accounts: Vec<config::AccountConfig>,
    input_sender: relm4::Sender<Msg>,
) -> adw::PreferencesDialog {
    let dialog = adw::PreferencesDialog::new();
    dialog.set_title("Settings");

    let page = adw::PreferencesPage::new();

    let inbox_group = adw::PreferencesGroup::new();
    inbox_group.set_title("Inbox");

    let threshold_row = adw::SpinRow::with_range(2.0, 20.0, 1.0);
    threshold_row.set_title("Bulk action threshold");
    threshold_row.set_subtitle("Selecting this many messages or more shows one bulk-action bar instead of a pop-out per row");
    threshold_row.set_value(settings.bulk_select_threshold as f64);
    {
        let sender = input_sender.clone();
        threshold_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetBulkThreshold(row.value().round() as usize));
        });
    }
    inbox_group.add(&threshold_row);

    let compose_group = adw::PreferencesGroup::new();
    compose_group.set_title("Compose");

    let signature_row = adw::EntryRow::new();
    signature_row.set_title("Signature");
    signature_row.set_text(&settings.signature);
    {
        let sender = input_sender.clone();
        signature_row.connect_changed(move |entry| {
            let _ = sender.send(Msg::SetSignature(entry.text().to_string()));
        });
    }
    compose_group.add(&signature_row);

    let search_group = adw::PreferencesGroup::new();
    search_group.set_title("Search");
    search_group.set_description(Some(
        "Starred mail and anything you've sent are always kept searchable. These limits only apply \
         to ordinary messages you've opened to read.",
    ));

    let retention_days_row = adw::SpinRow::with_range(0.0, 3650.0, 1.0);
    retention_days_row.set_title("Keep message text for");
    retention_days_row.set_subtitle("Days after receipt, 0 for no limit");
    retention_days_row.set_value(settings.body_cache_max_age_days.unwrap_or(0) as f64);
    {
        let sender = input_sender.clone();
        retention_days_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetRetentionDays(row.value().round() as u32));
        });
    }
    search_group.add(&retention_days_row);

    let retention_size_row = adw::SpinRow::with_range(0.0, 100_000.0, 10.0);
    retention_size_row.set_title("Maximum cache size");
    retention_size_row.set_subtitle(
        "Megabytes of searchable text, 0 for no limit \u{2014} text only, never attachments, so this covers far more mail than the number suggests",
    );
    retention_size_row.set_value(settings.body_cache_max_bytes.map(|b| b / 1_000_000).unwrap_or(0) as f64);
    {
        let sender = input_sender.clone();
        retention_size_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetRetentionMaxMb(row.value().round() as u32));
        });
    }
    search_group.add(&retention_size_row);

    let sync_group = adw::PreferencesGroup::new();
    sync_group.set_title("Sync");

    let idle_row = adw::SpinRow::with_range(0.0, 60.0, 1.0);
    idle_row.set_title("Check non-Inbox folders every");
    idle_row.set_subtitle("Minutes, 0 for the default (25) \u{2014} Inbox itself updates immediately via push");
    idle_row.set_value(settings.idle_timeout_minutes.unwrap_or(0) as f64);
    {
        let sender = input_sender.clone();
        idle_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetIdleTimeoutMinutes(row.value().round() as u32));
        });
    }
    sync_group.add(&idle_row);

    let reading_cache_row = adw::SpinRow::with_range(0.0, 100_000.0, 10.0);
    reading_cache_row.set_title("Maximum reading-pane cache size");
    reading_cache_row.set_subtitle(
        "Megabytes, 0 for no limit \u{2014} text and headers only, attachments are never cached",
    );
    reading_cache_row.set_value(settings.reading_cache_max_bytes.map(|b| b / 1_000_000).unwrap_or(0) as f64);
    {
        let sender = input_sender.clone();
        reading_cache_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetReadingCacheMaxMb(row.value().round() as u32));
        });
    }
    sync_group.add(&reading_cache_row);

    let notifications_group = adw::PreferencesGroup::new();
    notifications_group.set_title("Notifications");

    let mark_read_row = adw::SwitchRow::new();
    mark_read_row.set_title("Mark read when clicking a notification");
    mark_read_row.set_subtitle("Off by default \u{2014} clicking one always jumps to the message, this just decides whether it also marks it read");
    mark_read_row.set_active(settings.mark_read_on_notification_click);
    {
        let sender = input_sender.clone();
        mark_read_row.connect_active_notify(move |row| {
            let _ = sender.send(Msg::SetMarkReadOnNotificationClick(row.is_active()));
        });
    }
    notifications_group.add(&mark_read_row);

    let accounts_group = build_accounts_group(&accounts, &input_sender);

    page.add(&inbox_group);
    page.add(&compose_group);
    page.add(&sync_group);
    page.add(&search_group);
    page.add(&notifications_group);
    page.add(&accounts_group);
    dialog.add(&page);

    dialog
}

/// One row per configured account — color, short name, position, which
/// one is default, per-account contact import, and removal. The actual
/// writes happen in `App` (`Msg::SetAccountColor` etc.); this just
/// builds the widgets and wires their signals to send those messages.
fn build_accounts_group(accounts: &[config::AccountConfig], input_sender: &relm4::Sender<Msg>) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::new();
    group.set_title("Accounts");
    group.set_description(Some(
        "Color, name, and tab position \u{2014} changed here, never by dragging tabs live.",
    ));

    let total = accounts.len();
    for (position, account) in accounts.iter().enumerate() {
        let row = adw::ExpanderRow::new();
        let title = if account.short_name.is_empty() { &account.email } else { &account.short_name };
        row.set_title(&gtk::glib::markup_escape_text(title));
        row.set_subtitle(&format!(
            "Position {}{}",
            position + 1,
            if account.is_default { " \u{2014} Default" } else { "" }
        ));

        let dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        dot.add_css_class("candor-tab-color-dot");
        dot.add_css_class(crate::tab_strip_row::tab_color_css_class(account.color));
        dot.set_valign(gtk::Align::Center);
        row.add_prefix(&dot);

        // Short name.
        let name_row = adw::EntryRow::new();
        name_row.set_title("Short name");
        name_row.set_text(&account.short_name);
        {
            let sender = input_sender.clone();
            let id = account.id.clone();
            name_row.connect_changed(move |entry| {
                let raw = entry.text().to_string();
                // Alphanumeric only, capped at 13 characters (the
                // length of "entertainment") — see
                // `AccountConfig::short_name`'s own doc comment.
                let sanitized: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).take(13).collect();
                if sanitized != raw {
                    entry.set_text(&sanitized);
                    return;
                }
                let _ = sender.send(Msg::SetAccountShortName(id.clone(), sanitized));
            });
        }
        row.add_row(&name_row);

        // Color — one small swatch button per preset, reusing the
        // exact same CSS classes the tab strip itself uses.
        let color_row = adw::ActionRow::new();
        color_row.set_title("Color");
        let color_box = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        color_box.set_valign(gtk::Align::Center);
        for color in COLORS {
            let btn = gtk::Button::new();
            btn.add_css_class("flat");
            if color == account.color {
                btn.add_css_class("suggested-action");
            }
            let swatch = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            swatch.add_css_class("candor-tab-color-dot");
            swatch.add_css_class(crate::tab_strip_row::tab_color_css_class(color));
            btn.set_child(Some(&swatch));
            let sender = input_sender.clone();
            let id = account.id.clone();
            btn.connect_clicked(move |_| {
                let _ = sender.send(Msg::SetAccountColor(id.clone(), color));
            });
            color_box.append(&btn);
        }
        color_row.add_suffix(&color_box);
        row.add_row(&color_row);

        // Position — explicit Move Up/Down, never a live drag.
        let order_row = adw::ActionRow::new();
        order_row.set_title("Tab position");
        let up_btn = gtk::Button::from_icon_name("go-up-symbolic");
        up_btn.add_css_class("flat");
        up_btn.set_valign(gtk::Align::Center);
        up_btn.set_sensitive(position > 0);
        {
            let sender = input_sender.clone();
            let id = account.id.clone();
            up_btn.connect_clicked(move |_| {
                let _ = sender.send(Msg::MoveAccountUp(id.clone()));
            });
        }
        let down_btn = gtk::Button::from_icon_name("go-down-symbolic");
        down_btn.add_css_class("flat");
        down_btn.set_valign(gtk::Align::Center);
        down_btn.set_sensitive(position + 1 < total);
        {
            let sender = input_sender.clone();
            let id = account.id.clone();
            down_btn.connect_clicked(move |_| {
                let _ = sender.send(Msg::MoveAccountDown(id.clone()));
            });
        }
        order_row.add_suffix(&up_btn);
        order_row.add_suffix(&down_btn);
        row.add_row(&order_row);

        // Default tab.
        let default_row = adw::ActionRow::new();
        default_row.set_title("Default tab");
        default_row.set_subtitle("The account Candor always opens to");
        let default_btn =
            gtk::Button::with_label(if account.is_default { "This is the default" } else { "Set as Default" });
        default_btn.set_valign(gtk::Align::Center);
        default_btn.set_sensitive(!account.is_default);
        {
            let sender = input_sender.clone();
            let id = account.id.clone();
            default_btn.connect_clicked(move |_| {
                let _ = sender.send(Msg::SetAccountDefault(id.clone()));
            });
        }
        default_row.add_suffix(&default_btn);
        row.add_row(&default_row);

        // Import contacts — scoped to this account, unlike the old
        // global "Contacts" group this replaces (contacts are
        // per-account; a single global action never actually made
        // sense once more than one account could exist).
        let import_row = adw::ActionRow::new();
        import_row.set_title("Import Contacts\u{2026}");
        let import_btn = gtk::Button::with_label("Choose File\u{2026}");
        import_btn.set_valign(gtk::Align::Center);
        {
            let sender = input_sender.clone();
            let id = account.id.clone();
            import_btn.connect_clicked(move |_| {
                let _ = sender.send(Msg::ImportContactsCsvFor(id.clone()));
            });
        }
        import_row.add_suffix(&import_btn);
        row.add_row(&import_row);

        // Remove.
        let remove_row = adw::ActionRow::new();
        remove_row.set_title("Remove Account");
        let remove_btn = gtk::Button::with_label("Remove");
        remove_btn.add_css_class("destructive-action");
        remove_btn.set_valign(gtk::Align::Center);
        {
            let sender = input_sender.clone();
            let id = account.id.clone();
            remove_btn.connect_clicked(move |_| {
                let _ = sender.send(Msg::RemoveAccountRequest(id.clone()));
            });
        }
        remove_row.add_suffix(&remove_btn);
        row.add_row(&remove_row);

        group.add(&row);
    }

    group
}
