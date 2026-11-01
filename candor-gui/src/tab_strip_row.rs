//! One row of the bespoke tab strip that replaces `AdwTabBar`: the
//! stock widget can host at most one clickable icon per tab, and this
//! app needs two — lock and mute — plus a color swatch and no close
//! button.
//! `AdwTabView` itself is untouched and still does the real work of
//! hosting each account's content and switching which one is visible;
//! this is purely a display + click-target row that drives it from
//! outside, mediated by `App` (`main.rs`).
//!
//! Split of ownership, deliberately asymmetric:
//! - `locked` is display-only here. The authoritative value, its daemon
//!   enforcement, and the Send button that actually reads it all live
//!   on `AccountTab` — this row only relays a click up to `App`
//!   (`TabStripRowOutput::ToggleLockRequested`) and is told the result
//!   afterward (`TabStripRowMsg::SetLocked`), via
//!   `AccountTabOutput::LockChanged`. Two sources of truth for the same
//!   bool would drift; one authoritative owner plus a mirror doesn't.
//! - `muted` and new-mail detection are fully self-contained here —
//!   nothing else in the app needs to know a tab is muted, so there's
//!   no reason to route it through `AccountTab` at all.

use std::collections::HashMap;
use std::time::Duration;

use candor_core::config::TabColor;
use candor_core::store;
use relm4::factory::{DynamicIndex, FactoryComponent, FactorySender};
use relm4::gtk;
use relm4::gtk::gio;
use relm4::gtk::prelude::*;

/// How often this row's own background timer re-checks unread counts
/// for the new-mail pulse — same cadence as `AccountTab`'s periodic
/// `Msg::Refresh`, so neither one is the laggard.
const NEW_MAIL_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The GAction a system notification's click routes through — see
/// `check_new_mail`'s notification-firing branch and `App`'s own
/// registration of this same name in `main.rs`. Declared once here so
/// the two sides can't drift out of sync with each other by typo.
/// `NOTIFICATION_ACTION` is the bare name `App` registers the
/// `gio::SimpleAction` under; `NOTIFICATION_ACTION_DETAILED` is the
/// `app.`-prefixed detailed-action-name form `gio::Notification`
/// itself wants.
pub(crate) const NOTIFICATION_ACTION: &str = "notification-open";
pub(crate) const NOTIFICATION_ACTION_DETAILED: &str = "app.notification-open";

pub struct TabStripRow {
    pub(crate) account_id: String,
    /// `pub(crate)` so `App` can update these directly via its guard
    /// after a Settings-dialog edit (same direct-field-mutation pattern
    /// `AccountTab::sync_keyboard_focus_flags` already uses elsewhere
    /// in this codebase) — pure display data with no side effects of
    /// their own, unlike `locked`/`muted`, so there's no need for a
    /// dedicated message just to change what's shown.
    pub(crate) label: String,
    pub(crate) color: TabColor,
    locked: bool,
    muted: bool,
    has_new_mail: bool,
    /// Whether this is the account Candor opens to on launch — the
    /// *only* account that may ever produce a real OS-level
    /// notification. Every other account's new-mail signal stays
    /// purely this row's own pulse. `pub(crate)` so `App` can find the
    /// default row by
    /// position (`Msg::NotificationClicked`) without a second,
    /// separately-tracked copy of the same fact.
    pub(crate) is_default: bool,
    /// Whether the whole window currently has OS-level focus —
    /// broadcast down from `App`'s own `connect_is_active_notify` on
    /// the real window. Combined with `selected` to decide whether
    /// this tab counts as "currently being looked at" — see
    /// `maybe_clear_notification`.
    window_focused: bool,
    /// Last-observed unread count per folder (every folder except
    /// Drafts/Sent, neither of which means anything as "new mail") —
    /// per-folder rather than one combined total so a real new
    /// arrival's folder/uid can actually be looked up and reported,
    /// not just "something, somewhere, increased."
    last_unread_by_folder: HashMap<String, u32>,
    selected: bool,
}

pub struct TabStripRowInit {
    pub account_id: String,
    pub label: String,
    pub color: TabColor,
    pub locked: bool,
    pub muted: bool,
    pub is_default: bool,
    pub selected: bool,
}

#[derive(Debug, Clone)]
pub enum TabStripRowMsg {
    ToggleMute,
    /// Rolls back an optimistic mute toggle that the daemon call
    /// didn't confirm — see `TabStripRowMsg::ToggleMute`'s handler.
    SetMuted(bool),
    /// Authoritative update from `App`, after `AccountTab` actually
    /// changed the real lock state — see the module doc comment.
    SetLocked(bool),
    SetSelected(bool),
    /// Broadcast from `App` whenever the real window's OS-level focus
    /// changes — see `window_focused`'s doc comment.
    WindowFocus(bool),
    CheckNewMail,
}

#[derive(Debug)]
pub enum TabStripRowOutput {
    Selected(DynamicIndex),
    /// This row's lock icon was clicked — `App` relays this into the
    /// real `AccountTab` as `account_tab::Msg::ToggleLocked`; this row
    /// does not call the daemon itself for this one.
    ToggleLockRequested(DynamicIndex),
}

#[relm4::factory(pub)]
impl FactoryComponent for TabStripRow {
    type Init = TabStripRowInit;
    type Input = TabStripRowMsg;
    type Output = TabStripRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::Box;

    view! {
        root = gtk::Box {
            set_orientation: gtk::Orientation::Horizontal,
            set_spacing: 6,
            add_css_class: "candor-tab-strip-row",
            #[watch]
            set_css_classes: if self.selected {
                &["candor-tab-strip-row", "selected"]
            } else {
                &["candor-tab-strip-row"]
            },

            add_controller = gtk::GestureClick {
                connect_pressed[sender, index] => move |_gesture, _n_press, _x, _y| {
                    let _ = sender.output(TabStripRowOutput::Selected(index.clone()));
                }
            },

            gtk::Box {
                add_css_class: "candor-tab-color-dot",
                add_css_class: tab_color_css_class(self.color),
                set_valign: gtk::Align::Center,
            },

            gtk::Label {
                #[watch]
                set_label: &self.label,
                set_valign: gtk::Align::Center,
                set_ellipsize: gtk::pango::EllipsizeMode::End,
                set_max_width_chars: 20,
            },

            gtk::Button {
                add_css_class: "flat",
                add_css_class: "candor-lock-btn",
                #[watch]
                set_css_classes: if self.locked {
                    &["flat", "candor-lock-btn", "locked"]
                } else {
                    &["flat", "candor-lock-btn", "unlocked"]
                },
                #[watch]
                set_icon_name: if self.locked { "changes-prevent-symbolic" } else { "changes-allow-symbolic" },
                #[watch]
                set_tooltip_text: Some(if self.locked {
                    "Locked — click to unlock before sending"
                } else {
                    "Unlocked — click to lock"
                }),
                connect_clicked[sender, index] => move |_| {
                    let _ = sender.output(TabStripRowOutput::ToggleLockRequested(index.clone()));
                },
            },

            gtk::Button {
                add_css_class: "flat",
                add_css_class: "candor-notify-btn",
                #[watch]
                set_css_classes: &if self.muted {
                    vec!["flat", "candor-notify-btn", "muted"]
                } else if self.has_new_mail {
                    vec!["flat", "candor-notify-btn", "has-mail"]
                } else {
                    vec!["flat", "candor-notify-btn"]
                },
                set_icon_name: "weather-clear-symbolic",
                #[watch]
                set_tooltip_text: Some(if self.muted {
                    "Muted — click to unmute"
                } else if self.has_new_mail {
                    "New mail — click to mute this tab"
                } else {
                    "No new mail — click to mute this tab"
                }),
                connect_clicked => TabStripRowMsg::ToggleMute,
            },
        }
    }

    fn init_model(init: Self::Init, _index: &DynamicIndex, sender: FactorySender<Self>) -> Self {
        let input_sender = sender.input_sender().clone();
        gtk::glib::timeout_add_local(NEW_MAIL_POLL_INTERVAL, move || {
            let _ = input_sender.send(TabStripRowMsg::CheckNewMail);
            gtk::glib::ControlFlow::Continue
        });

        Self {
            account_id: init.account_id,
            label: init.label,
            color: init.color,
            locked: init.locked,
            muted: init.muted,
            has_new_mail: false,
            is_default: init.is_default,
            window_focused: true,
            last_unread_by_folder: HashMap::new(),
            selected: init.selected,
        }
    }

    fn update(&mut self, msg: Self::Input, sender: FactorySender<Self>) {
        match msg {
            TabStripRowMsg::ToggleMute => {
                let target = !self.muted;
                self.muted = target;
                if target {
                    self.has_new_mail = false;
                }
                let account_id = self.account_id.clone();
                // Self-contained — see the module doc comment for why
                // mute doesn't round-trip through `App`/`AccountTab`
                // the way lock does. Optimistic, like `AccountTab`'s
                // own `toggle_locked`; rolled back on failure.
                relm4::spawn_local(async move {
                    let result = async {
                        let conn = zbus::Connection::session().await?;
                        let proxy = crate::dbus::DaemonProxy::new(&conn).await?;
                        proxy.set_account_muted(&account_id, target).await
                    }
                    .await;
                    if !matches!(result, Ok(true)) {
                        let _ = sender.input_sender().send(TabStripRowMsg::SetMuted(!target));
                    }
                });
            }
            TabStripRowMsg::SetMuted(muted) => self.muted = muted,
            TabStripRowMsg::SetLocked(locked) => self.locked = locked,
            TabStripRowMsg::SetSelected(selected) => {
                self.selected = selected;
                self.maybe_clear_notification();
            }
            TabStripRowMsg::WindowFocus(focused) => {
                self.window_focused = focused;
                self.maybe_clear_notification();
            }
            TabStripRowMsg::CheckNewMail => self.check_new_mail(),
        }
    }
}

impl TabStripRow {
    /// Whether the user is, right now, actually looking at this tab —
    /// defined as *(this tab is selected) AND (the window has OS
    /// focus)*, re-evaluated continuously rather than only on a
    /// tab-switch. A tab you switched to while the window itself was
    /// unfocused (you alt-tabbed away mid-switch, say) doesn't count
    /// as viewed until the window actually regains focus too.
    fn currently_viewed(&self) -> bool {
        self.selected && self.window_focused
    }

    /// Called whenever either half of `currently_viewed` changes —
    /// clears the pulse the moment both are true, derived from state
    /// rather than wired into each individual "you might now be
    /// looking at this" interaction (click, Ctrl+Tab, window refocus,
    /// …) separately, per the same memory doc's resolved approach.
    fn maybe_clear_notification(&mut self) {
        if self.currently_viewed() {
            self.has_new_mail = false;
        }
    }

    /// Diffs this account's per-folder unread counts (every folder
    /// except Drafts/Sent, neither of which means anything as "new
    /// mail") against the last check — an increase in any one folder
    /// sets `has_new_mail` (the in-app pulse, cleared only by
    /// `maybe_clear_notification`). A real OS notification is scoped
    /// *tighter* than the pulse: Inbox arrivals only (matching this
    /// project's long-standing promise that a new Junk/Promotions
    /// message shouldn't interrupt you at the OS level just because
    /// it's technically "new" — the pulse still quietly reflects it,
    /// just not a desktop notification), and only when `is_default`
    /// and not already `currently_viewed` — every other tab's signal
    /// stays purely in-app either way.
    fn check_new_mail(&mut self) {
        if self.muted {
            return;
        }
        let Ok(db) = store::open() else { return };
        let Ok(folders) = store::list_folders(&db, &self.account_id) else { return };

        let mut any_arrival = false;
        let mut inbox_arrived = false;
        for folder in &folders {
            if matches!(folder.special_use.as_deref(), Some("\\Drafts") | Some("\\Sent")) {
                continue;
            }
            let previous = self.last_unread_by_folder.insert(folder.name.clone(), folder.unread);
            if previous.is_some_and(|p| folder.unread > p) {
                any_arrival = true;
                // IMAP reserves "INBOX" (case-insensitively) as the
                // one mailbox name every server must have — the same
                // check `folder_display`/`sync::INBOX` already use,
                // not a SPECIAL-USE tag (RFC 6154 doesn't define one
                // for Inbox at all, only for Drafts/Sent/Junk/etc).
                if folder.name.eq_ignore_ascii_case("INBOX") {
                    inbox_arrived = true;
                }
            }
        }

        if !any_arrival {
            return;
        }
        self.has_new_mail = true;

        if !inbox_arrived || !self.is_default || self.currently_viewed() {
            return;
        }

        // Newest few, not just the newest one outright — the newest
        // message overall could already be read (seen elsewhere, or
        // simply not the one that just arrived); the first unseen one
        // among the most recent is a much better guess at what the
        // user actually hasn't looked at yet.
        let Ok(messages) = store::list_messages(&db, &self.account_id, "INBOX", 10) else { return };
        let Some(message) = messages.iter().find(|m| !m.seen).or_else(|| messages.first()) else {
            return;
        };
        self.notify_new_mail("INBOX", message);
    }

    /// Builds and sends the real OS notification — only ever reached
    /// for the default account, and only once per detected arrival
    /// (called from `check_new_mail`'s one-shot increase branch, not
    /// on every poll tick while `has_new_mail` stays true), so an
    /// unviewed tab doesn't re-notify every `NEW_MAIL_POLL_INTERVAL`.
    /// Replaces (not stacks) any notification already showing for this
    /// account — one summarized slot per account, same convention most
    /// mail clients use rather than piling up one per message.
    fn notify_new_mail(&self, folder: &str, message: &store::MessageSummary) {
        let title = message
            .from_name
            .clone()
            .filter(|n| !n.is_empty())
            .or_else(|| message.from_address.clone())
            .unwrap_or_else(|| "New mail".to_string());
        let body = message.subject.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "(no subject)".to_string());

        let notification = gio::Notification::new(&title);
        notification.set_body(Some(&body));
        notification.set_default_action_and_target_value(
            NOTIFICATION_ACTION_DETAILED,
            Some(&(folder.to_string(), message.uid).to_variant()),
        );

        relm4::main_application().send_notification(Some(&self.account_id), &notification);
    }
}

/// `TabColor` is `candor_core`'s, not ours — a free function here
/// instead of an inherent impl (Rust's orphan rule won't allow the
/// latter for a foreign type from a foreign crate).
pub(crate) fn tab_color_css_class(color: TabColor) -> &'static str {
    match color {
        TabColor::Blue => "candor-color-blue",
        TabColor::Green => "candor-color-green",
        TabColor::Purple => "candor-color-purple",
        TabColor::Orange => "candor-color-orange",
        TabColor::Red => "candor-color-red",
        TabColor::Teal => "candor-color-teal",
        TabColor::Pink => "candor-color-pink",
        TabColor::Yellow => "candor-color-yellow",
    }
}
