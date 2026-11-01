mod account_tab;
mod body_view;
mod dbus;
mod folder_display;
mod folder_row;
mod message_row;
mod richtext;
mod settings_dialog;
mod snoozed_row;
mod tab_strip_row;
mod theme;

use candor_core::config::{self, TabColor};
use relm4::adw;
use relm4::adw::prelude::*;
use relm4::component::{AsyncComponent, AsyncComponentParts, AsyncComponentSender};
use relm4::factory::{AsyncFactoryVecDeque, DynamicIndex, FactoryVecDeque};
use relm4::gtk::{gio, glib};
use relm4::prelude::*;
use zeroize::Zeroizing;

use account_tab::{AccountTab, AccountTabInit, AccountTabOutput};
use dbus::DaemonProxy;
use tab_strip_row::{TabStripRow, TabStripRowInit, TabStripRowOutput, NOTIFICATION_ACTION};

/// Top-level shell: the real window, the account-setup ("Add account")
/// flow for when there's no tab to put it in yet, and the `AdwTabView`/
/// `AdwTabBar` hosting one real `AccountTab` component per configured
/// account. Almost everything else that used to live here from an
/// earlier single-account design — folders, messages, reading,
/// compose, search, keyboard nav, contacts — moved wholesale into
/// `AccountTab` itself; this struct only owns what's genuinely above a
/// single account: the window, the tab collection, and the setup form.
struct App {
    display_name: String,
    email: String,
    username: String,
    password: Zeroizing<String>,
    status: String,
    submitting: bool,
    needs_manual: bool,
    manual: ManualSettings,
    /// Manual override for `is_microsoft_domain`'s automatic guess —
    /// needed for a Microsoft 365 account on a custom domain (a school
    /// or workplace address that isn't literally @outlook.com/
    /// @hotmail.com/etc. but still only accepts OAuth2 sign-in). The
    /// domain alone can't tell us that; this lets the user say so.
    force_microsoft: bool,
    /// The Add Account form's own entry widgets, kept as persistent
    /// fields rather than declared inline in the view, so they can be
    /// cleared imperatively (`reset_add_account_form`) without a
    /// `#[watch]` binding on the same widget a `connect_changed`
    /// handler also writes to — that combination is a known infinite
    /// feedback loop in this codebase: `gtk_editable_set_text` fires
    /// `changed` even on a programmatic set, which would echo right
    /// back into `set_text` again forever. Same pattern already used
    /// for `AccountTab`'s `compose_to_entry` etc.
    name_entry: adw::EntryRow,
    email_entry: adw::EntryRow,
    username_entry: adw::EntryRow,
    password_entry: adw::PasswordEntryRow,
    force_microsoft_switch: adw::SwitchRow,
    tabs: AsyncFactoryVecDeque<AccountTab>,
    /// The bespoke tab strip that replaces `AdwTabBar` — see
    /// `tab_strip_row.rs`'s own module doc comment for why a custom
    /// widget was needed instead of the stock one.
    /// Kept in lockstep with `tabs`: every push/remove happens to both,
    /// at the same position, in the same `update()` call, so index
    /// parity always holds between them.
    strip: FactoryVecDeque<TabStripRow>,
    /// Whether the "Add account" form is showing even though at least
    /// one tab already exists — the tab bar's "+" button's toggle.
    /// Always true when there are zero tabs (nothing else to show).
    show_add_account_form: bool,
    /// The one real app-level copy of `AppSettings` — previously each
    /// `AccountTab` held (and independently persisted) its own copy,
    /// reached through a Settings menu duplicated identically on every
    /// tab. Owned here instead now, edited through one consolidated
    /// Settings dialog, and broadcast to every tab whenever it changes
    /// (`account_tab::Msg::SetSettings`) so an already-running tab's
    /// behavior (signature, retention, …) updates immediately rather
    /// than only on next restart.
    settings: config::AppSettings,
    /// A standalone clone of the input channel - needed by the
    /// Settings dialog's per-row click closures, which aren't passed a
    /// `sender` the way `view!`-declared widgets are. Same reasoning
    /// as `AccountTab`'s own former copy of this.
    input_sender: relm4::Sender<Msg>,
}

#[derive(Debug, Default, Clone)]
struct ManualSettings {
    imap_host: String,
    imap_port: String,
    imap_implicit_tls: bool,
    smtp_host: String,
    smtp_port: String,
    smtp_implicit_tls: bool,
}

#[derive(Debug)]
enum Msg {
    DisplayName(String),
    Email(String),
    Username(String),
    Password(String),
    ManualImapHost(String),
    ManualImapPort(String),
    ManualImapImplicitTls(bool),
    ManualSmtpHost(String),
    ManualSmtpPort(String),
    ManualSmtpImplicitTls(bool),
    ForceMicrosoft(bool),
    Submit,
    /// Starts the interactive Microsoft OAuth2 sign-in (opens the
    /// system browser, waits for the redirect) and, on success, submits
    /// the resulting token the same way `Submit` submits a password —
    /// see `App::sign_in_with_microsoft`.
    SignInWithMicrosoft,
    ShowAddAccountForm,
    HideAddAccountForm,
    /// An `AccountTab` finished removing its own account from the
    /// daemon and is telling us to drop its tab — see
    /// `AccountTabOutput::Removed`.
    AccountRemoved(String),
    /// Sent by the `AdwBreakpoint` set up in `init` whenever the window
    /// crosses the wide/narrow threshold — broadcast to every tab
    /// (`AsyncFactoryVecDeque::broadcast`), not just the visible one,
    /// so an inactive tab's layout is already correct the moment it's
    /// switched to.
    SetWideLayout(bool),
    /// A tab-strip row was clicked — switches the real `AdwTabView`
    /// page and updates every row's own `selected` highlight.
    TabSelected(DynamicIndex),
    /// A tab-strip row's lock icon was clicked — relayed into the real
    /// `AccountTab` at the same position, which owns the actual toggle
    /// (see `tab_strip_row`'s module doc comment for why).
    RequestToggleLock(DynamicIndex),
    /// An `AccountTab`'s lock state actually changed — relayed back
    /// down into the matching strip row so its icon stays accurate.
    SyncStripLocked(String, bool),
    /// The real window's OS-level focus changed — broadcast to every
    /// strip row (see `tab_strip_row`'s `window_focused` doc comment).
    WindowFocusChanged(bool),
    /// The default tab's system notification was clicked — brings the
    /// window and that tab into focus and flashes the triggering
    /// message in its list, without opening or marking it read (unless
    /// `AppSettings::mark_read_on_notification_click` says otherwise).
    /// Can only ever name the default account's own folder/uid, since
    /// only that account's tab can ever produce the notification this
    /// responds to.
    NotificationClicked(String, u32),
    /// Opens the one consolidated app-level Settings dialog — see
    /// `settings_dialog` for why this replaced a Preferences menu
    /// duplicated identically on every tab.
    OpenSettings,
    SetBulkThreshold(usize),
    SetSignature(String),
    SetRetentionDays(u32),
    SetRetentionMaxMb(u32),
    SetIdleTimeoutMinutes(u32),
    SetReadingCacheMaxMb(u32),
    SetMarkReadOnNotificationClick(bool),
    /// One account's color/short-name changed from the Settings
    /// dialog's per-account row — written straight to `accounts.toml`
    /// from here (no daemon round trip; see `settings_dialog`'s own
    /// doc comment for why these specific fields don't need one), then
    /// mirrored into the matching strip row directly.
    SetAccountColor(String, TabColor),
    SetAccountShortName(String, String),
    /// Exactly one account may be default at a time — clears every
    /// other account's flag, not just sets this one's.
    SetAccountDefault(String),
    /// Swaps this account with its neighbor — explicit, one step at a
    /// time, never a live drag: reordering live risks silently swapping
    /// which account is which mid-use, which defeats the whole point of
    /// a fixed position giving instant recognition at a glance.
    MoveAccountUp(String),
    MoveAccountDown(String),
    /// Relayed to whichever tab owns this account — see
    /// `account_tab::Msg::ImportContactsCsv`'s doc comment.
    ImportContactsCsvFor(String),
    /// Relayed to whichever tab owns this account — see
    /// `account_tab::Msg::RemoveAccount`.
    RemoveAccountRequest(String),
}

#[relm4::component(async)]
impl AsyncComponent for App {
    type Init = ();
    type Input = Msg;
    type Output = ();
    type CommandOutput = ();

    view! {
        adw::ApplicationWindow {
            set_default_width: 760,
            set_default_height: 540,

            #[wrap(Some)]
            set_content = &gtk::Box {
                set_orientation: gtk::Orientation::Vertical,

                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    add_css_class: "candor-tab-strip",
                    #[watch]
                    set_visible: !model.tabs.is_empty() && !model.show_add_account_form,

                    #[local_ref]
                    strip_box -> gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_hexpand: true,
                    },
                    gtk::Button {
                        set_icon_name: "list-add-symbolic",
                        set_tooltip_text: Some("Add account"),
                        add_css_class: "flat",
                        connect_clicked => Msg::ShowAddAccountForm,
                    },
                    gtk::Button {
                        set_icon_name: "emblem-system-symbolic",
                        set_tooltip_text: Some("Settings"),
                        add_css_class: "flat",
                        connect_clicked => Msg::OpenSettings,
                    },
                },

                #[local_ref]
                tab_view -> adw::TabView {
                    set_vexpand: true,
                    #[watch]
                    set_visible: !model.tabs.is_empty() && !model.show_add_account_form,
                    // Tabs are accounts — there's no "close" for one,
                    // only "remove the account" (Settings → Remove
                    // Account, inside that tab). Closing a tab the way
                    // a browser tab closes would just hide the account,
                    // which defeats the entire point of keeping
                    // separate accounts separate instead of one combined
                    // inbox — an account you've hidden but not removed
                    // would still sync in the background with no way to
                    // see it doing so.
                    connect_close_page => |_, _| {
                        gtk::glib::signal::Propagation::Stop
                    }
                },

                // --- add-account form: shown on first run (no tabs
                // yet), or after clicking the tab bar's "+" button ---
                adw::ToolbarView {
                    set_vexpand: true,
                    #[watch]
                    set_visible: model.tabs.is_empty() || model.show_add_account_form,

                    add_top_bar = &adw::HeaderBar {
                        #[wrap(Some)]
                        set_title_widget = &adw::WindowTitle {
                            set_title: "Add account",
                        },
                        pack_start = &gtk::Button {
                            set_icon_name: "go-previous-symbolic",
                            set_tooltip_text: Some("Back"),
                            // Nothing to go "back" to on first run —
                            // only offered once at least one tab
                            // already exists.
                            #[watch]
                            set_visible: !model.tabs.is_empty(),
                            connect_clicked => Msg::HideAddAccountForm,
                        },
                    },

                    #[wrap(Some)]
                    set_content = &gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 12,
                        set_margin_all: 16,

                        adw::PreferencesGroup {
                            set_title: "Add account",

                            #[local_ref]
                            name_entry -> adw::EntryRow {
                                set_title: "Your name",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::DisplayName(entry.text().to_string()));
                                },
                            },
                            #[local_ref]
                            email_entry -> adw::EntryRow {
                                set_title: "Email address",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::Email(entry.text().to_string()));
                                },
                            },
                            #[local_ref]
                            username_entry -> adw::EntryRow {
                                set_title: "Username (if different from email)",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::Username(entry.text().to_string()));
                                },
                            },
                            #[local_ref]
                            force_microsoft_switch -> adw::SwitchRow {
                                set_title: "This is a Microsoft 365 account on another domain",
                                set_subtitle: "Turn on for a school or work address that only \
                                    goes through Microsoft to sign in, even though it isn't \
                                    @outlook.com — Candor can't tell that from the address alone.",
                                connect_active_notify[sender] => move |row| {
                                    sender.input(Msg::ForceMicrosoft(row.is_active()));
                                },
                            },
                            #[local_ref]
                            password_entry -> adw::PasswordEntryRow {
                                set_title: "Password",
                                #[watch]
                                set_visible: !is_microsoft_domain(&model.email) && !model.force_microsoft,
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::Password(entry.text().to_string()));
                                },
                            },
                            adw::ActionRow {
                                set_title: "Microsoft accounts no longer accept a password here",
                                set_subtitle: "Outlook.com and Microsoft 365 require signing in \
                                    through Microsoft directly.",
                                #[watch]
                                set_visible: is_microsoft_domain(&model.email) || model.force_microsoft,

                                add_suffix = &gtk::Button {
                                    set_label: "Sign in with Microsoft",
                                    add_css_class: "suggested-action",
                                    set_valign: gtk::Align::Center,
                                    #[watch]
                                    set_sensitive: !model.submitting,
                                    connect_clicked => Msg::SignInWithMicrosoft,
                                },
                            },
                        },

                        adw::PreferencesGroup {
                            set_title: "Manual server settings",
                            set_description: Some("We couldn't find this provider's settings automatically."),

                            #[watch]
                            set_visible: model.needs_manual,

                            adw::EntryRow {
                                set_title: "IMAP host",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::ManualImapHost(entry.text().to_string()));
                                },
                            },
                            adw::EntryRow {
                                set_title: "IMAP port",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::ManualImapPort(entry.text().to_string()));
                                },
                            },
                            adw::SwitchRow {
                                set_title: "IMAP uses implicit TLS",
                                set_subtitle: "Off = STARTTLS",
                                set_active: true,
                                connect_active_notify[sender] => move |row| {
                                    sender.input(Msg::ManualImapImplicitTls(row.is_active()));
                                },
                            },
                            adw::EntryRow {
                                set_title: "SMTP host",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::ManualSmtpHost(entry.text().to_string()));
                                },
                            },
                            adw::EntryRow {
                                set_title: "SMTP port",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::ManualSmtpPort(entry.text().to_string()));
                                },
                            },
                            adw::SwitchRow {
                                set_title: "SMTP uses implicit TLS",
                                set_subtitle: "Off = STARTTLS",
                                set_active: false,
                                connect_active_notify[sender] => move |row| {
                                    sender.input(Msg::ManualSmtpImplicitTls(row.is_active()));
                                },
                            },
                        },

                        gtk::Button {
                            set_label: "Add account",
                            add_css_class: "suggested-action",
                            set_halign: gtk::Align::Start,
                            #[watch]
                            set_visible: !is_microsoft_domain(&model.email) && !model.force_microsoft,
                            #[watch]
                            set_sensitive: !model.submitting,
                            connect_clicked => Msg::Submit,
                        },

                        gtk::Label {
                            #[watch]
                            set_label: &model.status,
                            set_halign: gtk::Align::Start,
                            set_wrap: true,
                            add_css_class: "dim-label",
                        },
                    },
                },
            },
        }
    }

    async fn init(
        _init: Self::Init,
        root: Self::Root,
        sender: AsyncComponentSender<Self>,
    ) -> AsyncComponentParts<Self> {
        let startup = list_accounts_startup().await;

        let mut tabs = AsyncFactoryVecDeque::builder().launch(adw::TabView::new()).forward(
            sender.input_sender(),
            |output| match output {
                AccountTabOutput::Removed(id) => Msg::AccountRemoved(id),
                AccountTabOutput::LockChanged(id, locked) => Msg::SyncStripLocked(id, locked),
            },
        );
        let mut strip = FactoryVecDeque::builder().launch_default().forward(
            sender.input_sender(),
            |output| match output {
                TabStripRowOutput::Selected(index) => Msg::TabSelected(index),
                TabStripRowOutput::ToggleLockRequested(index) => Msg::RequestToggleLock(index),
            },
        );
        {
            let mut tabs_guard = tabs.guard();
            let mut strip_guard = strip.guard();
            for (i, account) in startup.accounts.iter().enumerate() {
                tabs_guard
                    .push_back(AccountTabInit { account_id: account.id.clone(), window: root.clone() });
                strip_guard.push_back(TabStripRowInit {
                    account_id: account.id.clone(),
                    label: account.label.clone(),
                    color: account.color,
                    locked: account.locked,
                    muted: account.muted,
                    is_default: account.is_default,
                    // The first tab is whichever one `AdwTabView` shows
                    // by default (the first page appended) — match the
                    // strip's own highlight to that from the start.
                    selected: i == 0,
                });
            }
        }

        let model = App {
            display_name: String::new(),
            email: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            status: startup.note.unwrap_or_default(),
            submitting: false,
            needs_manual: false,
            manual: ManualSettings::default(),
            force_microsoft: false,
            name_entry: adw::EntryRow::new(),
            email_entry: adw::EntryRow::new(),
            username_entry: adw::EntryRow::new(),
            password_entry: adw::PasswordEntryRow::new(),
            force_microsoft_switch: adw::SwitchRow::new(),
            tabs,
            strip,
            show_add_account_form: false,
            settings: config::load().map(|cfg| cfg.settings).unwrap_or_default(),
            input_sender: sender.input_sender().clone(),
        };

        let tab_view = model.tabs.widget();
        let strip_box = model.strip.widget();
        let name_entry = model.name_entry.clone();
        let email_entry = model.email_entry.clone();
        let username_entry = model.username_entry.clone();
        let password_entry = model.password_entry.clone();
        let force_microsoft_switch = model.force_microsoft_switch.clone();
        let widgets = view_output!();

        // Drives `Msg::SetWideLayout`, broadcast to every tab (see its
        // own doc comment) — same breakpoint/threshold/one-time-startup-
        // read mechanism the single-account `AppModel` used to run
        // itself, just living at the window level now that there can be
        // more than one tab sharing this one window.
        let condition = adw::BreakpointCondition::parse("max-width: 1150sp")
            .expect("valid breakpoint condition");
        let breakpoint = adw::Breakpoint::new(condition);
        let narrow_sender = sender.input_sender().clone();
        breakpoint.connect_apply(move |_| {
            let _ = narrow_sender.send(Msg::SetWideLayout(false));
        });
        let wide_sender = sender.input_sender().clone();
        breakpoint.connect_unapply(move |_| {
            let _ = wide_sender.send(Msg::SetWideLayout(true));
        });
        root.add_breakpoint(breakpoint);

        let startup_sync_sender = sender.input_sender().clone();
        let startup_sync_root = root.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(300), move || {
            let _ = startup_sync_sender.send(Msg::SetWideLayout(startup_sync_root.width() >= 1150));
        });

        // Broadcast to every strip row — see `tab_strip_row`'s own doc
        // comment on `window_focused` for why this, combined with
        // which tab is selected, is what actually decides whether a
        // tab counts as "currently being looked at" (not just which
        // one is selected on its own).
        let focus_sender = sender.input_sender().clone();
        root.connect_is_active_notify(move |window| {
            let _ = focus_sender.send(Msg::WindowFocusChanged(window.is_active()));
        });

        // The GAction a system notification's click routes through —
        // registered once, here, regardless of whether any account is
        // even eligible to produce one yet. See `tab_strip_row`'s
        // `notify_new_mail` for where this gets built and sent, and
        // `NOTIFICATION_ACTION`'s own doc comment for the bare-name/
        // detailed-name split.
        let notification_action = gio::SimpleAction::new(
            NOTIFICATION_ACTION,
            Some(glib::VariantTy::new("(su)").expect("valid variant type")),
        );
        let notification_sender = sender.input_sender().clone();
        notification_action.connect_activate(move |_action, parameter| {
            let Some(parameter) = parameter else { return };
            let Some((folder, uid)) = parameter.get::<(String, u32)>() else { return };
            let _ = notification_sender.send(Msg::NotificationClicked(folder, uid));
        });
        relm4::main_application().add_action(&notification_action);

        AsyncComponentParts { model, widgets }
    }

    async fn update(&mut self, msg: Self::Input, _sender: AsyncComponentSender<Self>, root: &Self::Root) {
        match msg {
            Msg::DisplayName(v) => self.display_name = v,
            Msg::Email(v) => self.email = v,
            Msg::Username(v) => self.username = v,
            // Reassigning (not `.clear()`) is what matters here —
            // dropping the old `Zeroizing<String>` actually overwrites
            // its bytes before freeing them, which `String::clear()`
            // alone would not do (it only resets the length).
            Msg::Password(v) => self.password = Zeroizing::new(v),
            Msg::ManualImapHost(v) => self.manual.imap_host = v,
            Msg::ManualImapPort(v) => self.manual.imap_port = v,
            Msg::ManualImapImplicitTls(v) => self.manual.imap_implicit_tls = v,
            Msg::ManualSmtpHost(v) => self.manual.smtp_host = v,
            Msg::ManualSmtpPort(v) => self.manual.smtp_port = v,
            Msg::ManualSmtpImplicitTls(v) => self.manual.smtp_implicit_tls = v,
            Msg::ForceMicrosoft(v) => self.force_microsoft = v,
            Msg::Submit => self.submit(root).await,
            Msg::SignInWithMicrosoft => self.sign_in_with_microsoft(root).await,
            Msg::ShowAddAccountForm => self.show_add_account_form = true,
            Msg::HideAddAccountForm => self.reset_add_account_form(),
            Msg::AccountRemoved(id) => {
                let index = self.tabs.iter().position(|tab| tab.is_some_and(|tab| tab.account_id == id));
                if let Some(index) = index {
                    self.tabs.guard().remove(index);
                    self.strip.guard().remove(index);
                }
            }
            Msg::SetWideLayout(v) => self.tabs.broadcast(account_tab::Msg::SetWideLayout(v)),
            Msg::TabSelected(index) => self.select_tab(index.current_index()),
            Msg::RequestToggleLock(index) => {
                let position = index.current_index();
                self.tabs.send(position, account_tab::Msg::ToggleLocked);
            }
            Msg::SyncStripLocked(id, locked) => {
                let index = self.strip.iter().position(|row| row.account_id == id);
                if let Some(index) = index {
                    self.strip.send(index, tab_strip_row::TabStripRowMsg::SetLocked(locked));
                }
            }
            Msg::WindowFocusChanged(focused) => {
                self.strip.broadcast(tab_strip_row::TabStripRowMsg::WindowFocus(focused));
            }
            Msg::NotificationClicked(folder, uid) => {
                root.present();
                // Can only ever be the default account — see
                // `Msg::NotificationClicked`'s own doc comment — so
                // finding it by `is_default` rather than threading an
                // id through the notification's own payload is enough.
                let default_index = self.strip.iter().position(|row| row.is_default);
                if let Some(index) = default_index {
                    self.select_tab(index);
                    self.tabs.send(index, account_tab::Msg::FocusMessage(folder, uid));
                }
            }
            Msg::OpenSettings => self.open_settings(root),
            Msg::SetBulkThreshold(v) => {
                self.settings.bulk_select_threshold = v;
                self.persist_settings();
            }
            Msg::SetSignature(v) => {
                self.settings.signature = v;
                self.persist_settings();
            }
            Msg::SetRetentionDays(v) => {
                self.settings.body_cache_max_age_days = (v > 0).then_some(v);
                self.persist_settings();
            }
            Msg::SetRetentionMaxMb(v) => {
                self.settings.body_cache_max_bytes = (v > 0).then_some(v as u64 * 1_000_000);
                self.persist_settings();
            }
            Msg::SetIdleTimeoutMinutes(v) => {
                self.settings.idle_timeout_minutes = (v > 0).then_some(v);
                self.persist_settings();
            }
            Msg::SetReadingCacheMaxMb(v) => {
                self.settings.reading_cache_max_bytes = (v > 0).then_some(v as u64 * 1_000_000);
                self.persist_settings();
            }
            Msg::SetMarkReadOnNotificationClick(v) => {
                self.settings.mark_read_on_notification_click = v;
                self.persist_settings();
            }
            Msg::SetAccountColor(id, color) => {
                mutate_account_config(&id, |acc| acc.color = color);
                let index = self.strip.iter().position(|row| row.account_id == id);
                if let Some(index) = index {
                    if let Some(row) = self.strip.guard().get_mut(index) {
                        row.color = color;
                    }
                }
            }
            Msg::SetAccountShortName(id, short_name) => {
                mutate_account_config(&id, |acc| acc.short_name = short_name.clone());
                let index = self.strip.iter().position(|row| row.account_id == id);
                if let Some(index) = index {
                    // Same fallback the strip was originally populated
                    // with (short_name, else email) — see
                    // `StartupAccount`'s own doc comment for why it's
                    // email, not `display_name`.
                    let email = config::load()
                        .ok()
                        .and_then(|cfg| cfg.accounts.into_iter().find(|a| a.id == id))
                        .map(|a| a.email);
                    if let Some(row) = self.strip.guard().get_mut(index) {
                        row.label = if short_name.is_empty() {
                            email.unwrap_or_default()
                        } else {
                            short_name
                        };
                    }
                }
            }
            Msg::SetAccountDefault(id) => {
                let _ = config::load().and_then(|mut cfg| {
                    for acc in cfg.accounts.iter_mut() {
                        acc.is_default = acc.id == id;
                    }
                    config::save(&cfg)
                });
                let mut guard = self.strip.guard();
                for i in 0..guard.len() {
                    if let Some(row) = guard.get_mut(i) {
                        row.is_default = row.account_id == id;
                    }
                }
            }
            Msg::MoveAccountUp(id) => self.move_account(&id, -1),
            Msg::MoveAccountDown(id) => self.move_account(&id, 1),
            Msg::ImportContactsCsvFor(id) => {
                let index = self.tabs.iter().position(|tab| tab.is_some_and(|tab| tab.account_id == id));
                if let Some(index) = index {
                    self.tabs.send(index, account_tab::Msg::ImportContactsCsv);
                }
            }
            Msg::RemoveAccountRequest(id) => {
                let index = self.tabs.iter().position(|tab| tab.is_some_and(|tab| tab.account_id == id));
                if let Some(index) = index {
                    self.tabs.send(index, account_tab::Msg::RemoveAccount);
                }
            }
        }
    }
}

impl App {
    /// Switches which `AdwTabView` page is visible and updates every
    /// strip row's own `selected` highlight to match — shared by a
    /// direct strip click (`Msg::TabSelected`) and landing on the
    /// default tab from a notification click (`Msg::NotificationClicked`),
    /// so both go through the exact same switching logic.
    fn select_tab(&mut self, position: usize) {
        let page = self.tabs.widget().nth_page(position as i32);
        self.tabs.widget().set_selected_page(&page);
        for i in 0..self.strip.len() {
            self.strip.send(i, tab_strip_row::TabStripRowMsg::SetSelected(i == position));
        }
    }

    /// Re-reads `accounts.toml`, merges in the latest in-memory
    /// settings, and writes it back — same re-read-immediately-before-
    /// writing reasoning `AccountTab`'s own version of this used to
    /// have (small window for clobbering a daemon-side account change),
    /// now living here since settings themselves do too. Broadcasts
    /// the result to every tab afterward so an already-running one
    /// reflects the change immediately — see `App::settings`'s doc
    /// comment.
    fn persist_settings(&mut self) {
        let result = config::load().and_then(|mut cfg| {
            cfg.settings = self.settings.clone();
            config::save(&cfg)
        });
        if result.is_ok() {
            self.tabs.broadcast(account_tab::Msg::SetSettings(self.settings.clone()));
        }
    }

    /// Swaps this account with its neighbor one position over — never
    /// a live drag, explicit and one step at a time. Swaps the actual
    /// `AccountTab`/`TabStripRow` instances (not just their displayed
    /// data), so whichever one was selected or mid-compose stays
    /// attached to itself, not to a screen position. The strip's own
    /// post-swap ordering becomes the new authoritative `tab_order`
    /// list — no separately-tracked copy needed, since it's already
    /// exactly the order to persist.
    fn move_account(&mut self, id: &str, delta: i32) {
        let Some(index) = self.strip.iter().position(|row| row.account_id == id) else { return };
        let len = self.strip.len();
        let target = index as i32 + delta;
        if target < 0 || target as usize >= len {
            return;
        }
        let target = target as usize;
        self.tabs.guard().swap(index, target);
        self.strip.guard().swap(index, target);

        let order: Vec<String> = self.strip.iter().map(|row| row.account_id.clone()).collect();
        let _ = config::load().and_then(|mut cfg| {
            for acc in cfg.accounts.iter_mut() {
                if let Some(position) = order.iter().position(|id| *id == acc.id) {
                    acc.tab_order = position as u32;
                }
            }
            config::save(&cfg)
        });
    }

    /// Builds and shows the one consolidated Settings dialog — see
    /// `settings_dialog` for its contents. Reads the account list
    /// straight from `accounts.toml` (a local file read, same as
    /// `persist_settings`) rather than over D-Bus, consistent with
    /// treating `color`/`short_name`/`tab_order`/`is_default` as
    /// GUI-direct-write fields, same as `AppSettings` itself.
    fn open_settings(&mut self, root: &adw::ApplicationWindow) {
        let accounts = config::load().map(|cfg| cfg.accounts).unwrap_or_default();
        let dialog = settings_dialog::build(self.settings.clone(), accounts, self.input_sender.clone());
        dialog.present(Some(root));
    }
}

/// Edits one account's config in place and writes it back — the
/// shared shape every per-account Settings field (color, short name)
/// uses. A local file write failing isn't a scenario worth building
/// error-recovery UI for, so this just quietly no-ops on failure
/// rather than returning a `Result` every caller would discard anyway.
fn mutate_account_config(id: &str, f: impl FnOnce(&mut config::AccountConfig)) {
    let Ok(mut cfg) = config::load() else { return };
    if let Some(acc) = cfg.accounts.iter_mut().find(|a| a.id == id) {
        f(acc);
    }
    let _ = config::save(&cfg);
}

/// Whether this email's domain is one Microsoft has moved (or is
/// moving) to OAuth2-only login — see `candor_core::oauth`'s doc
/// comment. Every other provider this app supports still takes a
/// plain or app-specific password, so this check is deliberately
/// Microsoft-only, not a general "does this provider need OAuth2"
/// guess.
fn is_microsoft_domain(email: &str) -> bool {
    let Some(domain) = email.rsplit('@').next() else { return false };
    matches!(
        domain.to_ascii_lowercase().as_str(),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com"
    )
}

impl App {
    async fn sign_in_with_microsoft(&mut self, root: &adw::ApplicationWindow) {
        self.submitting = true;
        self.status = "Opening your browser for Microsoft sign-in…".to_string();

        let token = tokio::task::spawn_blocking(candor_core::oauth::interactive_sign_in).await;

        let token = match token {
            Ok(Ok(token)) => token,
            Ok(Err(e)) => {
                self.submitting = false;
                self.status = format!("Microsoft sign-in failed: {e:#}");
                return;
            }
            Err(e) => {
                self.submitting = false;
                self.status = format!("Microsoft sign-in failed: {e}");
                return;
            }
        };

        self.status = "Signed in — verifying account…".to_string();

        let username = if self.username.trim().is_empty() {
            self.email.clone()
        } else {
            self.username.clone()
        };

        let result = self.call_daemon_oauth(&username, &token).await;
        self.submitting = false;
        self.handle_add_account_result(result, root).await;
    }

    async fn call_daemon_oauth(
        &self,
        username: &str,
        token: &candor_core::oauth::FreshToken,
    ) -> zbus::Result<(bool, String)> {
        let conn = zbus::Connection::session().await?;
        let proxy = DaemonProxy::new(&conn).await?;

        let (
            manual_imap_host,
            manual_imap_port,
            manual_imap_implicit_tls,
            manual_smtp_host,
            manual_smtp_port,
            manual_smtp_implicit_tls,
        ) = if self.needs_manual {
            (
                self.manual.imap_host.as_str(),
                self.manual.imap_port.parse().unwrap_or(993),
                self.manual.imap_implicit_tls,
                self.manual.smtp_host.as_str(),
                self.manual.smtp_port.parse().unwrap_or(587),
                self.manual.smtp_implicit_tls,
            )
        } else {
            ("", 0u16, true, "", 0u16, true)
        };

        proxy
            .add_oauth_account(
                &self.display_name,
                &self.email,
                username,
                &token.access_token,
                &token.refresh_token,
                token.expires_at,
                manual_imap_host,
                manual_imap_port,
                manual_imap_implicit_tls,
                manual_smtp_host,
                manual_smtp_port,
                manual_smtp_implicit_tls,
            )
            .await
    }

    async fn submit(&mut self, root: &adw::ApplicationWindow) {
        self.submitting = true;
        self.status = "Checking…".to_string();

        let username = if self.username.trim().is_empty() {
            self.email.clone()
        } else {
            self.username.clone()
        };

        let result = self.call_daemon(&username).await;
        self.submitting = false;
        self.handle_add_account_result(result, root).await;
    }

    /// Clears every field the Add Account form owns — called on a
    /// successful add, and also whenever the form is left without
    /// finishing (the "+"/back toggle), so nothing typed into it, most
    /// importantly a password, sits around in memory indefinitely once
    /// the user has navigated away from the screen that needed it.
    fn reset_add_account_form(&mut self) {
        self.status = String::new();
        self.needs_manual = false;
        self.display_name.clear();
        self.email.clear();
        self.username.clear();
        // Reassigning, not `.clear()`-ing in place — see `Msg::Password`'s
        // handler for why that distinction actually matters here.
        self.password = Zeroizing::new(String::new());
        self.manual = ManualSettings::default();
        self.force_microsoft = false;
        self.show_add_account_form = false;
        // The model fields above are what actually gets submitted —
        // these imperative calls are the only thing that clears what's
        // *displayed*, since these widgets are deliberately not
        // `#[watch]`-bound to avoid the same-widget set_text/
        // connect_changed feedback loop (see the struct field's doc
        // comment).
        self.name_entry.set_text("");
        self.email_entry.set_text("");
        self.username_entry.set_text("");
        self.password_entry.set_text("");
        self.force_microsoft_switch.set_active(false);
    }

    /// Shared by `submit` (password accounts) and
    /// `sign_in_with_microsoft` (OAuth2 accounts) — both end up with
    /// the same `(added, account_id)` shape from the daemon, and the
    /// same "clear the form and create the tab" or "ask for manual
    /// settings" or "show the error" response to it.
    async fn handle_add_account_result(&mut self, result: zbus::Result<(bool, String)>, root: &adw::ApplicationWindow) {
        match result {
            Ok((true, id)) => {
                self.reset_add_account_form();
                self.tabs.guard().push_back(AccountTabInit { account_id: id.clone(), window: root.clone() });
                // Re-fetch rather than guess the new account's label/
                // color/locked/muted client-side — it's one extra D-Bus
                // round trip, but avoids duplicating `account::add_account`'s
                // own defaulting logic here and drifting from it later.
                let refreshed = list_accounts_startup().await;
                let new_account = refreshed.accounts.into_iter().find(|a| a.id == id);
                if let Some(account) = new_account {
                    self.strip.guard().push_back(TabStripRowInit {
                        account_id: account.id,
                        label: account.label,
                        color: account.color,
                        locked: account.locked,
                        muted: account.muted,
                        is_default: account.is_default,
                        selected: false,
                    });
                }
            }
            Ok((false, _)) => {
                self.needs_manual = true;
                self.status = "Couldn't find this provider's settings automatically — \
                    fill them in above and try again."
                    .to_string();
            }
            Err(e) => {
                self.status = format!("Failed: {e}");
            }
        }
    }

    async fn call_daemon(&self, username: &str) -> zbus::Result<(bool, String)> {
        let conn = zbus::Connection::session().await?;
        let proxy = DaemonProxy::new(&conn).await?;

        let (
            manual_imap_host,
            manual_imap_port,
            manual_imap_implicit_tls,
            manual_smtp_host,
            manual_smtp_port,
            manual_smtp_implicit_tls,
        ) = if self.needs_manual {
            (
                self.manual.imap_host.as_str(),
                self.manual.imap_port.parse().unwrap_or(993),
                self.manual.imap_implicit_tls,
                self.manual.smtp_host.as_str(),
                self.manual.smtp_port.parse().unwrap_or(587),
                self.manual.smtp_implicit_tls,
            )
        } else {
            ("", 0u16, true, "", 0u16, true)
        };

        proxy
            .add_account(
                &self.display_name,
                &self.email,
                username,
                &self.password,
                manual_imap_host,
                manual_imap_port,
                manual_imap_implicit_tls,
                manual_smtp_host,
                manual_smtp_port,
                manual_smtp_implicit_tls,
            )
            .await
    }
}

/// One configured account, as the tab strip needs it — everything
/// `TabStripRowInit` wants, already resolved (label falls back from
/// `short_name` to the account's email — not `display_name`, which is
/// a different concept (the sender name used in outgoing mail, see
/// `send.rs`); `color` parsed from the daemon's `Debug`-formatted
/// string).
struct StartupAccount {
    id: String,
    label: String,
    color: TabColor,
    locked: bool,
    muted: bool,
    is_default: bool,
}

/// Checked once at startup: every configured account, in tab order
/// (`AccountConfig::tab_order`), and an optional note. A `Some` note
/// means the check itself failed (e.g. the daemon isn't running) — distinct from a
/// successful check that simply found no accounts.
struct StartupState {
    accounts: Vec<StartupAccount>,
    note: Option<String>,
}

/// `list_accounts`'s `colors` are `format!("{:?}", TabColor)` on the
/// daemon side (see its own doc comment) — parsed back here rather
/// than given a proper D-Bus enum type, since this is the only caller.
fn parse_tab_color(s: &str) -> TabColor {
    match s {
        "Green" => TabColor::Green,
        "Purple" => TabColor::Purple,
        "Orange" => TabColor::Orange,
        "Red" => TabColor::Red,
        "Teal" => TabColor::Teal,
        "Pink" => TabColor::Pink,
        "Yellow" => TabColor::Yellow,
        _ => TabColor::Blue,
    }
}

async fn list_accounts_startup() -> StartupState {
    let conn = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            return StartupState {
                accounts: Vec::new(),
                note: Some(format!("Could not reach the session bus: {e}")),
            };
        }
    };
    let proxy = match DaemonProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            return StartupState {
                accounts: Vec::new(),
                note: Some(format!("Could not reach candor-daemon: {e}")),
            };
        }
    };
    match proxy.list_accounts().await {
        Ok((ids, emails, _display_names, locked, muted, tab_orders, colors, short_names, is_defaults)) => {
            let mut accounts: Vec<(u32, StartupAccount)> = ids
                .into_iter()
                .enumerate()
                .map(|(i, id)| {
                    // Falls back to the account's email, not its
                    // display name — `display_name` is the sender name
                    // used in outgoing mail (see `send.rs`'s
                    // `build_message`), a different concept from what
                    // to call this tab, and happening to share a value
                    // when both are unset doesn't make them the same
                    // field.
                    let label = short_names
                        .get(i)
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .unwrap_or_else(|| emails.get(i).cloned().unwrap_or_default());
                    (
                        tab_orders.get(i).copied().unwrap_or(0),
                        StartupAccount {
                            id,
                            label,
                            color: colors.get(i).map(|c| parse_tab_color(c)).unwrap_or(TabColor::Blue),
                            locked: locked.get(i).copied().unwrap_or(true),
                            muted: muted.get(i).copied().unwrap_or(false),
                            is_default: is_defaults.get(i).copied().unwrap_or(false),
                        },
                    )
                })
                .collect();
            accounts.sort_by_key(|(order, _)| *order);
            // A config file written before `is_default`
            // existed backfills it to `false` via serde, so it's a real
            // case, not hypothetical, that no account is marked
            // default at all. Documented fallback: the lowest
            // `tab_order` (now `accounts[0]`, already sorted) becomes
            // default instead of leaving every tab without one —
            // without this, nothing would ever be eligible for a real
            // OS notification. Persisted back to `accounts.toml`, not
            // just patched in the in-memory list returned here — the
            // Settings dialog (`App::open_settings`) reads the file
            // directly, so a fallback that only ever lived in memory
            // would quietly disagree with what it shows the moment that
            // screen exists. Self-healing: runs once, the file is
            // consistent on every call after.
            if !accounts.iter().any(|(_, a)| a.is_default) {
                if let Some((_, first)) = accounts.first_mut() {
                    first.is_default = true;
                    let default_id = first.id.clone();
                    let _ = config::load().and_then(|mut cfg| {
                        if let Some(acc) = cfg.accounts.iter_mut().find(|a| a.id == default_id) {
                            acc.is_default = true;
                        }
                        config::save(&cfg)
                    });
                }
            }
            StartupState { accounts: accounts.into_iter().map(|(_, acc)| acc).collect(), note: None }
        }
        Err(e) => StartupState {
            accounts: Vec::new(),
            note: Some(format!("Could not list configured accounts: {e}")),
        },
    }
}

fn main() {
    // Never actually initialized before — every `tracing::*!` call
    // anywhere in code this process runs (including `candor-core`'s,
    // e.g. the OAuth2 flow) was a silent no-op without this, since
    // `tracing` events need a subscriber installed in the process
    // that's actually emitting them, not just somewhere in the
    // dependency graph.
    tracing_subscriber::fmt::init();
    let app = RelmApp::new("dev.candor.gui");
    theme::apply_and_watch();
    app.run_async::<App>(());
}

/// Security regression suite for the GUI crate — see the project's
/// `SECURITY.md` for the methodology.
#[cfg(test)]
mod architecture_regression_tests {
    /// Every `store::` reference the GUI is actually allowed to make —
    /// read-only functions, plus the handful of plain data types it
    /// needs as parameter/field types. Deliberately an allowlist, not
    /// a denylist of known write functions: a *new* write function
    /// added to `candor_core::store` isn't on this list by default, so
    /// if the GUI ever starts calling it, this test fails closed —
    /// whereas checking against a list of known writes would silently
    /// miss any write function added after this test was written.
    const ALLOWED_STORE_REFERENCES: &[&str] = &[
        // Read-only functions actually called from the GUI today.
        "open",
        "list_folders",
        "list_messages",
        "list_snoozed",
        "search_messages",
        "search_contacts",
        // Plain data types, not calls — these show up in the same
        // `store::Name` text shape a function call does, so they have
        // to be allowlisted too, or this test would flag every type
        // import as if it were a write.
        "Contact",
        "MessageSummary",
        "FolderInfo",
        "SnoozedMessage",
    ];

    /// Pulls every `store::<identifier>` occurrence out of a source
    /// file's *code* — `//`-comment text (plain or doc) on each line
    /// is stripped first, specifically because the first real run of
    /// this test found two false positives that were both exactly
    /// that: a doc comment mentioning a function name as prose, not
    /// an actual call. Not a full parse — doesn't know about block
    /// comments or `store::`-shaped text inside a string literal — so
    /// this is a best-effort tripwire, not a guarantee; see the test
    /// below for why that's still worth having.
    fn store_references_in(text: &str) -> Vec<String> {
        let mut found = Vec::new();
        for line in text.lines() {
            let code_part = line.split("//").next().unwrap_or(line);
            let mut rest = code_part;
            while let Some(idx) = rest.find("store::") {
                let after = &rest[idx + "store::".len()..];
                let name: String = after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                let consumed = "store::".len() + name.len();
                if !name.is_empty() {
                    found.push(name);
                }
                rest = &rest[idx + consumed.max(1)..];
            }
        }
        found
    }

    /// Guards the architecture promise in the README's "The
    /// architecture itself limits what can go wrong": the GUI process
    /// never writes to the local database directly — every change
    /// goes through the daemon. Scans every source file in this
    /// crate for `store::` references and fails on anything not on
    /// the explicit read-only allowlist above, naming the exact file
    /// and reference so a real regression is easy to find, not just
    /// "something somewhere called a write function."
    #[test]
    fn gui_source_never_references_a_store_write_function() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();

        for entry in std::fs::read_dir(&src_dir).expect("reading candor-gui/src") {
            let entry = entry.expect("reading dir entry");
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("reading source file");
            for name in store_references_in(&text) {
                if !ALLOWED_STORE_REFERENCES.contains(&name.as_str()) {
                    violations.push(format!("{}: store::{}", path.display(), name));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "candor-gui referenced store:: functionality outside the read-only allowlist:\n{}",
            violations.join("\n")
        );
    }
}
