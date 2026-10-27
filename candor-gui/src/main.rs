mod body_view;
mod dbus;
mod folder_display;
mod folder_row;
mod message_row;
mod richtext;
mod snoozed_row;
mod theme;

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use candor_core::config;
use candor_core::inspect::{AttachmentInfo, LinkWarning, MessageVerdict};
use candor_core::store;
use chrono::TimeZone;
use relm4::adw;
use relm4::adw::prelude::*;
use relm4::component::{AsyncComponent, AsyncComponentParts, AsyncComponentSender};
use relm4::factory::FactoryVecDeque;
use relm4::gtk::{gdk, gio, glib};
use relm4::loading_widgets::LoadingWidgets;
use relm4::prelude::*;
use relm4::view;

use dbus::DaemonProxy;
use folder_row::FolderRow;
use message_row::{MessageRow, MessageRowOutput};
use snoozed_row::{SnoozedRow, SnoozedRowOutput};

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
/// Cap on how many of a folder's messages the list view loads at once.
const MESSAGE_LIST_LIMIT: u32 = 100;

/// Which of the three top-level panes keyboard navigation currently
/// targets — purely a keyboard-cursor concept, independent of what's
/// actually showing on screen (that's still driven by
/// `selected_folder`/`reading`/`wide_layout` as before). Ctrl+1/2/3
/// switches between them; j/k moves within whichever one is current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyboardPane {
    Folders,
    Messages,
    Reading,
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

struct ReadingPane {
    /// Needed (not just at open time) so the archive/delete/mark-unread
    /// actions — triggered later, after the pane is already open — know
    /// which message and folder to act on.
    uid: u32,
    folder: String,
    subject: String,
    from: String,
    /// Display name alongside `from`, if the message had one — used by
    /// the reading pane's opt-in "Add to contacts" button
    /// (`Msg::AddContact`) so a contact added this way gets a name, not
    /// just a bare address.
    from_name: Option<String>,
    /// Raw `To`/`Cc` addresses, comma-joined, for Reply All.
    to: String,
    cc: String,
    /// Full DKIM/SPF/DMARC/warnings breakdown — shown as the security
    /// badge's tooltip rather than as always-visible text.
    verdict_summary: String,
    /// Whether the security badge should read as "all clear" (green) or
    /// "worth a look" (red) — see `security_is_ok`.
    security_ok: bool,
    link_warnings: Vec<LinkWarning>,
    message_id: Option<String>,
    body_text: Option<String>,
    attachments: Vec<AttachmentInfo>,
    /// Every inline image placeholder built for this message — lets
    /// "Show N images" load all of them at once, reusing the exact same
    /// per-image fetch+swap path a single click would use.
    pending_images: Vec<(gtk::Box, String, bool)>,
    /// `\Flagged` (star) state — read from the already-loaded list row
    /// at open time (IMAP flags live in the local index, not the cached
    /// `CachedMessage` or its inspection verdict), then kept in sync locally by
    /// `toggle_current_flag` so the badge doesn't need a full resync to
    /// reflect a click.
    flagged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposeKind {
    New,
    Reply,
    ReplyAll,
    Forward,
}

struct ComposeState {
    to: String,
    subject: String,
    in_reply_to: Option<String>,
    references: Option<String>,
    sending: bool,
    kind: ComposeKind,
    /// Local file paths picked via the attach-file dialog; read and sent
    /// as-is by the daemon, never copied anywhere ourselves.
    attachments: Vec<PathBuf>,
    /// `Some((folder, uid))` when this compose was opened by resuming an
    /// existing draft — so backing out again (or sending) can delete
    /// that *old* copy instead of leaving it behind once a fresh one is
    /// saved/sent, which would otherwise just pile up a duplicate in
    /// Drafts every time the same message got picked back up.
    editing_draft: Option<(String, u32)>,
    /// Keyboard focus — `(kb_pane, kb_folder_index, kb_message_uid)` —
    /// at the moment compose opened, so backing out or sending can put
    /// it back where it was (with the landing flash replaying) instead
    /// of leaving it wherever it happened to land inside compose. See
    /// `AppModel::kb_restore_origin`.
    kb_origin: (KeyboardPane, usize, Option<u32>),
}

struct AppModel {
    display_name: String,
    email: String,
    username: String,
    password: String,
    status: String,
    submitting: bool,
    needs_manual: bool,
    manual: ManualSettings,
    /// `Some(email)` when an account is already configured — shows the
    /// inbox screen instead of the add-account form.
    configured_email: Option<String>,
    /// The account's keyring/SQLite key — needed to query the local
    /// message index directly.
    account_id: Option<String>,
    selected_folder: Option<String>,
    /// How many of the selected folder's newest messages `reload()`
    /// fetches — starts at `MESSAGE_LIST_LIMIT`, bumped by the same
    /// amount each time "Load more" is activated (`Msg::LoadMoreMessages`),
    /// reset back to the default on every folder switch. Not a true
    /// offset/cursor — `list_messages` is just asked for a bigger `LIMIT`
    /// each time, so "load more" always re-fetches everything from the
    /// top, same as every other `reload()` call already does.
    folder_list_limit: u32,
    folders: FactoryVecDeque<FolderRow>,
    messages: FactoryVecDeque<MessageRow>,
    /// Every currently-snoozed message across every folder — only
    /// populated/shown while `viewing_snoozed` is true. Separate from
    /// `messages`/`MessageRow` entirely: a snoozed row only offers
    /// "cancel", not the full read/archive/star/etc. interaction set,
    /// since those all assume `self.selected_folder`, which doesn't
    /// mean anything in a cross-folder view — see `snoozed_row.rs`.
    snoozed: FactoryVecDeque<SnoozedRow>,
    /// Whether the inbox screen is showing the "Snoozed" view instead
    /// of `selected_folder`'s normal message list. Selecting a real
    /// folder always clears this back to `false`.
    viewing_snoozed: bool,
    /// Whether the window is currently wide enough to show the message
    /// list and reading pane side by side, rather than one at a time —
    /// driven by an `AdwBreakpoint` on window width (see `init`), not
    /// chosen by the user. Narrow (false) reproduces the previous
    /// behavior exactly: opening a message hides the list and takes
    /// over the full window, with the header's Back button returning to
    /// it. This exists because a maximized window left a large empty
    /// gap next to the message list with nothing in it, but a window
    /// tiled to half a wide monitor is too narrow to show a reading
    /// pane and a readable message at the same time — so the split only
    /// engages above the breakpoint width instead of always or never.
    wide_layout: bool,
    /// UIDs selected via each row's leading circle — drives both the
    /// per-row pop-out (exactly one selected) and the bulk-action bar
    /// (`settings.bulk_select_threshold`+ selected). Lives here rather than on
    /// each `MessageRow` because both of those depend on the *total*
    /// selection count, which no single row can see on its own; synced
    /// down to each row's `selected`/`revealed` fields by
    /// `sync_row_selection_flags`.
    selected_uids: std::collections::BTreeSet<u32>,
    /// Which currently-*selected* rows the mouse is over right now —
    /// not every hovered row, just the subset that's also selected,
    /// since that's the only thing `hover_deselect_source` cares about.
    /// Empty means the mouse is off every selected row, which is what
    /// starts the countdown; becoming non-empty again (hovering back
    /// onto any of them) cancels it. Below `settings.bulk_select_threshold`
    /// only — the bulk bar doesn't use this at all.
    hovered_selected: std::collections::HashSet<u32>,
    /// Identifies which `schedule_hover_deselect` call a pending
    /// `Msg::HoverDeselectTimeout` belongs to — see
    /// `kb_flash_generation`'s doc comment for why a generation counter
    /// is used here instead of canceling a `glib::SourceId` directly.
    hover_deselect_generation: u64,
    /// `Some` when a message is open for reading, hiding the inbox list.
    reading: Option<ReadingPane>,
    /// `Some` when the compose screen is open (new message or reply).
    compose: Option<ComposeState>,
    /// One `TextBuffer` for the app's whole lifetime, bound to the
    /// compose TextView exactly once at startup. Repeatedly calling
    /// `TextView::set_buffer()` via a `#[watch]` binding (i.e. on every
    /// model update, not just when compose opens) corrupted GTK's
    /// internal text-layout state and reliably crashed the app — this
    /// sidesteps that entirely by never swapping the buffer object after
    /// the view is built; opening compose just resets this buffer's text.
    compose_body_buffer: gtk::TextBuffer,
    /// The compose body's actual widget — see the `#[local_ref]` site
    /// in the view! macro for why this needs to be a persistent field
    /// rather than just inline there.
    compose_body_view: gtk::TextView,
    /// Same reasoning and same one-time, never-swapped binding as
    /// `compose_body_buffer` — the reading pane's body is now a real
    /// `GtkTextBuffer` (see `body_view`), not a rasterized image, and
    /// that earlier crash class is exactly what repeatedly calling
    /// `set_buffer()` on a live `TextView` causes.
    reading_body_buffer: gtk::TextBuffer,
    /// Kept directly (not just referenced from the view tree) because
    /// populating inline image placeholders requires
    /// `TextView::add_child_at_anchor`, which is a view method, not a
    /// buffer method — `open_message` needs to call it from outside the
    /// view! macro.
    reading_text_view: gtk::TextView,
    /// `To`/`Subject` entries for the compose screen — set imperatively
    /// (once, when compose opens) rather than via a `#[watch] set_text`
    /// binding. A `#[watch]` binding here caused an infinite hang on
    /// every single Reply/Forward: `set_text` fires GTK's `changed`
    /// signal even for a programmatic change, our `connect_changed`
    /// handler echoes that straight back into `Msg::ComposeSubject`/
    /// `ComposeTo`, and relm4 re-runs every `#[watch]` binding on *any*
    /// message with no equality check — so the fresh `update_view()`
    /// called `set_text` again with the identical text, which fired
    /// `changed` again, forever. Confirmed live: the main thread spun at
    /// 100% CPU with zero syscalls, stuck re-doing real Pango/fontconfig
    /// text shaping on every iteration of that cycle, never completing.
    /// Same one-time-bind fix as `compose_body_buffer` above, just for
    /// `EntryRow`s instead of a `TextBuffer`.
    compose_to_entry: adw::EntryRow,
    /// Autocomplete popover for `compose_to_entry` — built imperatively
    /// and rebuilt on every query change (`rebuild_contact_popover`),
    /// same established pattern as `move_to_menu_button`'s popover
    /// (`rebuild_move_to_menu`), not the `view!` macro: a dynamic list
    /// of click targets built from live query results doesn't fit a
    /// static widget tree. Parented to `compose_to_entry` once, in
    /// `init`.
    contact_popover: gtk::Popover,
    /// Current autocomplete matches for whatever's typed after the
    /// last comma in `compose_to_entry` — empty means the popover is
    /// (or should be) closed.
    contact_suggestions: Vec<store::Contact>,
    compose_subject_entry: adw::EntryRow,
    /// "Move to…" in the reading pane. Its popover isn't declared in the
    /// view! macro — it lists live folders, one button per folder with
    /// its own click closure (same plain-closure pattern as every other
    /// per-item action in this app, not a `gio::Menu`/action group) — so
    /// it's rebuilt imperatively by `rebuild_move_to_menu` whenever
    /// `self.folders` changes.
    move_to_menu_button: gtk::MenuButton,
    /// "Schedule" ("like an alarm for email") in the reading pane and
    /// the bulk-action bar. Unlike `move_to_menu_button`'s, these
    /// popovers list fixed relative-time presets rather than live
    /// data, so they're built once in `init()` via
    /// `build_schedule_popover`, not rebuilt on every `reload()`.
    schedule_current_menu_button: gtk::MenuButton,
    schedule_bulk_menu_button: gtk::MenuButton,
    /// A standalone clone of the input channel, kept so methods that
    /// aren't passed a `sender` (like `reload`, called from several
    /// places) can still queue a message — needed by
    /// `rebuild_move_to_menu`'s and `build_schedule_popover`'s
    /// per-button click closures.
    input_sender: relm4::Sender<Msg>,
    /// Local UI preferences (bulk-select threshold, signature) — loaded
    /// once at startup and kept in sync with `accounts.toml` by
    /// `persist_settings` on every change. See `config::AppSettings`'s
    /// doc comment for why this lives in `candor-core::config` rather
    /// than going through the daemon.
    settings: config::AppSettings,
    /// Which pane the keyboard cursor is in — see `KeyboardPane`.
    kb_pane: KeyboardPane,
    /// Which folder row the keyboard cursor is on, by index — folders
    /// don't reorder/prune themselves out from under an in-progress
    /// navigation the way messages do, so an index is stable enough.
    kb_folder_index: usize,
    /// Which message row the keyboard cursor is on, tracked by UID
    /// rather than index — the list reloads, reorders, and prunes rows
    /// during ordinary use (new mail, flag-refresh, archive-and-advance),
    /// and a UID survives that where an index wouldn't.
    kb_message_uid: Option<u32>,
    /// Briefly true right after a keyboard-driven "landing" (switching
    /// panes, or — once built — returning focus after compose), to
    /// drive the one-shot flash; cleared by `Msg::KbFlashEnd`.
    kb_flash: bool,
    /// Identifies which `schedule_kb_flash` call a pending
    /// `Msg::KbFlashEnd` belongs to — incremented on every call, never
    /// reset. `Msg::KbFlashEnd(gen)` only clears `kb_flash` when `gen`
    /// still matches, so a flash timer superseded by a newer pane
    /// switch before it fires just becomes a no-op instead of ending
    /// the new flash early. Earlier this held the pending timer's
    /// `glib::SourceId` instead, canceled via `.remove()` on every new
    /// call — but `timeout_add_local_once`'s source auto-destroys
    /// itself the instant it fires, so switching panes again in the
    /// narrow window after a flash timer fired but before its
    /// `Msg::KbFlashEnd` had been processed yet tried to remove an
    /// already-gone source. `SourceId::remove()` panics in that case,
    /// and since this all happens inside a GTK signal callback (an FFI
    /// boundary the panic can't unwind across), the whole process
    /// aborted — confirmed live via coredump: switching Ctrl+1/Ctrl+2
    /// back and forth quickly reproduced it every time. A generation
    /// counter needs no cancellation at all, so this can't recur.
    kb_flash_generation: u64,
    /// True once the keyboard (X, on the focused row) has touched the
    /// current selection — reset back to false the moment the
    /// selection empties out again (see `sync_row_selection_flags`), or
    /// immediately on a plain mouse click (`toggle_row_select`), since
    /// that's an explicit signal the mouse is driving again now. Exists
    /// purely to suppress mouse-only UI (the bulk bar, the per-row
    /// icon pop-out) while selecting via keyboard — those buttons
    /// exist to be clicked, and the entire point of X is not reaching
    /// for the mouse. Explicitly confirmed: "make sure when we add
    /// select in keyboard action it doesnt activate the bulk action
    /// bar... we arent using those icons because we are able to
    /// access them via the keyboard" — and separately, that a
    /// keyboard-built selection must never auto-expire the way a
    /// mouse one does (see the `!self.kb_select_mode` guard on
    /// `schedule_hover_deselect`'s call site in `row_hover_leave`).
    kb_select_mode: bool,
    /// Whether the search bar is currently open — `/` opens it, Escape
    /// closes it and restores `kb_restore_origin(search_kb_origin)`,
    /// same origin-restore pattern already used for compose.
    search_open: bool,
    search_query: String,
    /// The user-facing breadth toggle: search the current folder only,
    /// or every folder.
    search_all_folders: bool,
    /// Keyboard focus at the moment search was opened — see
    /// `search_open`'s doc comment.
    search_kb_origin: (KeyboardPane, usize, Option<u32>),
    /// Stored directly on the model (same reason as
    /// `compose_body_buffer`) so `Msg::OpenSearch`'s handler can call
    /// `.grab_focus()` on it — `update()` only ever gets `root`, not
    /// the full named-widgets struct.
    search_entry: gtk::Entry,
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
    Submit,
    RemoveAccount,
    OpenPreferences,
    SetBulkThreshold(usize),
    SetSignature(String),
    /// `0` means "no limit" (`None`) — same convention as the spin rows
    /// themselves, simpler than a separate enable/disable switch.
    SetRetentionDays(u32),
    SetRetentionMaxMb(u32),
    /// `0` means "use the built-in default" (25 min) — same convention
    /// as the retention rows.
    SetIdleTimeoutMinutes(u32),
    SetReadingCacheMaxMb(u32),
    /// "Import Contacts…" in Preferences — opens a file picker, then
    /// imports whatever CSV the user picks.
    ImportContactsCsv,
    SetKbPane(KeyboardPane),
    KbMoveUp,
    KbMoveDown,
    KbActivate,
    KbFlashEnd(u64),
    /// Action keys — act on `kb_target_uid()`, whatever the keyboard
    /// cursor is currently on (a focused list row, or the open reading
    /// pane), the same meaning either way. See `AppModel::kb_target_uid`.
    KbArchive,
    KbDelete,
    KbToggleUnread,
    KbToggleFlag,
    KbReply,
    KbReplyAll,
    KbForward,
    KbSchedule,
    KbMoveToFolder,
    KbToggleSelect,
    SelectFolderIndex(i32),
    SyncNow,
    Refresh,
    /// Bumps `folder_list_limit` by another `MESSAGE_LIST_LIMIT` batch
    /// and reloads — the explicit "Load more" row at the bottom of the
    /// message list.
    LoadMoreMessages,
    /// `/` (outside a text field) opens the search box and focuses it.
    OpenSearch,
    /// Escape while search is open — clears it and restores keyboard
    /// focus to wherever it was before, same pattern as backing out of
    /// compose.
    CloseSearch,
    SearchQueryChanged(String),
    /// Toggles the current-folder/all-folders search-breadth switch.
    SearchAllFoldersToggled(bool),
    /// The explicit "search the server too" action — broadens the
    /// current local search out to a live IMAP SEARCH.
    SearchServer,
    OpenMessageIndex(i32),
    GoBack,
    /// Sent by the `AdwBreakpoint` set up in `init` whenever the window
    /// crosses the wide/narrow threshold.
    SetWideLayout(bool),
    BodyClicked(f64, f64),
    OpenCompose,
    OpenReply,
    OpenReplyAll,
    OpenForward,
    ComposeTo(String),
    ComposeSubject(String),
    AttachFile,
    ClearAttachments,
    SaveAttachments,
    SendMessage,
    ShowAllImages,
    ArchiveMessage,
    DeleteMessage,
    /// The reading pane's opt-in "Add to contacts" button.
    AddContact,
    MarkUnread,
    ToggleCurrentFlag,
    MoveToFolder(String),
    ScheduleCurrent(i64),
    BulkSchedule(i64),
    ToggleSnoozedView,
    UnscheduleRow { folder: String, uid: u32 },
    /// Per-row quick actions from the message list, forwarded from
    /// `MessageRow`'s own output events — see `MessageRowOutput`.
    ArchiveRow(u32),
    DeleteRow(u32),
    ToggleRowUnread(u32),
    ToggleRowFlag(u32),
    ToggleRowSelect(u32),
    ScheduleRow { uid: u32, wake_at: i64 },
    ReplyRow(u32),
    ForwardRow(u32),
    RowHoverEnter(u32),
    RowHoverLeave(u32),
    HoverDeselectTimeout(u64),
    DraftSaved,
    DraftSaveFailed(String),
    ToggleSelectAll,
    ClearSelection,
    BulkMarkToggle,
    BulkFlagToggle,
    BulkArchive,
    BulkDelete,
}

#[relm4::component(async)]
impl AsyncComponent for AppModel {
    type Init = ();
    type Input = Msg;
    type Output = ();
    type CommandOutput = ();

    view! {
        adw::ApplicationWindow {
            set_default_width: 760,
            set_default_height: 540,

            // Ctrl+1/2/3 switches which pane (folders / messages /
            // reading) the keyboard cursor is in; j/k moves within it;
            // Enter activates whatever's focused. Deliberately not
            // guarding Ctrl+<number> on focus location — no text widget
            // in this app binds that combination to anything of its
            // own — but j/k/Enter are guarded: typing "j" or "k" into
            // compose, the signature field, or anywhere else text goes
            // must never be hijacked as navigation.
            add_controller = gtk::EventControllerKey {
                connect_key_pressed[sender] => move |controller, keyval, _keycode, state| {
                    if state.contains(gdk::ModifierType::CONTROL_MASK) {
                        let pane = match keyval {
                            gdk::Key::_1 => Some(KeyboardPane::Folders),
                            gdk::Key::_2 => Some(KeyboardPane::Messages),
                            gdk::Key::_3 => Some(KeyboardPane::Reading),
                            _ => None,
                        };
                        return match pane {
                            Some(pane) => {
                                sender.input(Msg::SetKbPane(pane));
                                glib::Propagation::Stop
                            }
                            None => glib::Propagation::Proceed,
                        };
                    }

                    // Escape (Back/cancel) works the same regardless of
                    // what has focus — unlike j/k/the action letters, it
                    // was never going to mean "type a literal Escape
                    // character" in a text field, so there's no reason
                    // to guard it the same way. A popover that's
                    // currently open consumes it itself to close (GTK's
                    // own behavior), so this only ever fires when
                    // nothing's already handled it.
                    if keyval == gdk::Key::Escape {
                        sender.input(Msg::GoBack);
                        return glib::Propagation::Stop;
                    }

                    let focused_is_text = controller
                        .widget()
                        .and_then(|w| w.downcast::<gtk::Window>().ok())
                        .and_then(|win| gtk::prelude::GtkWindowExt::focus(&win))
                        .is_some_and(|f| f.is::<gtk::Text>() || f.is::<gtk::TextView>());
                    if focused_is_text {
                        return glib::Propagation::Proceed;
                    }

                    if keyval == gdk::Key::slash {
                        sender.input(Msg::OpenSearch);
                        return glib::Propagation::Stop;
                    }

                    // Action keys loosely follow Gmail's own (E for
                    // archive, R/A/F for reply/reply-all/forward, V for
                    // move-to) — not because this app otherwise mirrors
                    // Gmail, but because that's the muscle memory most
                    // people already have for single-letter mail
                    // shortcuts, so reaching for the same letters here
                    // costs nothing and saves relearning.
                    let msg = match keyval {
                        gdk::Key::j => Some(Msg::KbMoveDown),
                        gdk::Key::k => Some(Msg::KbMoveUp),
                        gdk::Key::Return => Some(Msg::KbActivate),
                        // `OpenCompose` had no keyboard path at all
                        // before this — only the mouse-only "New
                        // Message" sidebar button. `open_compose`
                        // itself guards against clobbering an
                        // already-in-progress compose, same spirit as
                        // every other action key being a safe no-op in
                        // whatever state it doesn't apply to.
                        gdk::Key::c => Some(Msg::OpenCompose),
                        gdk::Key::e => Some(Msg::KbArchive),
                        gdk::Key::Delete | gdk::Key::BackSpace => Some(Msg::KbDelete),
                        gdk::Key::u => Some(Msg::KbToggleUnread),
                        gdk::Key::s => Some(Msg::KbToggleFlag),
                        gdk::Key::r => Some(Msg::KbReply),
                        gdk::Key::a => Some(Msg::KbReplyAll),
                        gdk::Key::f => Some(Msg::KbForward),
                        gdk::Key::b => Some(Msg::KbSchedule),
                        gdk::Key::v => Some(Msg::KbMoveToFolder),
                        gdk::Key::x => Some(Msg::KbToggleSelect),
                        _ => None,
                    };
                    match msg {
                        Some(msg) => {
                            sender.input(msg);
                            glib::Propagation::Stop
                        }
                        None => glib::Propagation::Proceed,
                    }
                }
            },

            #[wrap(Some)]
            set_content = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::WindowTitle {
                        #[watch]
                        set_title: &header_title(&model),
                        #[watch]
                        set_subtitle: &header_subtitle(&model),
                    },

                    pack_start = &gtk::Button {
                        set_icon_name: "go-previous-symbolic",
                        set_tooltip_text: Some("Back"),
                        // In the wide side-by-side layout the list is
                        // always visible next to the reading pane, so
                        // there's nothing to navigate back from — only
                        // offer it in the narrow, one-pane-at-a-time
                        // layout (or out of compose, either way).
                        #[watch]
                        set_visible: (model.reading.is_some() && !model.wide_layout) || model.compose.is_some(),
                        connect_clicked => Msg::GoBack,
                    },

                    // Settings menu — currently just "Remove account",
                    // but a gear/popover is the right home for anything
                    // account-level that isn't routine enough to earn
                    // its own always-visible header button.
                    pack_end = &gtk::MenuButton {
                        set_icon_name: "emblem-system-symbolic",
                        set_tooltip_text: Some("Settings"),
                        #[watch]
                        set_visible: model.configured_email.is_some()
                            && model.reading.is_none()
                            && model.compose.is_none(),
                        #[wrap(Some)]
                        set_popover = &gtk::Popover {
                            #[wrap(Some)]
                            set_child = &gtk::Box {
                                set_orientation: gtk::Orientation::Vertical,
                                set_margin_all: 6,

                                gtk::Button {
                                    set_label: "Preferences",
                                    add_css_class: "flat",
                                    connect_clicked => Msg::OpenPreferences,
                                },
                                gtk::Button {
                                    set_label: "Remove Account",
                                    add_css_class: "flat",
                                    connect_clicked => Msg::RemoveAccount,
                                },
                            },
                        },
                    },
                    pack_end = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some("Sync now"),
                        #[watch]
                        set_visible: model.configured_email.is_some()
                            && model.reading.is_none()
                            && model.compose.is_none(),
                        connect_clicked => Msg::SyncNow,
                    },
                    pack_end = &gtk::ToggleButton {
                        set_icon_name: "system-search-symbolic",
                        set_tooltip_text: Some("Search (/)"),
                        #[watch]
                        set_visible: model.configured_email.is_some()
                            && model.reading.is_none()
                            && model.compose.is_none(),
                        #[watch]
                        set_active: model.search_open,
                        connect_clicked[sender] => move |btn| {
                            sender.input(if btn.is_active() { Msg::OpenSearch } else { Msg::CloseSearch });
                        },
                    },
                    pack_end = &gtk::Button {
                        set_icon_name: "mail-forward-symbolic",
                        set_tooltip_text: Some("Forward"),
                        #[watch]
                        set_visible: model.reading.is_some() && model.compose.is_none(),
                        connect_clicked => Msg::OpenForward,
                    },
                    pack_end = &gtk::Button {
                        set_icon_name: "mail-reply-all-symbolic",
                        set_tooltip_text: Some("Reply All"),
                        #[watch]
                        set_visible: model.reading.is_some() && model.compose.is_none(),
                        connect_clicked => Msg::OpenReplyAll,
                    },
                    pack_end = &gtk::Button {
                        set_icon_name: "mail-reply-sender-symbolic",
                        set_tooltip_text: Some("Reply"),
                        #[watch]
                        set_visible: model.reading.is_some() && model.compose.is_none(),
                        connect_clicked => Msg::OpenReply,
                    },
                    pack_end = &gtk::Button {
                        set_icon_name: "mail-attachment-symbolic",
                        set_tooltip_text: Some("Attach Files"),
                        #[watch]
                        set_visible: model.compose.is_some(),
                        connect_clicked => Msg::AttachFile,
                    },
                    pack_end = &gtk::Button {
                        set_icon_name: "mail-send-symbolic",
                        set_tooltip_text: Some("Send"),
                        add_css_class: "suggested-action",
                        #[watch]
                        set_visible: model.compose.is_some(),
                        #[watch]
                        set_sensitive: model.compose.as_ref().is_some_and(|c| !c.sending),
                        connect_clicked => Msg::SendMessage,
                    },
                },

                add_top_bar = &gtk::Separator {
                    set_orientation: gtk::Orientation::Horizontal,
                },

                #[wrap(Some)]
                set_content = &gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 8,
                    set_margin_all: 16,

                    // --- inbox screen ---
                    gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 8,
                        set_vexpand: true,

                        // No `reading.is_none()` here anymore — the
                        // reading pane now lives *inside* this screen
                        // (see the message/reading split further down),
                        // side by side with the list on a wide window or
                        // swapped with it one-at-a-time on a narrow one,
                        // rather than being a separate full-takeover
                        // screen that hid this whole area.
                        #[watch]
                        set_visible: model.configured_email.is_some() && model.compose.is_none(),

                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_width_request: 180,
                            // The folder-row label and the "Snoozed"
                            // label each set their own `hexpand: true`
                            // (so the unread count/badge in that one row
                            // pins to the row's right edge) — with
                            // nothing here saying otherwise, GTK reads
                            // that as "the whole sidebar wants to grow"
                            // and propagates it all the way up, so the
                            // sidebar ended up splitting the window's
                            // width roughly evenly with the message list
                            // instead of staying at `width_request`.
                            // Setting it explicitly here is what actually
                            // stops that climb.
                            set_hexpand: false,

                            gtk::Button {
                                set_icon_name: "mail-message-new-symbolic",
                                set_tooltip_text: Some("New Message"),
                                set_halign: gtk::Align::Start,
                                add_css_class: "flat",
                                // Lined up with the folder row labels
                                // below it, not just the list's edge —
                                // "navigation-sidebar" rows indent their
                                // text this much from the list's own
                                // start.
                                set_margin_start: 8,
                                set_margin_top: 4,
                                set_margin_bottom: 4,
                                connect_clicked => Msg::OpenCompose,
                            },

                            gtk::ScrolledWindow {
                                set_hscrollbar_policy: gtk::PolicyType::Never,
                                set_vexpand: true,

                                #[local_ref]
                                folder_list -> gtk::ListBox {
                                    add_css_class: "navigation-sidebar",
                                    // Explicit rather than relying on
                                    // GTK's default — this is what makes
                                    // `reload()`'s `select_row` call
                                    // actually paint a visible highlight.
                                    set_selection_mode: gtk::SelectionMode::Single,
                                    connect_row_activated[sender] => move |_list, row| {
                                        sender.input(Msg::SelectFolderIndex(row.index()));
                                    }
                                }
                            },

                            gtk::Separator {
                                set_orientation: gtk::Orientation::Horizontal,
                            },

                            // Not a real folder — a filtered, local-only
                            // view of whatever's currently snoozed (see
                            // `snoozed_row.rs`), kept separate from the
                            // folder list above since it isn't one.
                            gtk::Button {
                                set_halign: gtk::Align::Fill,
                                add_css_class: "flat",
                                set_margin_all: 4,
                                #[watch]
                                set_css_classes: if model.viewing_snoozed {
                                    &["flat", "suggested-action"]
                                } else {
                                    &["flat"]
                                },
                                connect_clicked => Msg::ToggleSnoozedView,

                                gtk::Box {
                                    set_orientation: gtk::Orientation::Horizontal,
                                    set_spacing: 8,

                                    gtk::Image {
                                        set_icon_name: Some("alarm-symbolic"),
                                    },
                                    gtk::Label {
                                        set_label: "Snoozed",
                                        set_halign: gtk::Align::Start,
                                        set_hexpand: true,
                                    },
                                    gtk::Label {
                                        #[watch]
                                        set_label: &model.snoozed.len().to_string(),
                                        #[watch]
                                        set_visible: !model.snoozed.is_empty(),
                                        add_css_class: "dim-label",
                                        add_css_class: "caption",
                                    },
                                },
                            },
                        },

                        gtk::Separator {
                            set_orientation: gtk::Orientation::Vertical,
                        },

                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_hexpand: true,
                            set_vexpand: true,
                            #[watch]
                            set_visible: !model.viewing_snoozed,

                            // The list and the reading pane, side by side
                            // on a wide window (`wide_layout`, driven by
                            // the `AdwBreakpoint` set up in `init`) or
                            // swapped one-at-a-time on a narrow one — see
                            // the comment on `AppModel::wide_layout`.
                            gtk::Box {
                                set_orientation: gtk::Orientation::Horizontal,
                                set_spacing: 8,
                                set_hexpand: true,
                                set_vexpand: true,

                                gtk::Box {
                                    set_orientation: gtk::Orientation::Vertical,
                                    // Each row's title wraps across two
                                    // lines (the date eyebrow + subject —
                                    // see `message_row.rs`) rather than
                                    // ellipsizing, so it needs real room:
                                    // at 320 the shortest words didn't
                                    // even fit a line and wrapped
                                    // mid-word, producing a column of
                                    // single-letter lines and absurdly
                                    // tall rows. Bumped from 420 to 460 —
                                    // the search bar and bulk-action bar
                                    // both live in this same column now
                                    // (see their own comments below for
                                    // why they moved here), and 420 was
                                    // a tight fit for the bulk bar's six
                                    // icon buttons plus its "N selected"
                                    // label.
                                    set_width_request: 460,
                                    #[watch]
                                    set_hexpand: !model.wide_layout,
                                    #[watch]
                                    set_visible: model.wide_layout || model.reading.is_none(),

                                    // `/` opens this (outside a text field),
                                    // Escape closes it and restores keyboard
                                    // focus to wherever it was — same
                                    // origin-restore pattern as backing out of
                                    // compose (`kb_restore_origin`). Typing
                                    // live-filters the message list in place
                                    // (`reload()` branches to `search_messages`
                                    // while this is open) rather than showing a
                                    // separate results view.
                                    //
                                    // Lives in this narrower list column,
                                    // not the wider box that also contains
                                    // the reading pane — it used to sit
                                    // one level up, which stretched it
                                    // (and the bulk-action bar below) all
                                    // the way to the reading pane's right
                                    // edge on a wide window, nowhere near
                                    // the list it actually acts on. Found
                                    // live: "the bulk edit bar icons are
                                    // too far away when you are in
                                    // fullscreen mode."
                                    gtk::Box {
                                        set_orientation: gtk::Orientation::Horizontal,
                                        set_spacing: 6,
                                        set_margin_all: 8,
                                        #[watch]
                                        set_visible: model.search_open,

                                        // Deliberately NOT a `#[watch] set_text`
                                        // binding — pairing that with
                                        // `connect_changed` on the same widget
                                        // is a known infinite-loop hazard in this
                                        // codebase (`gtk_editable_set_text`
                                        // fires `changed` even on a programmatic
                                        // set, which would echo right back into
                                        // `set_text` again forever — see
                                        // `candor_relm4_watch_feedback_loop_bug`
                                        // in memory). The model's own
                                        // `search_query` field is kept in sync
                                        // purely for `reload()` to read; the
                                        // widget's displayed text is the user's
                                        // own typing and is only ever set
                                        // imperatively, at `Msg::OpenSearch`/
                                        // `Msg::CloseSearch`, never reactively.
                                        #[local_ref]
                                        search_entry -> gtk::Entry {
                                            set_hexpand: true,
                                            set_placeholder_text: Some("Search mail…"),
                                            connect_changed[sender] => move |entry| {
                                                sender.input(Msg::SearchQueryChanged(entry.text().to_string()));
                                            },
                                        },
                                        gtk::ToggleButton {
                                            set_label: "All folders",
                                            #[watch]
                                            set_active: model.search_all_folders,
                                            connect_toggled[sender] => move |btn| {
                                                sender.input(Msg::SearchAllFoldersToggled(btn.is_active()));
                                            },
                                        },
                                        gtk::Button {
                                            set_label: "Search server",
                                            set_tooltip_text: Some(
                                                "Also search the live server \u{2014} slower, but finds matches not yet cached locally"
                                            ),
                                            connect_clicked => Msg::SearchServer,
                                        },
                                        gtk::Button {
                                            set_icon_name: "window-close-symbolic",
                                            set_tooltip_text: Some("Close search"),
                                            add_css_class: "flat",
                                            connect_clicked => Msg::CloseSearch,
                                        },
                                    },

                                    // Surfaces once enough rows are selected that
                                    // hand-picking a different action per message
                                    // stops being plausible — see
                                    // `settings.bulk_select_threshold`. Below that, each
                                    // selected row keeps its own pop-out instead
                                    // (see `message_row.rs`). "Select all" lives
                                    // in here too, not as its own always-visible
                                    // control — once you've picked enough to get
                                    // this bar, "grab everything else in this
                                    // folder too" is the natural next click.
                                    // Always visible and height-reserved, even
                                    // with nothing selected — toggling this bar
                                    // with `set_visible` made the message list
                                    // jump up/down by its height every time the
                                    // selection crossed the threshold, which
                                    // read as the whole list jittering. Fading
                                    // its *contents* in and out instead keeps
                                    // the reserved space constant, so crossing
                                    // the threshold never moves anything below it.
                                    // Lives in the list column — see the
                                    // search bar's comment just above for
                                    // why (same reason, same fix).
                                    gtk::Box {
                                        set_orientation: gtk::Orientation::Horizontal,
                                        set_spacing: 6,
                                        set_margin_all: 8,
                                        set_height_request: 40,
                                        add_css_class: "card",
                                        #[watch]
                                        set_opacity: if bulk_bar_active(&model) { 1.0 } else { 0.0 },
                                        #[watch]
                                        set_sensitive: bulk_bar_active(&model),

                                        gtk::Button {
                                            set_icon_name: "edit-select-all-symbolic",
                                            set_tooltip_text: Some("Select all in this folder"),
                                            add_css_class: "flat",
                                            connect_clicked => Msg::ToggleSelectAll,
                                        },
                                        gtk::Button {
                                            set_icon_name: "window-close-symbolic",
                                            set_tooltip_text: Some("Clear selection"),
                                            add_css_class: "flat",
                                            connect_clicked => Msg::ClearSelection,
                                        },
                                        gtk::Label {
                                            #[watch]
                                            set_label: &format!("{} selected", model.selected_uids.len()),
                                            set_hexpand: true,
                                            set_halign: gtk::Align::Start,
                                        },
                                        // One button, not two — it already
                                        // knows what to do: all-unread selected
                                        // shows "mark read", all-read shows
                                        // "mark unread", and a mixed selection
                                        // defaults to "mark read" (see
                                        // `bulk_mark_target`). A uniform
                                        // selection closes itself afterward
                                        // same as the other bulk actions; a
                                        // resolved mixed one stays open so you
                                        // can see — and, if you clicked the
                                        // wrong direction, immediately reverse
                                        // — what just happened before
                                        // confirming by closing it yourself.
                                        // Mark-read/unread, star, archive, and
                                        // schedule all drop out in Drafts/Sent —
                                        // none of them mean anything for your own
                                        // outgoing mail. Delete (and select-all/
                                        // clear, above) still do.
                                        gtk::Button {
                                            #[watch]
                                            set_icon_name: if bulk_mark_target(&model) { "mail-read-symbolic" } else { "mail-unread-symbolic" },
                                            #[watch]
                                            set_tooltip_text: Some(if bulk_mark_target(&model) { "Mark read" } else { "Mark unread" }),
                                            add_css_class: "flat",
                                            #[watch]
                                            set_visible: !model.current_folder_restricted(),
                                            connect_clicked => Msg::BulkMarkToggle,
                                        },
                                        gtk::Button {
                                            #[watch]
                                            set_icon_name: if bulk_flag_target(&model) { "non-starred-symbolic" } else { "starred-symbolic" },
                                            #[watch]
                                            set_tooltip_text: Some(if bulk_flag_target(&model) { "Star selected" } else { "Unstar selected" }),
                                            add_css_class: "flat",
                                            #[watch]
                                            set_visible: !model.current_folder_restricted(),
                                            connect_clicked => Msg::BulkFlagToggle,
                                        },
                                        gtk::Button {
                                            set_icon_name: "mail-archive-symbolic",
                                            set_tooltip_text: Some("Archive selected"),
                                            add_css_class: "flat",
                                            #[watch]
                                            set_visible: !model.current_folder_restricted(),
                                            connect_clicked => Msg::BulkArchive,
                                        },
                                        gtk::Button {
                                            set_icon_name: "user-trash-symbolic",
                                            set_tooltip_text: Some("Delete selected"),
                                            add_css_class: "flat",
                                            connect_clicked => Msg::BulkDelete,
                                        },
                                        #[local_ref]
                                        schedule_bulk_menu_button -> gtk::MenuButton {
                                            set_icon_name: "alarm-symbolic",
                                            set_tooltip_text: Some("Schedule selected…"),
                                            add_css_class: "flat",
                                            #[watch]
                                            set_visible: !model.current_folder_restricted(),
                                        },
                                    },

                                    gtk::ScrolledWindow {
                                        set_hexpand: true,
                                        set_vexpand: true,

                                        #[local_ref]
                                        message_list -> gtk::ListBox {
                                            add_css_class: "boxed-list",
                                            set_selection_mode: gtk::SelectionMode::None,
                                            set_valign: gtk::Align::Start,
                                            set_margin_all: 8,
                                            connect_row_activated[sender] => move |_list, row| {
                                                sender.input(Msg::OpenMessageIndex(row.index()));
                                            }
                                        }
                                    },

                                    // Explicit "Load more" rather than
                                    // infinite scroll (the user's own
                                    // choice) — shown only when the list
                                    // currently shows exactly
                                    // `folder_list_limit` messages, since
                                    // that's the only signal available
                                    // that there might be more past the
                                    // cutoff (fetching one extra row just
                                    // to know for certain wasn't judged
                                    // worth the complexity here). An
                                    // ordinary `GtkButton` participates in
                                    // the normal Tab/Enter focus chain on
                                    // its own, so no custom keyboard
                                    // wiring is needed for "or
                                    // keyboard-activate".
                                    gtk::Button {
                                        set_label: "Load more",
                                        set_margin_all: 8,
                                        #[watch]
                                        set_visible: model.messages.len() as u32 == model.folder_list_limit,
                                        connect_clicked => Msg::LoadMoreMessages,
                                    },
                                },

                                gtk::Separator {
                                    set_orientation: gtk::Orientation::Vertical,
                                    #[watch]
                                    set_visible: model.wide_layout,
                                },

                                gtk::Box {
                                    set_orientation: gtk::Orientation::Vertical,
                                    set_hexpand: true,
                                    set_vexpand: true,
                                    #[watch]
                                    set_visible: model.wide_layout || model.reading.is_some(),

                                    // --- reading pane ---
                                    gtk::Box {
                                        set_orientation: gtk::Orientation::Vertical,
                                        set_spacing: 8,
                                        set_vexpand: true,

                                        // `&& model.compose.is_none()`, not just
                                        // `model.reading.is_some()` alone — Reply/Forward
                                        // deliberately keep `self.reading` populated (so
                                        // "Back" from the compose screen returns to the
                                        // same message instead of the inbox), but without
                                        // this, that left the reading pane's own
                                        // interactive `TextView` — complete with
                                        // clickable links and image-load buttons —
                                        // visible and overlapping the compose screen at
                                        // the same time. Confirmed: clicking Reply/Forward
                                        // crashed the app, almost certainly two live
                                        // interactive `TextView`s simultaneously fighting
                                        // over focus — the same class of fragile-GTK-
                                        // text-widget-state bug already found once this
                                        // session (see `compose_body_buffer`'s comment).
                                        #[watch]
                                        set_visible: model.reading.is_some() && model.compose.is_none(),

                                        gtk::Box {
                                            set_orientation: gtk::Orientation::Horizontal,
                                            set_spacing: 8,

                                            // Security badge: a single at-a-glance
                                            // signal instead of the old always-spelled-
                                            // out "DKIM: pass · SPF: pass · DMARC: pass"
                                            // text — the full breakdown (same detail as
                                            // before, plus any link/attachment/sender
                                            // warnings) is still there, just on hover
                                            // now rather than permanently on screen.
                                            gtk::Box {
                                                set_spacing: 4,
                                                #[watch]
                                                set_tooltip_text: model
                                                    .reading
                                                    .as_ref()
                                                    .map(|r| r.verdict_summary.as_str()),

                                                gtk::Image {
                                                    #[watch]
                                                    set_icon_name: Some(
                                                        if model.reading.as_ref().is_some_and(|r| r.security_ok) {
                                                            "security-high-symbolic"
                                                        } else {
                                                            "security-low-symbolic"
                                                        },
                                                    ),
                                                    #[watch]
                                                    set_css_classes: security_css_classes(
                                                        model.reading.as_ref().is_some_and(|r| r.security_ok),
                                                    ),
                                                },
                                                gtk::Label {
                                                    set_label: "Security",
                                                    add_css_class: "dim-label",
                                                },
                                            },

                                            gtk::Box {
                                                set_hexpand: true,
                                            },

                                            // Opt-in, zero-friction contact capture —
                                            // deliberately not automatic (see
                                            // `candor_group6_contacts_plan` in memory for
                                            // why auto-harvesting every sender/reply
                                            // recipient was ruled out as too noisy).
                                            // Available any time a message is open, not
                                            // just when replying — clicking it is the only
                                            // way a received sender ever becomes a
                                            // contact; ignoring it costs nothing.
                                            gtk::Button {
                                                set_icon_name: "contact-new-symbolic",
                                                set_tooltip_text: Some("Add to contacts"),
                                                connect_clicked => Msg::AddContact,
                                            },

                                            gtk::Button {
                                                set_icon_name: "mail-attachment-symbolic",
                                                #[watch]
                                                set_tooltip_text: Some(
                                                    &model
                                                        .reading
                                                        .as_ref()
                                                        .map(|r| format!("Save {} Attachment(s)", r.attachments.len()))
                                                        .unwrap_or_default(),
                                                ),
                                                #[watch]
                                                set_visible: model
                                                    .reading
                                                    .as_ref()
                                                    .is_some_and(|r| !r.attachments.is_empty()),
                                                connect_clicked => Msg::SaveAttachments,
                                            },
                                            gtk::Button {
                                                set_icon_name: "image-x-generic-symbolic",
                                                #[watch]
                                                set_tooltip_text: Some(
                                                    &model
                                                        .reading
                                                        .as_ref()
                                                        .map(|r| format!("Show {} image(s)", r.pending_images.len()))
                                                        .unwrap_or_default(),
                                                ),
                                                #[watch]
                                                set_visible: model
                                                    .reading
                                                    .as_ref()
                                                    .is_some_and(|r| !r.pending_images.is_empty()),
                                                connect_clicked => Msg::ShowAllImages,
                                            },
                                            // Archive, mark-unread, star, and schedule
                                            // drop out for Sent mail specifically — the
                                            // only folder besides Drafts this
                                            // restriction applies to that's ever opened
                                            // through the reading pane at all (Drafts
                                            // always routes into compose instead — see
                                            // `Msg::OpenMessageIndex`). Delete and
                                            // Move-to stay available either way.
                                            gtk::Button {
                                                set_icon_name: "mail-archive-symbolic",
                                                set_tooltip_text: Some("Archive"),
                                                #[watch]
                                                set_visible: !model.current_folder_restricted(),
                                                connect_clicked => Msg::ArchiveMessage,
                                            },
                                            gtk::Button {
                                                set_icon_name: "user-trash-symbolic",
                                                set_tooltip_text: Some("Delete"),
                                                connect_clicked => Msg::DeleteMessage,
                                            },
                                            gtk::Button {
                                                set_icon_name: "mail-unread-symbolic",
                                                set_tooltip_text: Some("Mark Unread"),
                                                #[watch]
                                                set_visible: !model.current_folder_restricted(),
                                                connect_clicked => Msg::MarkUnread,
                                            },
                                            gtk::Button {
                                                #[watch]
                                                set_icon_name: if model.reading.as_ref().is_some_and(|r| r.flagged) {
                                                    "starred-symbolic"
                                                } else {
                                                    "non-starred-symbolic"
                                                },
                                                set_tooltip_text: Some("Star"),
                                                #[watch]
                                                set_visible: !model.current_folder_restricted(),
                                                connect_clicked => Msg::ToggleCurrentFlag,
                                            },
                                            #[local_ref]
                                            move_to_menu_button -> gtk::MenuButton {
                                                set_icon_name: "folder-symbolic",
                                                set_tooltip_text: Some("Move to…"),
                                            },
                                            #[local_ref]
                                            schedule_current_menu_button -> gtk::MenuButton {
                                                set_icon_name: "alarm-symbolic",
                                                set_tooltip_text: Some("Schedule…"),
                                                #[watch]
                                                set_visible: !model.current_folder_restricted(),
                                            },
                                        },

                                        gtk::ScrolledWindow {
                                            set_vexpand: true,
                                            set_hexpand: true,

                                            #[local_ref]
                                            reading_text_view -> gtk::TextView {
                                                set_editable: false,
                                                set_cursor_visible: false,
                                                set_wrap_mode: gtk::WrapMode::WordChar,
                                                set_left_margin: 16,
                                                set_right_margin: 16,
                                                set_top_margin: 12,
                                                set_bottom_margin: 12,

                                                add_controller = gtk::GestureClick {
                                                    connect_pressed[sender] => move |_gesture, _n_press, x, y| {
                                                        sender.input(Msg::BodyClicked(x, y));
                                                    }
                                                },
                                            }
                                        },
                                    },

                                    // Only ever shown in the wide layout —
                                    // in the narrow one, this whole column
                                    // (along with the reading pane above)
                                    // is hidden whenever nothing's open,
                                    // same as before the split existed.
                                    // Here, it's what fills the space that
                                    // used to just sit empty next to the
                                    // list on a maximized window.
                                    gtk::Box {
                                        set_orientation: gtk::Orientation::Vertical,
                                        set_valign: gtk::Align::Center,
                                        set_vexpand: true,
                                        set_spacing: 8,
                                        #[watch]
                                        set_visible: model.reading.is_none() && model.compose.is_none(),

                                        gtk::Image {
                                            set_icon_name: Some("mail-unread-symbolic"),
                                            set_pixel_size: 48,
                                            add_css_class: "dim-label",
                                        },
                                        gtk::Label {
                                            set_label: "Select a message to read",
                                            add_css_class: "dim-label",
                                        },
                                    },
                                },
                            },
                        },

                        // The "Snoozed" view — cross-folder, read-only
                        // besides "cancel" (see `snoozed_row.rs`).
                        // Occupies the same space as the normal message
                        // area above, which hides itself while this is
                        // showing.
                        gtk::ScrolledWindow {
                            set_hexpand: true,
                            set_vexpand: true,
                            #[watch]
                            set_visible: model.viewing_snoozed,

                            #[local_ref]
                            snoozed_list -> gtk::ListBox {
                                add_css_class: "boxed-list",
                                set_selection_mode: gtk::SelectionMode::None,
                                set_valign: gtk::Align::Start,
                                set_margin_all: 8,
                            }
                        },
                    },

                    // --- compose screen ---
                    gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 8,
                        set_vexpand: true,

                        #[watch]
                        set_visible: model.compose.is_some(),

                        adw::PreferencesGroup {
                            #[local_ref]
                            compose_to_entry -> adw::EntryRow {
                                set_title: "To",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::ComposeTo(entry.text().to_string()));
                                },
                            },
                            #[local_ref]
                            compose_subject_entry -> adw::EntryRow {
                                set_title: "Subject",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::ComposeSubject(entry.text().to_string()));
                                },
                            },
                        },

                        gtk::Box {
                            set_orientation: gtk::Orientation::Horizontal,
                            set_spacing: 8,

                            #[watch]
                            set_visible: model.compose.as_ref().is_some_and(|c| !c.attachments.is_empty()),

                            gtk::Label {
                                set_halign: gtk::Align::Start,
                                set_hexpand: true,
                                set_wrap: true,
                                add_css_class: "dim-label",
                                #[watch]
                                set_label: &model
                                    .compose
                                    .as_ref()
                                    .map(|c| attachment_summary(&c.attachments))
                                    .unwrap_or_default(),
                            },

                            gtk::Button {
                                set_icon_name: "edit-clear-symbolic",
                                set_tooltip_text: Some("Remove Attachments"),
                                connect_clicked => Msg::ClearAttachments,
                            },
                        },

                        gtk::ScrolledWindow {
                            set_vexpand: true,

                            // Stored as a persistent model field (not
                            // just inline here) so `open_reply`/
                            // `open_reply_all` can call `.grab_focus()`
                            // on it directly from `update()` — same
                            // `#[local_ref]` pattern as
                            // `reading_text_view`. `update()` only ever
                            // gets `root`, not the full named-widgets
                            // struct, so a widget that needs driving
                            // from a message handler has to live on
                            // `self` like this.
                            #[local_ref]
                            compose_body_view -> gtk::TextView {
                                set_wrap_mode: gtk::WrapMode::Word,
                                set_top_margin: 8,
                                set_bottom_margin: 8,
                                set_left_margin: 8,
                                set_right_margin: 8,
                                // Bound once, never swapped — see the
                                // comment on `compose_body_buffer`.
                                set_buffer: Some(&model.compose_body_buffer),
                            }
                        },
                    },

                    // --- add-account form ---
                    gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 12,

                        #[watch]
                        set_visible: model.configured_email.is_none(),

                        adw::PreferencesGroup {
                            set_title: "Add account",

                            adw::EntryRow {
                                set_title: "Your name",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::DisplayName(entry.text().to_string()));
                                },
                            },
                            adw::EntryRow {
                                set_title: "Email address",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::Email(entry.text().to_string()));
                                },
                            },
                            adw::EntryRow {
                                set_title: "Username (if different from email)",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::Username(entry.text().to_string()));
                                },
                            },
                            adw::PasswordEntryRow {
                                set_title: "Password",
                                connect_changed[sender] => move |entry| {
                                    sender.input(Msg::Password(entry.text().to_string()));
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
                            set_sensitive: !model.submitting,
                            connect_clicked => Msg::Submit,
                        },
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
        }
    }

    fn init_loading_widgets(root: Self::Root) -> Option<LoadingWidgets> {
        view! {
            #[local]
            root {
                set_default_width: 760,
                set_default_height: 540,

                #[name(spinner)]
                gtk::Spinner {
                    start: (),
                    set_halign: gtk::Align::Center,
                    set_valign: gtk::Align::Center,
                }
            }
        }
        Some(LoadingWidgets::new(root, spinner))
    }

    async fn init(
        _init: Self::Init,
        root: Self::Root,
        sender: AsyncComponentSender<Self>,
    ) -> AsyncComponentParts<Self> {
        let startup = check_existing_account().await;

        let folders = FactoryVecDeque::builder().launch_default().detach();
        let messages = FactoryVecDeque::builder().launch_default().forward(
            sender.input_sender(),
            |output| match output {
                MessageRowOutput::Archive(uid) => Msg::ArchiveRow(uid),
                MessageRowOutput::Delete(uid) => Msg::DeleteRow(uid),
                MessageRowOutput::ToggleUnread(uid) => Msg::ToggleRowUnread(uid),
                MessageRowOutput::ToggleFlag(uid) => Msg::ToggleRowFlag(uid),
                MessageRowOutput::ToggleSelect(uid) => Msg::ToggleRowSelect(uid),
                MessageRowOutput::Schedule { uid, wake_at } => Msg::ScheduleRow { uid, wake_at },
                MessageRowOutput::Reply(uid) => Msg::ReplyRow(uid),
                MessageRowOutput::Forward(uid) => Msg::ForwardRow(uid),
                MessageRowOutput::HoverEnter(uid) => Msg::RowHoverEnter(uid),
                MessageRowOutput::HoverLeave(uid) => Msg::RowHoverLeave(uid),
            },
        );
        let snoozed = FactoryVecDeque::builder().launch_default().forward(
            sender.input_sender(),
            |output| match output {
                SnoozedRowOutput::Unschedule { folder, uid } => Msg::UnscheduleRow { folder, uid },
            },
        );

        let mut model = AppModel {
            display_name: String::new(),
            email: String::new(),
            username: String::new(),
            password: String::new(),
            status: startup.note.unwrap_or_default(),
            submitting: false,
            needs_manual: false,
            manual: ManualSettings::default(),
            configured_email: startup.email,
            account_id: startup.account_id,
            selected_folder: None,
            folder_list_limit: MESSAGE_LIST_LIMIT,
            folders,
            messages,
            snoozed,
            viewing_snoozed: false,
            wide_layout: false,
            selected_uids: std::collections::BTreeSet::new(),
            hovered_selected: std::collections::HashSet::new(),
            hover_deselect_generation: 0,
            reading: None,
            compose: None,
            compose_body_buffer: gtk::TextBuffer::new(None::<&gtk::TextTagTable>),
            compose_body_view: gtk::TextView::new(),
            search_open: false,
            search_query: String::new(),
            search_all_folders: false,
            search_kb_origin: (KeyboardPane::Folders, 0, None),
            search_entry: gtk::Entry::new(),
            reading_body_buffer: gtk::TextBuffer::new(None::<&gtk::TextTagTable>),
            reading_text_view: gtk::TextView::new(),
            compose_to_entry: adw::EntryRow::new(),
            contact_popover: gtk::Popover::new(),
            contact_suggestions: Vec::new(),
            compose_subject_entry: adw::EntryRow::new(),
            move_to_menu_button: gtk::MenuButton::new(),
            schedule_current_menu_button: gtk::MenuButton::new(),
            schedule_bulk_menu_button: gtk::MenuButton::new(),
            input_sender: sender.input_sender().clone(),
            settings: config::load().map(|cfg| cfg.settings).unwrap_or_default(),
            kb_pane: KeyboardPane::Messages,
            kb_folder_index: 0,
            kb_message_uid: None,
            kb_flash: false,
            kb_flash_generation: 0,
            kb_select_mode: false,
        };
        model.reload();
        model.reading_text_view.set_buffer(Some(&model.reading_body_buffer));
        model
            .schedule_current_menu_button
            .set_popover(Some(&build_schedule_popover(model.input_sender.clone(), Msg::ScheduleCurrent)));
        model
            .schedule_bulk_menu_button
            .set_popover(Some(&build_schedule_popover(model.input_sender.clone(), Msg::BulkSchedule)));
        // Managed entirely by `rebuild_contact_popover`/`update_contact_suggestions`
        // (popup/popdown driven by whether there are any matches right
        // now), not by the usual click-to-open/click-outside-to-close
        // behavior a popover normally has — autohide would fight with
        // that, dismissing it the instant focus moves for an unrelated
        // reason mid-typing.
        model.contact_popover.set_parent(&model.compose_to_entry);
        model.contact_popover.set_autohide(false);
        model.contact_popover.set_has_arrow(false);

        let folder_list = model.folders.widget();
        let message_list = model.messages.widget();
        let snoozed_list = model.snoozed.widget();
        let reading_text_view = model.reading_text_view.clone();
        let search_entry = model.search_entry.clone();
        let compose_body_view = model.compose_body_view.clone();
        let compose_to_entry = model.compose_to_entry.clone();
        let compose_subject_entry = model.compose_subject_entry.clone();
        let move_to_menu_button = model.move_to_menu_button.clone();
        let schedule_current_menu_button = model.schedule_current_menu_button.clone();
        let schedule_bulk_menu_button = model.schedule_bulk_menu_button.clone();
        let widgets = view_output!();

        // Drives `wide_layout`: below this width the list and reading
        // pane can't both be comfortably readable at once (the exact
        // problem with a window tiled to half even a fairly wide
        // monitor), so they go back to sharing one pane the way they
        // always have; at or above it there's room to show both side by
        // side permanently instead of leaving that space empty. 1150sp
        // is a judgment call, not a measured value — raised from an
        // initial 1000 after the list column (420 wide, see above) plus
        // the folder sidebar (~180) plus a reading pane worth actually
        // having open (~450) plus margins didn't comfortably fit below
        // it; comfortably below a maximized window on most monitors,
        // comfortably above half of one.
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

        // `apply`/`unapply` only fire on a *crossing* of the threshold —
        // confirmed directly (another standalone test): a window that
        // launches wide and never once gets narrower never fires either
        // signal at all, since the breakpoint's condition was never
        // true to begin with and there's nothing to "unapply". That left
        // `wide_layout` stuck at its initial `false`, matching exactly
        // what was reported: full-screen on launch showed no reading
        // pane, and it only started tracking width correctly after the
        // first real resize (the first actual crossing) taught the
        // breakpoint to start emitting. A one-time read of the window's
        // real width shortly after showing — not relied on afterward,
        // just to get the initial state right — closes that gap. The
        // delay gives Wayland's initial configure a moment to land
        // before reading it; a window not yet mapped would otherwise be
        // measured at its unhelpful GTK-requested default size.
        let startup_sync_sender = sender.input_sender().clone();
        let startup_sync_root = root.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(300), move || {
            let _ = startup_sync_sender.send(Msg::SetWideLayout(startup_sync_root.width() >= 1150));
        });

        // Periodic refresh so the list picks up what the daemon's
        // background IDLE sync lands in the DB, without needing a D-Bus
        // signal subscription for v1.
        let input_sender = sender.input_sender().clone();
        sender.command(move |_out, shutdown| {
            shutdown
                .register(async move {
                    loop {
                        tokio::time::sleep(REFRESH_INTERVAL).await;
                        let _ = input_sender.send(Msg::Refresh);
                    }
                })
                .drop_on_shutdown()
        });

        AsyncComponentParts { model, widgets }
    }

    async fn update(
        &mut self,
        msg: Self::Input,
        _sender: AsyncComponentSender<Self>,
        root: &Self::Root,
    ) {
        match msg {
            Msg::DisplayName(v) => self.display_name = v,
            Msg::Email(v) => self.email = v,
            Msg::Username(v) => self.username = v,
            Msg::Password(v) => self.password = v,
            Msg::ManualImapHost(v) => self.manual.imap_host = v,
            Msg::ManualImapPort(v) => self.manual.imap_port = v,
            Msg::ManualImapImplicitTls(v) => self.manual.imap_implicit_tls = v,
            Msg::ManualSmtpHost(v) => self.manual.smtp_host = v,
            Msg::ManualSmtpPort(v) => self.manual.smtp_port = v,
            Msg::ManualSmtpImplicitTls(v) => self.manual.smtp_implicit_tls = v,
            Msg::Submit => self.submit().await,
            Msg::RemoveAccount => self.remove_account().await,
            Msg::OpenPreferences => self.open_preferences(root),
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
            Msg::ImportContactsCsv => self.import_contacts_csv(root).await,
            Msg::SetKbPane(pane) => self.set_kb_pane(pane),
            Msg::KbMoveUp => self.kb_move(-1),
            Msg::KbMoveDown => self.kb_move(1),
            Msg::KbActivate => self.kb_activate(root).await,
            Msg::KbFlashEnd(generation) => {
                if generation != self.kb_flash_generation {
                    return;
                }
                self.kb_flash = false;
                self.sync_keyboard_focus_flags();
            }
            Msg::KbArchive => self.kb_archive().await,
            Msg::KbDelete => self.kb_delete().await,
            Msg::KbToggleUnread => self.kb_toggle_unread().await,
            Msg::KbToggleFlag => self.kb_toggle_flag().await,
            Msg::KbReply => self.kb_reply(root).await,
            Msg::KbReplyAll => self.kb_reply_all(root).await,
            Msg::KbForward => self.kb_forward(root).await,
            Msg::KbSchedule => self.kb_schedule(root).await,
            Msg::KbMoveToFolder => self.kb_move_to_folder(root).await,
            Msg::KbToggleSelect => self.kb_toggle_select(),
            Msg::SelectFolderIndex(index) => {
                if let Some(folder) = (index >= 0).then(|| self.folders.get(index as usize)).flatten() {
                    self.selected_folder = Some(folder.raw_name.clone());
                    self.viewing_snoozed = false;
                    self.folder_list_limit = MESSAGE_LIST_LIMIT;
                    // A click acts exactly like Ctrl+1 + navigating here
                    // with j/k would have — keeps the keyboard cursor in
                    // sync with the mouse instead of the two silently
                    // drifting apart. No flash: you can already see
                    // where you clicked.
                    self.kb_pane = KeyboardPane::Folders;
                    self.kb_folder_index = index as usize;
                    self.reload();
                }
            }
            Msg::ToggleSnoozedView => {
                self.viewing_snoozed = !self.viewing_snoozed;
                self.reload();
            }
            Msg::UnscheduleRow { folder, uid } => self.unschedule_row(&folder, uid).await,
            Msg::SyncNow => self.sync_now().await,
            Msg::Refresh => self.reload(),
            Msg::LoadMoreMessages => {
                self.folder_list_limit += MESSAGE_LIST_LIMIT;
                self.reload();
            }
            Msg::OpenSearch => {
                if !self.search_open {
                    self.search_kb_origin = (self.kb_pane, self.kb_folder_index, self.kb_message_uid);
                    self.search_open = true;
                    self.search_query.clear();
                    self.search_entry.set_text("");
                    self.reload();
                }
                self.search_entry.grab_focus();
            }
            Msg::CloseSearch => self.close_search(root),
            Msg::SearchQueryChanged(v) => {
                self.search_query = v;
                self.reload();
            }
            Msg::SearchAllFoldersToggled(v) => {
                self.search_all_folders = v;
                self.reload();
            }
            Msg::SearchServer => self.search_server().await,
            Msg::OpenMessageIndex(index) => {
                let uid = (index >= 0)
                    .then(|| self.messages.get(index as usize))
                    .flatten()
                    .map(|row| row.summary.uid);
                if let Some(uid) = uid {
                    // Same reasoning as `SelectFolderIndex` above — a
                    // click keeps the keyboard cursor in sync, no flash.
                    self.kb_pane = KeyboardPane::Messages;
                    self.kb_message_uid = Some(uid);
                    self.sync_keyboard_focus_flags();
                    // A draft isn't something you *read* — it's
                    // something you were in the middle of writing, so
                    // clicking one picks straight back up in compose
                    // rather than opening the reading pane.
                    if self.current_folder_special_use("\\Drafts") {
                        self.resume_draft(uid).await;
                    } else {
                        self.open_message(uid, root).await;
                    }
                }
            }
            Msg::GoBack => {
                // Priority order for what Escape actually closes, most
                // specific/recently-opened first: a compose in progress,
                // then the search bar (it's a temporary overlay over
                // whatever else is showing), then finally the reading
                // pane itself. The controller that sends `GoBack` has no
                // access to model state to decide this itself (it's a
                // plain `EventControllerKey` closure with just `sender`
                // — see the `/`/Escape wiring on the root window), so it
                // always fires the same message and this is where the
                // actual branching happens.
                if self.compose.is_some() {
                    self.backout_of_compose();
                } else if self.search_open {
                    self.close_search(root);
                } else {
                    self.reading = None;
                }
            }
            Msg::SetWideLayout(v) => self.wide_layout = v,
            Msg::BodyClicked(x, y) => self.handle_body_click(x, y, root).await,
            Msg::OpenCompose => self.open_compose(),
            Msg::OpenReply => self.open_reply(),
            Msg::OpenReplyAll => self.open_reply_all(),
            Msg::OpenForward => self.open_forward(),
            Msg::ComposeTo(v) => {
                if let Some(c) = self.compose.as_mut() {
                    c.to = v.clone();
                }
                self.update_contact_suggestions(&v);
            }
            Msg::ComposeSubject(v) => {
                if let Some(c) = self.compose.as_mut() {
                    c.subject = v;
                }
            }
            Msg::AttachFile => self.attach_file(root).await,
            Msg::ClearAttachments => {
                if let Some(c) = self.compose.as_mut() {
                    c.attachments.clear();
                }
            }
            Msg::SaveAttachments => self.save_attachments(root).await,
            Msg::SendMessage => self.send_compose().await,
            Msg::ShowAllImages => self.show_all_images(root).await,
            Msg::ArchiveMessage => self.move_current_message("\\Archive").await,
            Msg::DeleteMessage => self.move_current_message("\\Trash").await,
            Msg::AddContact => self.add_contact().await,
            Msg::MarkUnread => self.mark_current_unread().await,
            Msg::ToggleCurrentFlag => self.toggle_current_flag().await,
            Msg::MoveToFolder(folder) => self.move_current_message_to_folder(folder).await,
            Msg::ScheduleCurrent(wake_at) => self.schedule_current_message(wake_at).await,
            Msg::BulkSchedule(wake_at) => self.bulk_schedule(wake_at).await,
            Msg::ArchiveRow(uid) => self.move_row(uid, "\\Archive").await,
            Msg::DeleteRow(uid) => self.move_row(uid, "\\Trash").await,
            Msg::ToggleRowUnread(uid) => self.toggle_row_unread(uid).await,
            Msg::ToggleRowFlag(uid) => self.toggle_row_flag(uid).await,
            Msg::ToggleRowSelect(uid) => self.toggle_row_select(uid),
            Msg::ScheduleRow { uid, wake_at } => self.schedule_row(uid, wake_at).await,
            Msg::ReplyRow(uid) => {
                self.open_message(uid, root).await;
                self.open_reply();
            }
            Msg::ForwardRow(uid) => {
                self.open_message(uid, root).await;
                self.open_forward();
            }
            Msg::RowHoverEnter(uid) => self.row_hover_enter(uid),
            Msg::RowHoverLeave(uid) => self.row_hover_leave(uid),
            Msg::HoverDeselectTimeout(generation) => self.hover_deselect_timeout(generation),
            Msg::DraftSaved => self.sync_drafts_folder().await,
            Msg::DraftSaveFailed(e) => self.status = e,
            Msg::ToggleSelectAll => self.toggle_select_all(),
            Msg::ClearSelection => self.clear_selection(),
            Msg::BulkMarkToggle => self.bulk_mark_toggle().await,
            Msg::BulkFlagToggle => self.bulk_flag_toggle().await,
            Msg::BulkArchive => self.bulk_move("\\Archive").await,
            Msg::BulkDelete => self.bulk_move("\\Trash").await,
        }
    }
}

impl AppModel {
    /// Re-reads folders and the selected folder's messages straight from
    /// the local SQLite index — the daemon is the writer, this is a pure
    /// local read, no D-Bus round trip needed.
    fn reload(&mut self) {
        let Some(account_id) = self.account_id.clone() else {
            self.folders.guard().clear();
            self.messages.guard().clear();
            self.snoozed.guard().clear();
            self.selected_uids.clear();
            return;
        };
        let Ok(db) = store::open() else { return };

        let infos = store::list_folders(&db, &account_id).unwrap_or_default();
        let mut displays: Vec<_> = infos.iter().map(folder_display::normalize).collect();
        displays.sort_by_key(folder_display::sort_key);
        let raw_names: Vec<String> = displays.iter().map(|d| d.raw_name.clone()).collect();

        {
            let mut guard = self.folders.guard();
            guard.clear();
            for display in displays {
                guard.push_back(display);
            }
        }

        {
            let mut guard = self.snoozed.guard();
            guard.clear();
            for snoozed in store::list_snoozed(&db, &account_id).unwrap_or_default() {
                guard.push_back(snoozed);
            }
        }

        let folder = self
            .selected_folder
            .clone()
            .filter(|f| raw_names.contains(f))
            .or_else(|| raw_names.first().cloned());
        self.selected_folder = folder.clone();

        // `self.folders` was just rebuilt from scratch above — brand
        // new `GtkListBoxRow`s with no memory of which one used to be
        // selected, so GTK's own selection highlight (which is what
        // actually shows which folder you're in) silently disappears
        // on every single `reload()`: the periodic refresh, going back
        // from a message, sending mail, all of it. Re-selecting the
        // matching row every time this runs is what makes the
        // highlight actually persist rather than only surviving until
        // the next refresh tick.
        let folder_list = self.folders.widget();
        match self.selected_folder.as_ref().and_then(|f| raw_names.iter().position(|n| n == f)) {
            Some(index) => folder_list.select_row(folder_list.row_at_index(index as i32).as_ref()),
            None => folder_list.select_row(None::<&gtk::ListBoxRow>),
        }

        // The "Snoozed" view is cross-folder and non-interactive beyond
        // cancel — it's populated separately above, not from here, and
        // has nothing to do with whichever real folder happens to be
        // selected underneath it. Still clear `messages` while it's
        // showing so a stale list isn't sitting there if the view
        // toggles back off mid-refresh.
        let new_uids: std::collections::HashSet<u32> = if self.viewing_snoozed {
            let mut messages_guard = self.messages.guard();
            if messages_guard.len() > 0 {
                messages_guard.clear();
            }
            std::collections::HashSet::new()
        } else {
            let query = self.search_query.trim();
            let messages = if self.search_open && !query.is_empty() {
                // Scoped to the current folder unless the all-folders
                // toggle is on — the user-facing breadth choice, not a
                // fixed architectural one. Local-first: this only ever
                // searches what's already synced/cached; `SearchServer`
                // is the separate, explicit action that reaches out to
                // the live IMAP server.
                let scope = (!self.search_all_folders).then(|| folder.as_deref()).flatten();
                store::search_messages(&db, &account_id, scope, query, self.folder_list_limit)
                    .unwrap_or_default()
            } else {
                folder
                    .map(|folder| {
                        store::list_messages(&db, &account_id, &folder, self.folder_list_limit)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default()
            };
            let uids = messages.iter().map(|m| m.uid).collect();

            // `reload()` runs on every periodic refresh tick regardless
            // of whether anything actually changed — clearing and
            // rebuilding every row from scratch every ~10s (up to
            // `MESSAGE_LIST_LIMIT` of them) destroys and recreates that
            // many live GTK widgets for literally no visible difference
            // almost every single time it runs. Skipping the rebuild
            // entirely when the freshly-queried data is identical to
            // what's already showing is what actually gets rid of that
            // wasted, un-asked-for redraw.
            let unchanged = {
                let current: Vec<&store::MessageSummary> = self.messages.iter().map(|r| &r.summary).collect();
                current.len() == messages.len() && current.iter().zip(messages.iter()).all(|(a, b)| **a == *b)
            };
            if !unchanged {
                let mut messages_guard = self.messages.guard();
                messages_guard.clear();
                for m in messages {
                    messages_guard.push_back(m);
                }
            }
            uids
        };

        // `reload()` runs on every periodic refresh tick (every
        // `REFRESH_INTERVAL`), not just after a real change, and
        // rebuilds every row from scratch either way — unconditionally
        // clearing the selection here wiped out whatever the user had
        // selected every ~10s even when nothing had actually changed.
        // Pruning to just the UIDs that still exist keeps a live
        // selection intact across routine refreshes while still
        // dropping anything that genuinely got archived/deleted/moved
        // out from under it.
        self.selected_uids.retain(|uid| new_uids.contains(uid));
        self.sync_row_selection_flags();
        self.sync_keyboard_focus_flags();
        self.rebuild_move_to_menu();
    }

    async fn open_message(&mut self, uid: u32, root: &adw::ApplicationWindow) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        self.status = "Loading message…".to_string();

        let path = {
            let result = async {
                let conn = zbus::Connection::session().await?;
                let proxy = DaemonProxy::new(&conn).await?;
                proxy.fetch_body(&folder, uid).await
            }
            .await;

            match result {
                Ok((true, path)) => path,
                Ok((false, _)) => {
                    self.status = "No account configured.".to_string();
                    return;
                }
                Err(e) => {
                    self.status = format!("Failed to load message: {e}");
                    return;
                }
            }
        };
        let path = std::path::PathBuf::from(path);

        // Never raw MIME bytes — `fetch_body` only ever caches the
        // extracted display content (`body::CachedMessage`), never
        // attachment bytes or even the full raw message. See
        // `body.rs`'s module doc comment.
        let cached = match candor_core::body::read_cached_message(&path) {
            Ok(Some(cached)) => cached,
            Ok(None) => {
                self.status = "Message isn't cached.".to_string();
                return;
            }
            Err(e) => {
                self.status = format!("Failed to read cached message: {e}");
                return;
            }
        };

        let verdict = candor_core::body::read_verdict(&path).ok().flatten();
        // `sanitized_html_with_images` (not the default `sanitized_html`)
        // because the latter has `img src` stripped entirely — fine for
        // the old raster renderer, which only ever drew what was handed
        // to it, but we now need the real `src` *string* up front so
        // `richtext::html_to_segments` can discover each image and build
        // a click-to-load placeholder for it. This never fetches
        // anything: only the URL text is extracted here — the actual
        // network request happens solely from an explicit per-image
        // click (see `fetch_one_image`), same as before.
        let html =
            verdict.as_ref().and_then(|v| v.sanitized_html_with_images.clone()).unwrap_or_default();

        // `richtext::collapse_whitespace` on every header/body field that
        // can end up in a GTK widget, not just HTML body text it was
        // originally written for — confirmed live that a raw `Subject`
        // header (automated/marketing email headers can carry the same
        // zero-width padding bodies do) hung the whole app for minutes
        // feeding straight into an `EntryRow` on Reply. Headers are
        // exactly the kind of thing that never goes through the HTML
        // sanitizer at all, so nothing was ever filtering this out of
        // them.
        let subject = richtext::collapse_whitespace(cached.subject.as_deref().unwrap_or("(no subject)"));
        let from = richtext::collapse_whitespace(cached.from_address.as_deref().unwrap_or("(unknown sender)"));
        let from_name = cached.from_name.as_deref().map(richtext::collapse_whitespace).filter(|n| !n.is_empty());
        let message_id = cached.message_id;
        let body_text = cached.body_text.as_deref().map(richtext::strip_invisible_chars);
        let to_addrs = richtext::collapse_whitespace(&cached.to);
        let cc_addrs = richtext::collapse_whitespace(&cached.cc);

        // Walking the HTML into rich-text segments is cheap compared to
        // what litehtml's CSS layout used to cost, but it's still real
        // work proportional to message size — keep it off the main
        // thread rather than assume it's always negligible.
        let segments = if html.trim().is_empty() {
            let text = body_text.clone().unwrap_or_default();
            tokio::task::spawn_blocking(move || richtext::plain_text_segments(&text))
                .await
                .unwrap_or_default()
        } else {
            tokio::task::spawn_blocking(move || richtext::html_to_segments(&html)).await.unwrap_or_default()
        };

        let pending_anchors = body_view::populate(&self.reading_body_buffer, &segments);
        let tracker_urls = verdict.as_ref().map(|v| v.suspected_trackers.clone()).unwrap_or_default();
        let mut pending_images = Vec::with_capacity(pending_anchors.len());
        for pending in pending_anchors {
            let is_tracker = tracker_urls.contains(&pending.src);
            let container =
                Self::build_image_placeholder(pending.src.clone(), pending.alt, &tracker_urls, root);
            self.reading_text_view.add_child_at_anchor(&container, &pending.anchor);
            pending_images.push((container, pending.src, is_tracker));
        }

        let flagged =
            self.messages.iter().find(|row| row.summary.uid == uid).is_some_and(|row| row.summary.flagged);

        // Cloned before `body_text` moves into `ReadingPane` below —
        // caching this for search is free (the fetch above already
        // happened to display it), except in Junk, which is never
        // cached regardless of trigger (see `message_bodies`'s caching
        // policy).
        let body_for_cache =
            (!self.current_folder_special_use("\\Junk")).then(|| body_text.clone()).flatten();

        self.status = String::new();
        let reading_folder = folder.clone();
        self.reading = Some(ReadingPane {
            uid,
            folder,
            subject,
            from,
            from_name,
            to: to_addrs,
            cc: cc_addrs,
            verdict_summary: summarize_verdict(verdict.as_ref()),
            security_ok: security_is_ok(verdict.as_ref()),
            link_warnings: verdict.as_ref().map(|v| v.link_warnings.clone()).unwrap_or_default(),
            attachments: verdict.map(|v| v.attachments).unwrap_or_default(),
            message_id,
            body_text,
            pending_images,
            flagged,
        });

        // Opening the message in the reading pane IS reading it, even
        // though — unlike that — fetching/caching its raw bytes above
        // deliberately isn't (see `body::fetch_body`'s `BODY.PEEK[]`
        // comment). This used to be `tokio::spawn`ed and left to the
        // next periodic `reload()` to pick up, on the theory that a
        // live IMAP round trip shouldn't delay the message appearing —
        // but `mark_read` is local-only now (writes SQLite and returns
        // — see `queue_flag_change` on the daemon side), so there's no
        // real round trip to wait out, and leaving it detached just
        // meant going back to the list right after opening a message
        // would still show it unread for however long until the next
        // periodic tick. Awaiting it and reloading immediately closes
        // that gap: the row is correct the moment you go back, not
        // eventually.
        if let Ok(conn) = zbus::Connection::session().await {
            if let Ok(proxy) = DaemonProxy::new(&conn).await {
                let _ = proxy.mark_read(&reading_folder, uid).await;
                if let Some(text) = body_for_cache {
                    let _ = proxy.cache_opened_body(&reading_folder, uid, &text).await;
                }
            }
        }
        self.reload();
    }

    /// Builds one inline "click to load this image" placeholder — a flat
    /// button with the image's alt text, swapped in place for the real
    /// picture once clicked. Flagging a specific image as a likely
    /// tracker (rather than blocking or warning about images as a whole)
    /// is only possible now that loading is per-image instead of
    /// all-or-nothing.
    ///
    /// Deliberately doesn't go through `Msg`/`sender.input` — a
    /// `gtk::Box` embedded in a `Msg` variant makes the whole `Msg` type
    /// non-`Send`, which breaks relm4's channel infrastructure far
    /// beyond this one feature (it cascades into anything that sends a
    /// `Msg` across a thread, e.g. the periodic refresh timer below).
    /// `glib::spawn_future_local` runs this async work pinned to the
    /// main thread instead, which is exactly where it needs to run
    /// anyway (it ends by mutating a live `GtkBox`) and doesn't require
    /// `Send` at all.
    fn build_image_placeholder(
        src: String,
        alt: String,
        tracker_urls: &[String],
        root: &adw::ApplicationWindow,
    ) -> gtk::Box {
        let is_tracker = tracker_urls.contains(&src);
        let container = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        container.add_css_class("inline-image-placeholder");

        let icon_name = if is_tracker { "security-low-symbolic" } else { "image-x-generic-symbolic" };
        let button = gtk::Button::builder()
            .icon_name(icon_name)
            .tooltip_text(if is_tracker {
                format!("Possible tracking pixel — click to load anyway: {alt}")
            } else {
                format!("Click to load image: {alt}")
            })
            .css_classes(["flat"])
            .build();
        container.append(&button);

        let label = gtk::Label::new(Some(&format!("[{alt}]")));
        label.add_css_class("dim-label");
        container.append(&label);

        let container_for_click = container.clone();
        let root = root.clone();
        button.connect_clicked(move |_| {
            glib::spawn_future_local(load_single_image(
                container_for_click.clone(),
                src.clone(),
                is_tracker,
                root.clone(),
            ));
        });

        container
    }

    /// Leaving compose without sending — saves whatever was typed as a
    /// draft (real IMAP `APPEND`, not a local-only queue: see
    /// `save_draft`'s doc comment for why this one genuinely is a
    /// network round trip) as long as there's actually something to
    /// save, same as every other mail client's "closing this discards
    /// nothing you typed" behavior. An empty compose (nothing ever
    /// typed into To/Subject/body) is just abandoned, same as before —
    /// no reason to leave a blank draft sitting in Drafts.
    /// Returns to the inbox *immediately* — the actual draft save (a
    /// real network round trip; see `save_draft`'s doc comment) runs in
    /// the background via `glib::spawn_future_local`, same pattern as
    /// the per-image load buttons, rather than being awaited right here
    /// in the message handler. Awaiting it inline was the bug: relm4
    /// only processes one message at a time, so the *entire* UI sat
    /// frozen — not just the compose screen — for however long the
    /// IMAP `APPEND` (confirmed live: 3-4 seconds) took to come back,
    /// which is a much worse user experience than "the draft shows up
    /// a moment after you're already back in the inbox."
    /// Closes the search bar and restores keyboard focus to wherever it
    /// was before it opened (`search_kb_origin`) — shared by
    /// `Msg::CloseSearch` (the explicit close button, and toggling the
    /// header search button off) and `Msg::GoBack`'s Escape handling.
    fn close_search(&mut self, root: &adw::ApplicationWindow) {
        self.search_open = false;
        self.search_query.clear();
        self.search_entry.set_text("");
        // Hiding the search bar's container doesn't by itself clear GTK
        // keyboard focus away from whatever was focused inside it — GTK
        // just advances focus to the next focusable widget in the chain
        // (confirmed live: it lands on the header's search toggle
        // button), which then silently re-activates itself on a bare
        // Return/Enter afterward, since a focused `GtkButton` handles
        // that key *before* it ever reaches this window's
        // `EventControllerKey` — reopening search right after closing
        // it. Explicitly clearing focus here is what stops that.
        gtk::prelude::GtkWindowExt::set_focus(root, None::<&gtk::Widget>);
        let origin = self.search_kb_origin;
        self.reload();
        self.kb_restore_origin(origin);
    }

    fn backout_of_compose(&mut self) {
        let Some(compose) = self.compose.take() else {
            return;
        };
        // Doesn't wait on the draft save below — nothing about *where
        // the keyboard cursor lands* depends on whether that's finished.
        self.kb_restore_origin(compose.kb_origin);

        // Explicit, not left to GTK to figure out on its own — see the
        // focus-handling gotcha found while closing the search bar
        // (`candor_gtk_adwaita_gotchas` in memory): don't assume a
        // popover tied to a widget that's about to disappear closes
        // itself cleanly.
        self.contact_popover.popdown();
        self.contact_suggestions.clear();

        let start = self.compose_body_buffer.start_iter();
        let end = self.compose_body_buffer.end_iter();
        let body = self.compose_body_buffer.text(&start, &end, false).to_string();
        self.compose_body_buffer.set_text("");

        let has_content = !compose.to.trim().is_empty() || !compose.subject.trim().is_empty() || !body.trim().is_empty();
        let input_sender = self.input_sender.clone();
        // A fresh id every save, same as before this field existed —
        // a draft's Message-ID was never stable across repeated saves
        // to begin with, and drafts aren't a body-cache trigger anyway
        // (only an actual send is), so there's no continuity to lose.
        let message_id =
            candor_core::send::generate_message_id(self.configured_email.as_deref().unwrap_or(""));

        if has_content {
            self.status = "Saving draft…".to_string();
            glib::spawn_future_local(async move {
                let result = async {
                    let conn = zbus::Connection::session().await?;
                    let proxy = DaemonProxy::new(&conn).await?;
                    proxy
                        .save_draft(
                            &compose.to,
                            &compose.subject,
                            &body,
                            compose.in_reply_to.as_deref().unwrap_or(""),
                            compose.references.as_deref().unwrap_or(""),
                            &message_id,
                        )
                        .await
                }
                .await;

                // The *old* copy has to be gone before anything
                // refreshes the list, not after — doing this the other
                // way around (sync first, delete after) is exactly what
                // produced "two drafts, then one disappears a few
                // seconds later": the sync made both the new save and
                // the still-undeleted old one visible at once, and
                // nothing ever repainted the list again once the delete
                // itself (which is local-first/instant on its own —
                // see `queue_move`) quietly finished underneath it.
                if let Some((folder, uid)) = compose.editing_draft {
                    if let Ok(conn) = zbus::Connection::session().await {
                        if let Ok(proxy) = DaemonProxy::new(&conn).await {
                            let _ = proxy.move_message(&folder, uid, "\\Trash").await;
                        }
                    }
                }

                let msg = match result {
                    Ok(true) => Msg::DraftSaved,
                    Ok(false) => Msg::DraftSaveFailed("Couldn't save draft — no Drafts folder found.".to_string()),
                    Err(e) => Msg::DraftSaveFailed(format!("Failed to save draft: {e}")),
                };
                let _ = input_sender.send(msg);
            });
        } else {
            self.status = String::new();
            if let Some((folder, uid)) = compose.editing_draft {
                glib::spawn_future_local(async move {
                    if let Ok(conn) = zbus::Connection::session().await {
                        if let Ok(proxy) = DaemonProxy::new(&conn).await {
                            let _ = proxy.move_message(&folder, uid, "\\Trash").await;
                        }
                    }
                    let _ = input_sender.send(Msg::Refresh);
                });
            }
        }
    }

    /// Opens an existing draft back into compose instead of the reading
    /// pane — see `Msg::OpenMessageIndex`'s doc comment on why Drafts
    /// specifically routes here. Reads the same cached `CachedMessage`
    /// `open_message` does, just pulling compose fields out of it
    /// instead of building a `ReadingPane`.
    async fn resume_draft(&mut self, uid: u32) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        self.status = "Loading draft…".to_string();

        let path = {
            let result = async {
                let conn = zbus::Connection::session().await?;
                let proxy = DaemonProxy::new(&conn).await?;
                proxy.fetch_body(&folder, uid).await
            }
            .await;

            match result {
                Ok((true, path)) => path,
                Ok((false, _)) => {
                    self.status = "No account configured.".to_string();
                    return;
                }
                Err(e) => {
                    self.status = format!("Failed to load draft: {e}");
                    return;
                }
            }
        };

        let path = std::path::PathBuf::from(path);
        let cached = match candor_core::body::read_cached_message(&path) {
            Ok(Some(cached)) => cached,
            _ => {
                self.status = "Failed to read cached draft.".to_string();
                return;
            }
        };

        let to = richtext::collapse_whitespace(&cached.to);
        let subject = richtext::collapse_whitespace(cached.subject.as_deref().unwrap_or(""));
        let body = cached.body_text.as_deref().map(richtext::strip_invisible_chars).unwrap_or_default();

        self.close_reading();
        self.compose_body_buffer.set_text(&body);
        self.compose_to_entry.set_text(&to);
        self.compose_subject_entry.set_text(&subject);
        self.status = String::new();
        self.compose = Some(ComposeState {
            to,
            subject,
            in_reply_to: None,
            references: None,
            sending: false,
            kind: ComposeKind::New,
            attachments: Vec::new(),
            editing_draft: Some((folder, uid)),
            kb_origin: (self.kb_pane, self.kb_folder_index, self.kb_message_uid),
        });
    }

    fn open_compose(&mut self) {
        // Guards against clobbering an in-progress compose — the "New
        // Message" button is only ever shown when nothing's open, so
        // this never mattered for the mouse path, but `c` (below) is a
        // global keybinding reachable from any state, and silently
        // wiping out whatever the user was already writing would be a
        // real problem, not just a cosmetic one.
        if self.compose.is_some() {
            return;
        }
        self.close_reading();
        self.compose_body_buffer.set_text(&self.with_signature(""));
        self.compose_to_entry.set_text("");
        self.compose_subject_entry.set_text("");
        // The To field is the one empty field — the "next logical
        // interaction point" this compose follows focus to (see
        // `candor_keyboard_navigation` in memory's passive/active rule).
        // This was the actual gap found live this session: nothing
        // here ever called `grab_focus()` at all before, so the design
        // intent was never really implemented.
        self.compose_to_entry.grab_focus();
        self.compose = Some(ComposeState {
            to: String::new(),
            subject: String::new(),
            in_reply_to: None,
            references: None,
            sending: false,
            kind: ComposeKind::New,
            attachments: Vec::new(),
            editing_draft: None,
            kb_origin: (self.kb_pane, self.kb_folder_index, self.kb_message_uid),
        });
    }

    /// Drops the reading pane's state *and* actually clears its
    /// `TextBuffer` content — not just hiding the pane. Dropping
    /// `self.reading` alone does not detach anything from GTK's side: a
    /// message with inline image placeholders embeds real widgets into
    /// `reading_text_view` via `TextChildAnchor`, and those stay attached
    /// (GTK holds its own reference) regardless of whether our own
    /// `ReadingPane` struct still exists. Confirmed live: just hiding
    /// that pane while switching to compose (so "Back" could return to
    /// the same message) still hung the whole app on Reply/Forward for a
    /// message with several embedded images — clearing the buffer
    /// up front, unconditionally, is what actually avoids that, at the
    /// cost of "Back" from a reply going to the inbox instead of back to
    /// the specific message.
    fn close_reading(&mut self) {
        self.reading = None;
        self.reading_body_buffer.set_text("");
    }

    fn open_reply(&mut self) {
        let Some(reading) = &self.reading else {
            return;
        };

        let subject = if reading.subject.to_ascii_lowercase().starts_with("re:") {
            reading.subject.clone()
        } else {
            format!("Re: {}", reading.subject)
        };

        let quoted = reading
            .body_text
            .as_deref()
            .unwrap_or("")
            .lines()
            .map(|line| format!("> {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = format!("\n\n{} wrote:\n{quoted}", reading.from);
        let to = reading.from.clone();
        let message_id = reading.message_id.clone();

        self.close_reading();
        self.compose_body_buffer.set_text(&self.with_signature(&body));
        self.compose_to_entry.set_text(&to);
        self.compose_subject_entry.set_text(&subject);
        // To is already filled in (it's a reply) — the body is the
        // next logical place to type, so focus follows there instead.
        self.compose_body_view.grab_focus();
        self.compose = Some(ComposeState {
            to,
            subject,
            in_reply_to: message_id.clone(),
            references: message_id,
            sending: false,
            kind: ComposeKind::Reply,
            attachments: Vec::new(),
            editing_draft: None,
            kb_origin: (self.kb_pane, self.kb_folder_index, self.kb_message_uid),
        });
    }

    /// Like `open_reply`, but addresses the original sender and every
    /// other `To`/`Cc` recipient — minus our own account address, so we
    /// don't end up emailing ourselves.
    fn open_reply_all(&mut self) {
        let Some(reading) = &self.reading else {
            return;
        };

        let subject = if reading.subject.to_ascii_lowercase().starts_with("re:") {
            reading.subject.clone()
        } else {
            format!("Re: {}", reading.subject)
        };

        let quoted = reading
            .body_text
            .as_deref()
            .unwrap_or("")
            .lines()
            .map(|line| format!("> {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = format!("\n\n{} wrote:\n{quoted}", reading.from);
        let to = reply_all_recipients(reading, self.configured_email.as_deref());
        let message_id = reading.message_id.clone();

        self.close_reading();
        self.compose_body_buffer.set_text(&self.with_signature(&body));
        self.compose_to_entry.set_text(&to);
        self.compose_subject_entry.set_text(&subject);
        // Same reasoning as `open_reply` — To is already filled in.
        self.compose_body_view.grab_focus();
        self.compose = Some(ComposeState {
            to,
            subject,
            in_reply_to: message_id.clone(),
            references: message_id,
            sending: false,
            kind: ComposeKind::ReplyAll,
            attachments: Vec::new(),
            editing_draft: None,
            kb_origin: (self.kb_pane, self.kb_folder_index, self.kb_message_uid),
        });
    }

    /// Forwards don't thread onto the original message (no
    /// `In-Reply-To`/`References`) — the recipient is a new conversation,
    /// not a reply to the sender.
    fn open_forward(&mut self) {
        let Some(reading) = &self.reading else {
            return;
        };

        let subject = if reading.subject.to_ascii_lowercase().starts_with("fwd:") {
            reading.subject.clone()
        } else {
            format!("Fwd: {}", reading.subject)
        };
        let body = format!(
            "\n\n---------- Forwarded message ----------\nFrom: {}\nSubject: {}\n\n{}",
            reading.from,
            reading.subject,
            reading.body_text.as_deref().unwrap_or(""),
        );

        self.close_reading();
        self.compose_body_buffer.set_text(&self.with_signature(&body));
        self.compose_to_entry.set_text("");
        self.compose_subject_entry.set_text(&subject);
        // To is the one empty field, same reasoning as `open_compose`.
        self.compose_to_entry.grab_focus();
        self.compose = Some(ComposeState {
            to: String::new(),
            subject,
            in_reply_to: None,
            references: None,
            sending: false,
            kind: ComposeKind::Forward,
            attachments: Vec::new(),
            editing_draft: None,
            kb_origin: (self.kb_pane, self.kb_folder_index, self.kb_message_uid),
        });
    }

    /// Opens a multi-file picker and appends whatever's picked to the
    /// open compose's attachment list; does nothing if the picker is
    /// cancelled or compose isn't open.
    /// "Import Contacts…" in Preferences — a one-time import, not a
    /// live sync (see `candor_group6_contacts_plan` in memory). File
    /// picking happens here (GUI), but the actual CSV read/parse/
    /// upsert happens daemon-side (`import_contacts_csv`'s D-Bus
    /// method) — consistent with every other write in this app going
    /// through the daemon rather than the GUI touching the database or
    /// the filesystem's contents directly.
    async fn import_contacts_csv(&mut self, root: &adw::ApplicationWindow) {
        let dialog = gtk::FileDialog::builder().title("Import Contacts").build();
        let Ok(file) = dialog.open_future(Some(root)).await else {
            return;
        };
        let Some(path) = file.path() else {
            return;
        };

        self.status = "Importing contacts…".to_string();
        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.import_contacts_csv(&path.display().to_string()).await
        }
        .await;

        self.status = match result {
            Ok((true, count)) => format!("Imported {count} contact(s)."),
            Ok((false, _)) => "No account configured.".to_string(),
            Err(e) => format!("Failed to import contacts: {e}"),
        };
    }

    async fn attach_file(&mut self, root: &adw::ApplicationWindow) {
        let dialog = gtk::FileDialog::builder().title("Attach Files").build();
        let Ok(files) = dialog.open_multiple_future(Some(root)).await else {
            return;
        };

        let mut paths = Vec::new();
        for i in 0..files.n_items() {
            if let Some(path) = files.item(i).and_then(|obj| obj.downcast::<gio::File>().ok()).and_then(|f| f.path())
            {
                paths.push(path);
            }
        }

        if let Some(compose) = self.compose.as_mut() {
            compose.attachments.extend(paths);
        }
    }

    /// Fetches attachment content fresh, over the network, only now —
    /// this is the one explicit action that ever lets attachment bytes
    /// exist at all, anywhere (see `body.rs`'s module doc comment on
    /// why opening a message to read it never does). The daemon does
    /// the actual fetch+write (it's the only thing that talks to IMAP);
    /// the GUI only picks the destination.
    async fn save_attachments(&mut self, root: &adw::ApplicationWindow) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        if reading.attachments.is_empty() {
            return;
        }
        let (folder, uid) = (reading.folder.clone(), reading.uid);

        let dialog = gtk::FileDialog::builder().title("Save Attachments To").build();
        let Ok(dest_folder) = dialog.select_folder_future(Some(root)).await else {
            return;
        };
        let Some(dest_dir) = dest_folder.path() else {
            return;
        };

        self.status = "Saving attachments…".to_string();

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.save_attachments(&folder, uid, &dest_dir.display().to_string()).await
        }
        .await;

        self.status = match result {
            Ok((true, count)) => format!("Saved {count} attachment(s)."),
            Ok((false, _)) => "No account configured.".to_string(),
            Err(e) => format!("Failed to save attachments: {e}"),
        };
    }

    /// The raw IMAP folder name tagged with a given RFC 6154 SPECIAL-USE
    /// attribute (e.g. `\Trash`), from the locally-synced folder list —
    /// same source the sidebar already reads from, no network round trip
    /// needed just to find a folder name.
    fn special_use_folder(&self, special_use: &str) -> Option<String> {
        let account_id = self.account_id.clone()?;
        let db = store::open().ok()?;
        let folders = store::list_folders(&db, &account_id).ok()?;
        folders.into_iter().find(|f| f.special_use.as_deref() == Some(special_use)).map(|f| f.name)
    }

    /// Whether `self.selected_folder` is the one tagged with this
    /// SPECIAL-USE attribute.
    fn current_folder_special_use(&self, special_use: &str) -> bool {
        self.selected_folder.is_some() && self.selected_folder == self.special_use_folder(special_use)
    }

    /// Whether the current folder is Drafts or Sent — neither really
    /// has a use for read/unread, star, or archive (you're not
    /// triaging your own outgoing mail the way you triage an inbox);
    /// drives which per-row/bulk actions show for `message_row.rs` and
    /// the bulk bar. Delete still applies to both.
    fn current_folder_restricted(&self) -> bool {
        self.current_folder_special_use("\\Drafts") || self.current_folder_special_use("\\Sent")
    }

    /// Moves one message (by folder+UID, not necessarily the one
    /// currently open) to whichever folder is tagged `special_use` —
    /// `\Trash` for delete, `\Archive` for archive. Gmail doesn't tag any
    /// folder `\Archive` at all (its equivalent is `\All`, "All Mail"),
    /// so archiving falls back to that when no `\Archive` folder exists.
    /// Shared by both the reading-pane actions and the message list's
    /// own per-row quick actions.
    async fn move_message_by_uid(&mut self, folder: &str, uid: u32, special_use: &str) {
        let target = self
            .special_use_folder(special_use)
            .or_else(|| (special_use == "\\Archive").then(|| self.special_use_folder("\\All")).flatten());
        let Some(target) = target else {
            self.status = "Couldn't find a folder for that action.".to_string();
            return;
        };

        self.status = "Moving message…".to_string();

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.move_message(folder, uid, &target).await
        }
        .await;

        match result {
            // `move_message` is local-only/instant now (see
            // `queue_move` on the daemon side) — it already removed
            // the row from this folder's local cache before returning,
            // so a cheap `reload()` is all that's needed to make the
            // list reflect it; the actual IMAP `MOVE` happens later,
            // unhurried, in the background.
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to move message: {e}"),
        }
    }

    /// Archives or deletes the currently-open message — closes the
    /// reading pane first, since the message just left the folder that's
    /// currently showing.
    async fn move_current_message(&mut self, special_use: &str) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let (uid, folder) = (reading.uid, reading.folder.clone());
        self.reading = None;
        self.move_message_by_uid(&folder, uid, special_use).await;
    }

    /// Archives or deletes a message straight from the list, without
    /// opening it first.
    async fn move_row(&mut self, uid: u32, special_use: &str) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        self.move_message_by_uid(&folder, uid, special_use).await;
    }

    /// Sets or clears a message's `\Seen` flag (by folder+UID). Shared by
    /// the reading-pane "Mark Unread" action and the list's per-row
    /// toggle.
    /// `mark_read`/`mark_unread` are local-only now (see
    /// `queue_flag_change` on the daemon side) — the D-Bus round trip
    /// here is just IPC to a method that writes to SQLite and returns,
    /// not a live IMAP `STORE`, so this resolves in well under a
    /// millisecond rather than the several seconds a real network
    /// round trip used to take. `reload()` (cheap, local-only) is
    /// enough to pick up the change; there's nothing server-side yet
    /// for a real `sync_now()` to catch up on.
    async fn set_seen_by_uid(&mut self, folder: &str, uid: u32, seen: bool) {
        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            if seen {
                proxy.mark_read(folder, uid).await
            } else {
                proxy.mark_unread(folder, uid).await
            }
        }
        .await;

        match result {
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to update read status: {e}"),
        }
    }

    /// Sets or clears a message's `\Flagged` (star) flag by folder+UID —
    /// same shape, and same local-only reasoning, as `set_seen_by_uid`.
    async fn set_flagged_by_uid(&mut self, folder: &str, uid: u32, flagged: bool) {
        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            if flagged {
                proxy.mark_flagged(folder, uid).await
            } else {
                proxy.mark_unflagged(folder, uid).await
            }
        }
        .await;

        match result {
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to update star: {e}"),
        }
    }

    /// The list's per-row star button — flips whichever state that row
    /// is currently showing.
    async fn toggle_row_flag(&mut self, uid: u32) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        let currently_flagged =
            self.messages.iter().find(|row| row.summary.uid == uid).map(|row| row.summary.flagged);
        let Some(currently_flagged) = currently_flagged else {
            return;
        };
        self.set_flagged_by_uid(&folder, uid, !currently_flagged).await;
    }

    /// The list's per-row "Schedule…" pop-out action.
    async fn schedule_row(&mut self, uid: u32, wake_at: i64) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.schedule_message(&folder, uid, wake_at).await
        }
        .await;

        match result {
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to schedule message: {e}"),
        }
    }

    /// Cancels a pending snooze from the "Snoozed" view — unlike every
    /// other row action in this app, `folder` comes from the row
    /// itself rather than `self.selected_folder`, since this view
    /// spans every folder at once.
    async fn unschedule_row(&mut self, folder: &str, uid: u32) {
        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.unschedule_message(folder, uid).await
        }
        .await;

        match result {
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to cancel schedule: {e}"),
        }
    }

    /// Clears the open message's `\Seen` flag and closes the reading pane
    /// — matches the point of marking something unread (come back to it
    /// later), which isn't really served by leaving it open right after.
    async fn mark_current_unread(&mut self) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let (uid, folder) = (reading.uid, reading.folder.clone());
        self.reading = None;
        self.set_seen_by_uid(&folder, uid, false).await;
    }

    /// Flips the open message's star — unlike "Mark Unread" this leaves
    /// the reading pane open, since starring isn't "I'm done with this,
    /// go back" the way marking unread is. Updates `self.reading` in
    /// place afterward so the badge reflects it immediately rather than
    /// waiting on the next resync.
    async fn toggle_current_flag(&mut self) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let (uid, folder, flagged) = (reading.uid, reading.folder.clone(), reading.flagged);
        self.set_flagged_by_uid(&folder, uid, !flagged).await;
        if let Some(reading) = self.reading.as_mut() {
            reading.flagged = !flagged;
        }
    }

    /// Re-queries contacts for whatever's typed after the last comma in
    /// `to` (the recipient currently being typed — `compose_to_entry`
    /// already supports multiple comma-separated recipients, and
    /// autocomplete only ever matches/replaces that trailing segment,
    /// never the already-finished ones before it) and rebuilds the
    /// popover from the results. An empty segment (nothing typed yet,
    /// or just finished one with a trailing comma) closes the popover
    /// rather than dumping every contact in the account on screen.
    fn update_contact_suggestions(&mut self, to: &str) {
        let segment = current_recipient_segment(to);
        self.contact_suggestions = if segment.is_empty() {
            Vec::new()
        } else {
            self.account_id
                .clone()
                .zip(store::open().ok())
                .and_then(|(account_id, db)| store::search_contacts(&db, &account_id, segment, 6).ok())
                .unwrap_or_default()
        };
        self.rebuild_contact_popover();
    }

    /// Rebuilds `contact_popover`'s contents from `contact_suggestions`
    /// and pops it open/closed to match — same "fully rebuild on every
    /// change, one button per item, plain click closures" pattern as
    /// `rebuild_move_to_menu`, chosen for the same reason: a handful of
    /// dynamic rows from a live query doesn't fit a static `view!` tree.
    fn rebuild_contact_popover(&mut self) {
        let list_box = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
        list_box.add_css_class("navigation-sidebar");

        let current_to = self.compose.as_ref().map(|c| c.to.clone()).unwrap_or_default();
        for contact in &self.contact_suggestions {
            let recipient = match contact.name.as_deref() {
                Some(name) if !name.is_empty() => format!("{name} <{}>", contact.address),
                _ => contact.address.clone(),
            };
            let button = gtk::Button::builder().label(&recipient).has_frame(false).build();

            let entry = self.compose_to_entry.clone();
            let popover = self.contact_popover.clone();
            let current_to = current_to.clone();
            let recipient_for_insert = recipient.clone();
            button.connect_clicked(move |_| {
                let new_to = replace_last_recipient_segment(&current_to, &recipient_for_insert);
                entry.set_text(&new_to);
                entry.set_position(-1);
                entry.grab_focus();
                popover.popdown();
            });
            list_box.append(&button);
        }

        self.contact_popover.set_child(Some(&list_box));
        if self.contact_suggestions.is_empty() {
            self.contact_popover.popdown();
        } else {
            self.contact_popover.popup();
        }
    }

    /// The reading pane's opt-in "Add to contacts" button
    /// (`Msg::AddContact`) — adds the open message's sender. No
    /// confirmation dialog, no visible change beyond the status line:
    /// the whole point, per the user's own framing, is that this is a
    /// "click this if you want, or just ignore it" affordance, not a
    /// decision the app interrupts anything to ask about.
    async fn add_contact(&mut self) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let (address, name) = (reading.from.clone(), reading.from_name.clone().unwrap_or_default());

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.add_contact(&address, &name, "manual").await
        }
        .await;

        self.status = match result {
            Ok(true) => format!("Added {address} to contacts."),
            Ok(false) => "No account configured.".to_string(),
            Err(e) => format!("Failed to add contact: {e}"),
        };
    }

    /// "Move to…" — moves the open message to an explicit folder chosen
    /// from `rebuild_move_to_menu`'s popover, bypassing the special-use
    /// resolution `move_message_by_uid` does for Archive/Trash (there's
    /// no ambiguity to resolve: the target folder's raw name was picked
    /// directly from the live folder list).
    async fn move_current_message_to_folder(&mut self, target: String) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let (uid, folder) = (reading.uid, reading.folder.clone());
        self.reading = None;
        self.status = "Moving message…".to_string();

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.move_message(&folder, uid, &target).await
        }
        .await;

        match result {
            // Local-only/instant, same reasoning as `move_message_by_uid`.
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to move message: {e}"),
        }
    }

    /// "Schedule…" on the open message — closes the reading pane since
    /// a snoozed message isn't visible anywhere until it wakes (see
    /// `store::snooze_message`'s doc comment), the same way archiving
    /// or deleting the current message does.
    async fn schedule_current_message(&mut self, wake_at: i64) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let (uid, folder) = (reading.uid, reading.folder.clone());
        self.reading = None;

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.schedule_message(&folder, uid, wake_at).await
        }
        .await;

        match result {
            Ok(true) => self.reload(),
            Ok(false) => self.status = "No account configured.".to_string(),
            Err(e) => self.status = format!("Failed to schedule message: {e}"),
        }
    }

    /// Schedules every selected message for the same wake time, then
    /// clears the selection — same shape as the other bulk actions.
    async fn bulk_schedule(&mut self, wake_at: i64) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        let uids: Vec<u32> = self.selected_uids.iter().copied().collect();

        // One connection and one `reload()` for the whole batch, not
        // one of each per message — see `bulk_mark_toggle`'s doc
        // comment for why that distinction actually matters now that
        // these calls are fast (confirmed live: 200+ messages with a
        // fresh connection and a full list rebuild after literally
        // every single one made a bulk action feel like it was
        // grinding through them one at a time, which it genuinely was).
        let result: zbus::Result<()> = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            for &uid in &uids {
                proxy.schedule_message(&folder, uid, wake_at).await?;
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            self.status = format!("Failed to schedule messages: {e}");
        }

        self.selected_uids.clear();
        self.sync_row_selection_flags();
        self.reload();
    }

    /// Rebuilds the "Move to…" popover from the current folder list —
    /// called whenever `self.folders` changes (end of `reload`). Plain
    /// buttons with per-folder click closures, same pattern as every
    /// other per-item action in this app, rather than a `gio::Menu` +
    /// action group.
    fn rebuild_move_to_menu(&mut self) {
        let list_box = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
        list_box.add_css_class("navigation-sidebar");

        let popover = gtk::Popover::new();
        popover.set_child(Some(&list_box));

        for folder in self.folders.iter() {
            let raw_name = folder.raw_name.clone();
            let button = gtk::Button::builder().label(&raw_name).has_frame(false).build();
            let input_sender = self.input_sender.clone();
            let popover_for_click = popover.clone();
            button.connect_clicked(move |_| {
                let _ = input_sender.send(Msg::MoveToFolder(raw_name.clone()));
                popover_for_click.popdown();
            });
            list_box.append(&button);
        }

        self.move_to_menu_button.set_popover(Some(&popover));
    }

    /// The list's per-row "toggle unread" button — flips whichever state
    /// that row is currently showing, unlike the reading pane's version
    /// (which only ever marks unread, since a message being *open* only
    /// makes sense to flip one direction).
    async fn toggle_row_unread(&mut self, uid: u32) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        let currently_seen =
            self.messages.iter().find(|row| row.summary.uid == uid).map(|row| row.summary.seen);
        let Some(currently_seen) = currently_seen else {
            return;
        };
        self.set_seen_by_uid(&folder, uid, !currently_seen).await;
    }

    /// Pushes `selected_uids` down into each row's own `selected`/
    /// `revealed` fields — the only place that decides `revealed` is
    /// here, since it depends on the *total* selection count
    /// (`settings.bulk_select_threshold`), not anything a single row can know on
    /// its own — and also `restricted`, for the same reason: no row
    /// knows which folder it's in, only `AppModel` does. Call this
    /// after every change to `selected_uids`, and `reload()` always
    /// does regardless (a folder switch needs `restricted` re-synced
    /// even with the selection untouched).
    fn sync_row_selection_flags(&mut self) {
        // A fresh empty selection is never "keyboard mode" until X
        // actually says so again — catches every path that can empty
        // `selected_uids` (clear, a completed bulk action, a plain
        // click) in one place instead of resetting it at each one.
        if self.selected_uids.is_empty() {
            self.kb_select_mode = false;
        }
        let bulk_active = self.selected_uids.len() >= self.settings.bulk_select_threshold;
        let restricted = self.current_folder_restricted();
        let mut guard = self.messages.guard();
        for i in 0..guard.len() {
            let Some(row) = guard.get_mut(i) else { continue };
            let is_selected = self.selected_uids.contains(&row.summary.uid);
            row.selected = is_selected;
            // A selection built with X never reveals the per-row
            // icon pop-out either, same reasoning as the bulk bar
            // below — those icons exist for a mouse, and the whole
            // point of selecting with the keyboard is not reaching
            // for one.
            row.revealed = is_selected && !bulk_active && !self.kb_select_mode;
            row.restricted = restricted;
        }
    }

    /// Same reasoning as `sync_row_selection_flags`, for the separate
    /// keyboard-cursor concept instead of the bulk-select one — only
    /// `AppModel` knows `kb_pane`/`kb_folder_index`/`kb_message_uid`,
    /// no single row can. Call after any change to that state, and
    /// from `reload()` (a rebuild otherwise loses it).
    fn sync_keyboard_focus_flags(&mut self) {
        let folders_focused = self.kb_pane == KeyboardPane::Folders;
        let messages_focused = self.kb_pane == KeyboardPane::Messages;
        let flash = self.kb_flash;

        let mut folders = self.folders.guard();
        for i in 0..folders.len() {
            let Some(row) = folders.get_mut(i) else { continue };
            let focused = folders_focused && i == self.kb_folder_index;
            row.kb_focused = focused;
            row.kb_flash = focused && flash;
        }
        drop(folders);

        let mut messages = self.messages.guard();
        for i in 0..messages.len() {
            let Some(row) = messages.get_mut(i) else { continue };
            let focused = messages_focused && Some(row.summary.uid) == self.kb_message_uid;
            row.kb_focused = focused;
            row.kb_flash = focused && flash;
        }
    }

    /// How long the one-shot "you just landed here" flash lasts before
    /// easing back down to the quieter resting `.kb-focused` look.
    const KB_FLASH_MILLIS: u64 = 750;

    /// Switches which pane the keyboard cursor is in (Ctrl+1/2/3) and
    /// triggers the landing flash. Reading is refused when nothing's
    /// open — there's nothing there to land on (see the controller's
    /// doc comment in the view! macro); j/k and Enter already never
    /// send a message that would get here in that case from the inbox
    /// side, but a stray Ctrl+3 should still just do nothing rather
    /// than focus an empty pane.
    fn set_kb_pane(&mut self, pane: KeyboardPane) {
        if pane == KeyboardPane::Reading && self.reading.is_none() {
            return;
        }
        self.kb_pane = pane;
        self.schedule_kb_flash();
    }

    fn schedule_kb_flash(&mut self) {
        self.kb_flash = true;
        self.kb_flash_generation += 1;
        let generation = self.kb_flash_generation;
        self.sync_keyboard_focus_flags();
        let input_sender = self.input_sender.clone();
        glib::timeout_add_local_once(
            std::time::Duration::from_millis(Self::KB_FLASH_MILLIS),
            move || {
                let _ = input_sender.send(Msg::KbFlashEnd(generation));
            },
        );
    }

    /// Restores keyboard focus to wherever it was before compose opened
    /// (`ComposeState::kb_origin`) — the message replied/forwarded from,
    /// the row `C` was pressed on, or just the folder pane for a blank
    /// compose started from there. The reading pane itself is already
    /// closed by the time this runs (`close_reading` happens on every
    /// compose-opening path), so there's nothing left in pane 3 to
    /// return to even if that's where the origin pane was — landing
    /// back on the list (or, if the target message is gone too, the
    /// folder pane) covers both cases the same way. Confirmed
    /// explicitly: an edited draft that gets deleted and leaves nothing
    /// to land on should fall back to the folder pane, not point at
    /// nothing.
    fn kb_restore_origin(&mut self, origin: (KeyboardPane, usize, Option<u32>)) {
        let (pane, folder_index, message_uid) = origin;
        self.kb_folder_index = folder_index;
        let still_exists =
            message_uid.is_some_and(|uid| self.messages.iter().any(|row| row.summary.uid == uid));
        match pane {
            KeyboardPane::Folders => self.kb_pane = KeyboardPane::Folders,
            KeyboardPane::Messages | KeyboardPane::Reading => {
                if still_exists {
                    self.kb_message_uid = message_uid;
                    self.kb_pane = KeyboardPane::Messages;
                } else {
                    self.kb_pane = KeyboardPane::Folders;
                }
            }
        }
        self.schedule_kb_flash();
    }

    /// j/k within whichever pane currently has the keyboard cursor —
    /// moves the folder/message cursor by one row, or (pane 3) scrolls
    /// the open message, never jumping panes on its own. `delta` is
    /// `-1` for k (up) or `1` for j (down).
    fn kb_move(&mut self, delta: i32) {
        match self.kb_pane {
            KeyboardPane::Folders => {
                let len = self.folders.len();
                if len == 0 {
                    return;
                }
                let next = (self.kb_folder_index.min(len - 1) as i32 + delta).clamp(0, len as i32 - 1);
                self.kb_folder_index = next as usize;
                self.sync_keyboard_focus_flags();
            }
            KeyboardPane::Messages => {
                let len = self.messages.len();
                if len == 0 {
                    return;
                }
                let current = self.kb_message_uid.and_then(|uid| {
                    (0..len).find(|&i| self.messages.get(i).is_some_and(|r| r.summary.uid == uid))
                });
                // No prior cursor position — j or k either one just
                // lands on the top row rather than skipping past it by
                // applying `delta` to an assumed starting point.
                let next = match current {
                    Some(i) => (i as i32 + delta).clamp(0, len as i32 - 1) as usize,
                    None => 0,
                };
                self.kb_message_uid = self.messages.get(next).map(|row| row.summary.uid);
                self.sync_keyboard_focus_flags();
            }
            KeyboardPane::Reading => self.scroll_reading_pane(delta),
        }
    }

    fn scroll_reading_pane(&self, delta: i32) {
        const STEP: f64 = 60.0;
        let Some(scrolled) = self
            .reading_text_view
            .ancestor(gtk::ScrolledWindow::static_type())
            .and_then(|w| w.downcast::<gtk::ScrolledWindow>().ok())
        else {
            return;
        };
        let adj = scrolled.vadjustment();
        let max = (adj.upper() - adj.page_size()).max(adj.lower());
        let next = (adj.value() + delta as f64 * STEP).clamp(adj.lower(), max);
        adj.set_value(next);
    }

    /// Enter on whichever pane currently has the keyboard cursor —
    /// opens the focused folder or message exactly like clicking it
    /// would (including staying in the same pane afterward: opening
    /// something to view it is passive, same reasoning as the click
    /// path). Reading pane has nothing to activate.
    async fn kb_activate(&mut self, root: &adw::ApplicationWindow) {
        match self.kb_pane {
            KeyboardPane::Folders => {
                if let Some(folder) = self.folders.get(self.kb_folder_index) {
                    self.selected_folder = Some(folder.raw_name.clone());
                    self.viewing_snoozed = false;
                    self.reload();
                }
            }
            KeyboardPane::Messages => {
                if let Some(uid) = self.kb_message_uid {
                    if self.current_folder_special_use("\\Drafts") {
                        self.resume_draft(uid).await;
                    } else {
                        self.open_message(uid, root).await;
                    }
                }
            }
            KeyboardPane::Reading => {}
        }
    }

    /// Which message an action key acts on — the one open in the
    /// reading pane, or the row the list cursor is on, whichever pane
    /// currently has the keyboard. No message in the folders pane.
    fn kb_target_uid(&self) -> Option<u32> {
        match self.kb_pane {
            KeyboardPane::Messages => self.kb_message_uid,
            KeyboardPane::Reading => self.reading.as_ref().map(|r| r.uid),
            KeyboardPane::Folders => None,
        }
    }

    /// Where the keyboard cursor should land once `removed_uid` is
    /// gone from the list — the message before it in list order, or
    /// (if it was first) the new first one, or `None` if the list is
    /// now empty. Must be called *before* the removal actually
    /// happens, while `removed_uid` can still be found.
    ///
    /// Confirmed explicitly, verbatim: "say you have 30 messages and
    /// slid down 10 and archived that one your focus should shift to
    /// the message before the one you archived" — not whatever slides
    /// up to fill the gap.
    fn kb_fallback_after_removal(&self, removed_uid: u32) -> Option<u32> {
        let index = self.messages.iter().position(|row| row.summary.uid == removed_uid)?;
        if index > 0 {
            self.messages.get(index - 1).map(|row| row.summary.uid)
        } else {
            self.messages.get(1).map(|row| row.summary.uid)
        }
    }

    /// Shared by `kb_archive`/`kb_delete` — both remove the target row
    /// from the list, so both need the same "land on the previous
    /// message, close the reading pane if it was showing this one,
    /// fall back to the folder pane if the list is now empty" handling
    /// afterward.
    async fn kb_remove_target(&mut self, special_use: &str) {
        // A keyboard-built selection wins over the single focused
        // target — reuses the exact same batched method the bulk bar's
        // Archive/Delete buttons call, so it stays in sync with that
        // UI's own behavior (including clearing the selection after).
        if !self.selected_uids.is_empty() {
            self.bulk_move(special_use).await;
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        let fallback = self.kb_fallback_after_removal(uid);
        if self.reading.as_ref().is_some_and(|r| r.uid == uid) {
            self.move_current_message(special_use).await;
        } else {
            self.move_row(uid, special_use).await;
        }
        self.kb_pane = KeyboardPane::Messages;
        self.kb_message_uid = fallback;
        self.sync_keyboard_focus_flags();
    }

    async fn kb_archive(&mut self) {
        if self.current_folder_restricted() {
            return;
        }
        self.kb_remove_target("\\Archive").await;
    }

    /// Delete stays available even in Drafts/Sent — same exception the
    /// per-row pop-out and reading pane already make.
    async fn kb_delete(&mut self) {
        self.kb_remove_target("\\Trash").await;
    }

    /// Reuses whichever existing toggle already has the right shape for
    /// the target: `mark_current_unread` for the open reading-pane
    /// message — it's one-directional and closes the pane, since there
    /// not being a `seen` field on `ReadingPane` to flip in place is
    /// itself the tell that "toggling" an *open* message's unread state
    /// was never a real concept here, only "mark unread and go back"
    /// was — or `toggle_row_unread` for a merely-focused row, which
    /// does toggle both ways. Marking unread doesn't remove the row
    /// from the list (passive — see point 2 of the interaction design:
    /// "we don't expect the email to go anywhere, we just expect it to
    /// change shape"), so the cursor stays on the same message, just
    /// normalized back to the list pane since pane 3 just closed.
    async fn kb_toggle_unread(&mut self) {
        if self.current_folder_restricted() {
            return;
        }
        if !self.selected_uids.is_empty() {
            self.bulk_mark_toggle().await;
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        if self.reading.as_ref().is_some_and(|r| r.uid == uid) {
            self.mark_current_unread().await;
            self.kb_pane = KeyboardPane::Messages;
            self.kb_message_uid = Some(uid);
            self.sync_keyboard_focus_flags();
        } else {
            self.toggle_row_unread(uid).await;
        }
    }

    /// Starring is passive either way — neither `toggle_current_flag`
    /// nor `toggle_row_flag` move or close anything, so no cursor
    /// follow-up is needed here at all.
    async fn kb_toggle_flag(&mut self) {
        if self.current_folder_restricted() {
            return;
        }
        if !self.selected_uids.is_empty() {
            self.bulk_flag_toggle().await;
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        if self.reading.as_ref().is_some_and(|r| r.uid == uid) {
            self.toggle_current_flag().await;
        } else {
            self.toggle_row_flag(uid).await;
        }
    }

    /// Reply/Reply All/Forward need the message's body loaded to quote
    /// it, so unlike a plain Enter (passive — see `kb_activate`), these
    /// *do* open it first if it isn't already — then follow straight
    /// into compose, the active-transition rule confirmed explicitly:
    /// "if we expect further interaction with the email then we need
    /// to follow it and be ready at the next logical interaction
    /// point." Exactly what the existing per-row Reply/Forward pop-out
    /// buttons already do (`Msg::ReplyRow`/`Msg::ForwardRow`) — these
    /// just add the Reply All case and hang off a key instead.
    async fn kb_reply(&mut self, root: &adw::ApplicationWindow) {
        if self.current_folder_restricted() {
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        self.open_message(uid, root).await;
        self.open_reply();
    }

    async fn kb_reply_all(&mut self, root: &adw::ApplicationWindow) {
        if self.current_folder_restricted() {
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        self.open_message(uid, root).await;
        self.open_reply_all();
    }

    async fn kb_forward(&mut self, root: &adw::ApplicationWindow) {
        if self.current_folder_restricted() {
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        self.open_message(uid, root).await;
        self.open_forward();
    }

    /// Schedule and Move-to are themselves a pick-one-of-several
    /// sub-choice, so "the next logical interaction point" is the
    /// popover itself, not any specific option in it — confirmed that
    /// opening it via `popup()` is enough, no extra focus-forcing
    /// needed: GTK already moves keyboard focus onto the popover's
    /// first row the instant it opens (confirmed directly, a standalone
    /// test), so arrow keys and Enter work immediately with no mouse
    /// involved at any point.
    async fn kb_schedule(&mut self, root: &adw::ApplicationWindow) {
        if self.current_folder_restricted() {
            return;
        }
        if !self.selected_uids.is_empty() {
            self.schedule_bulk_menu_button.popup();
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        if !self.reading.as_ref().is_some_and(|r| r.uid == uid) {
            self.open_message(uid, root).await;
        }
        self.schedule_current_menu_button.popup();
    }

    async fn kb_move_to_folder(&mut self, root: &adw::ApplicationWindow) {
        if self.current_folder_restricted() {
            return;
        }
        // No bulk "move to an arbitrary folder" exists (only Archive/
        // Trash do, via `bulk_move`) — refusing outright with a
        // selection active is safer than moving just the one row under
        // the keyboard cursor while the selection sits there implying
        // the whole batch was meant.
        if !self.selected_uids.is_empty() {
            return;
        }
        let Some(uid) = self.kb_target_uid() else { return };
        if !self.reading.as_ref().is_some_and(|r| r.uid == uid) {
            self.open_message(uid, root).await;
        }
        self.move_to_menu_button.popup();
    }

    fn toggle_row_select(&mut self, uid: u32) {
        // An explicit click always wins over the passive hover timer —
        // without this, selecting a 2nd/3rd row while the mouse happens
        // to be mid-countdown from a previous moment could still fire
        // underneath the new selection a moment later.
        self.cancel_hover_deselect();
        if !self.selected_uids.remove(&uid) {
            self.selected_uids.insert(uid);
        }
        // An explicit click is the mouse taking over, same as any
        // other click already implicitly does for keyboard focus (see
        // `Msg::SelectFolderIndex`/`Msg::OpenMessageIndex`) — the bulk
        // bar and per-row pop-out go back to normal from here.
        self.kb_select_mode = false;
        self.sync_row_selection_flags();
    }

    /// `X` on the focused row — the keyboard equivalent of clicking its
    /// select circle, for batching up several messages before one bulk
    /// action key instead of handling them one at a time (the other,
    /// equally real, keyboard workflow — confirmed explicitly after
    /// asking which one real keyboard users actually want: both, for
    /// different situations). Sets `kb_select_mode`, which is what
    /// keeps the mouse-only bulk bar and per-row pop-out from popping
    /// up over a selection nobody's about to reach for a mouse to use.
    fn kb_toggle_select(&mut self) {
        if self.kb_pane != KeyboardPane::Messages {
            return;
        }
        let Some(uid) = self.kb_message_uid else { return };
        self.cancel_hover_deselect();
        if !self.selected_uids.remove(&uid) {
            self.selected_uids.insert(uid);
        }
        self.kb_select_mode = true;
        self.sync_row_selection_flags();
    }

    fn clear_selection(&mut self) {
        self.cancel_hover_deselect();
        self.selected_uids.clear();
        self.sync_row_selection_flags();
    }

    /// Selects every message currently in the list, or clears the
    /// selection if everything's already selected — the usual toggle
    /// convention for a "select all" control.
    fn toggle_select_all(&mut self) {
        self.cancel_hover_deselect();
        let all_uids: std::collections::BTreeSet<u32> =
            self.messages.iter().map(|row| row.summary.uid).collect();
        if !all_uids.is_empty() && self.selected_uids == all_uids {
            self.selected_uids.clear();
        } else {
            self.selected_uids = all_uids;
        }
        self.sync_row_selection_flags();
    }

    /// How long the mouse has to sit off of every currently-selected
    /// row before the selection (and whichever per-row pop-out that
    /// implies) clears itself — long enough that moving the mouse to,
    /// say, click something else nearby doesn't accidentally eat the
    /// selection, short enough that it doesn't feel like it's stuck
    /// open forever.
    const HOVER_DESELECT_SECONDS: u32 = 2;

    /// A selected row just gained the mouse — cancels any pending
    /// auto-deselect, the same way clicking anything explicitly would.
    /// Ignored for a row that isn't actually selected (every row sends
    /// this unconditionally; it has no way to know its own selection
    /// state is irrelevant here).
    fn row_hover_enter(&mut self, uid: u32) {
        if !self.selected_uids.contains(&uid) {
            return;
        }
        self.hovered_selected.insert(uid);
        self.cancel_hover_deselect();
    }

    /// A selected row just lost the mouse — starts the countdown only
    /// once *every* selected row has lost it too (see
    /// `hovered_selected`'s doc comment), and never above
    /// `settings.bulk_select_threshold`: this behavior is purely about the
    /// per-row pop-out, which the bulk bar replaces entirely past that
    /// point.
    fn row_hover_leave(&mut self, uid: u32) {
        if !self.selected_uids.contains(&uid) {
            return;
        }
        self.hovered_selected.remove(&uid);
        // A keyboard-built selection must never auto-expire — there's
        // no mouse hovering it to begin with, so "nothing's hovered"
        // would otherwise arm this on every single `X` press.
        // Confirmed explicitly: letting a keyboard selection quietly
        // vanish on its own "would also be bad."
        if self.hovered_selected.is_empty()
            && !self.selected_uids.is_empty()
            && self.selected_uids.len() < self.settings.bulk_select_threshold
            && !self.kb_select_mode
        {
            self.schedule_hover_deselect();
        }
    }

    fn schedule_hover_deselect(&mut self) {
        self.hover_deselect_generation += 1;
        let generation = self.hover_deselect_generation;
        let input_sender = self.input_sender.clone();
        glib::timeout_add_seconds_local(Self::HOVER_DESELECT_SECONDS, move || {
            let _ = input_sender.send(Msg::HoverDeselectTimeout(generation));
            glib::ControlFlow::Break
        });
    }

    /// Invalidates any pending auto-deselect timer without needing to
    /// touch a `glib::SourceId` at all — see `kb_flash_generation`'s
    /// doc comment for why this codebase no longer cancels a timer by
    /// calling `.remove()` on one that might have already fired.
    fn cancel_hover_deselect(&mut self) {
        self.hover_deselect_generation += 1;
    }

    fn hover_deselect_timeout(&mut self, generation: u64) {
        if generation != self.hover_deselect_generation {
            return;
        }
        // Re-check rather than assume: a hover-enter in between
        // scheduling this and it firing already bumps the generation
        // above and returns early, but this is cheap insurance against
        // clearing a selection the mouse has in fact wandered back onto.
        if self.hovered_selected.is_empty() && self.selected_uids.len() < self.settings.bulk_select_threshold {
            self.selected_uids.clear();
            self.sync_row_selection_flags();
        }
    }

    /// `Some(true)`/`Some(false)` if every selected row's `seen` agrees,
    /// `None` if the selection is a mix of read and unread — drives
    /// which single button the bulk bar shows for this action (see
    /// `bulk_mark_target`) and whether clicking it should auto-clear
    /// the selection afterward (see `bulk_mark_toggle`).
    fn selected_seen_uniform(&self) -> Option<bool> {
        let mut seen_values =
            self.messages.iter().filter(|r| self.selected_uids.contains(&r.summary.uid)).map(|r| r.summary.seen);
        let first = seen_values.next()?;
        seen_values.all(|v| v == first).then_some(first)
    }

    /// Same as `selected_seen_uniform`, for `flagged` (star) instead.
    fn selected_flagged_uniform(&self) -> Option<bool> {
        let mut flagged_values = self
            .messages
            .iter()
            .filter(|r| self.selected_uids.contains(&r.summary.uid))
            .map(|r| r.summary.flagged);
        let first = flagged_values.next()?;
        flagged_values.all(|v| v == first).then_some(first)
    }

    /// Marks every selected message read or unread — whichever the
    /// single merged button was showing when clicked (see
    /// `bulk_mark_target`). A uniform selection (all read, or all
    /// unread) clears itself afterward, same "done" convention as
    /// archive/delete/schedule; a mixed one deliberately doesn't, so
    /// the result stays visible (the button updates to reflect the new,
    /// now-uniform state) until the user closes it themselves — a
    /// silent auto-close right after resolving an ambiguous mixed batch
    /// would hide the one moment that's actually worth confirming.
    /// One connection, one loop, one `reload()` for the whole selection
    /// — not `set_seen_by_uid` called once per message. That helper's
    /// own connect-then-reload shape is fine for a single click, but
    /// looping it over a large selection meant opening a fresh D-Bus
    /// connection *and* fully rebuilding the entire message list from
    /// SQLite after every individual message — confirmed live that
    /// unstarring 200+ messages in Junk this way took long enough to
    /// look like it had hung, even though each underlying write is
    /// itself fast (local-only, no network — see `queue_flag_change`
    /// on the daemon side). The actual bottleneck was never the write;
    /// it was redoing all of that setup 200 times over.
    async fn bulk_mark_toggle(&mut self) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        let was_uniform = self.selected_seen_uniform().is_some();
        let target = bulk_mark_target(self);
        let uids: Vec<u32> = self.selected_uids.iter().copied().collect();

        let result: zbus::Result<()> = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            for &uid in &uids {
                if target {
                    proxy.mark_read(&folder, uid).await?;
                } else {
                    proxy.mark_unread(&folder, uid).await?;
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            self.status = format!("Failed to update read status: {e}");
        }

        if was_uniform {
            self.selected_uids.clear();
        }
        self.sync_row_selection_flags();
        self.reload();
    }

    /// Stars or unstars every selected message — same batched shape,
    /// same reasoning, as `bulk_mark_toggle`.
    async fn bulk_flag_toggle(&mut self) {
        let Some(folder) = self.selected_folder.clone() else {
            return;
        };
        let was_uniform = self.selected_flagged_uniform().is_some();
        let target = bulk_flag_target(self);
        let uids: Vec<u32> = self.selected_uids.iter().copied().collect();

        let result: zbus::Result<()> = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            for &uid in &uids {
                if target {
                    proxy.mark_flagged(&folder, uid).await?;
                } else {
                    proxy.mark_unflagged(&folder, uid).await?;
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            self.status = format!("Failed to update star: {e}");
        }

        if was_uniform {
            self.selected_uids.clear();
        }
        self.sync_row_selection_flags();
        self.reload();
    }

    /// Archives, deletes, or moves every selected message — same
    /// batched shape, same reasoning, as `bulk_mark_toggle`. The target
    /// folder only needs resolving once (every message in the batch is
    /// going to the same place), not once per message.
    async fn bulk_move(&mut self, special_use: &str) {
        let Some(from_folder) = self.selected_folder.clone() else {
            return;
        };
        let target = self
            .special_use_folder(special_use)
            .or_else(|| (special_use == "\\Archive").then(|| self.special_use_folder("\\All")).flatten());
        let Some(target) = target else {
            self.status = "Couldn't find a folder for that action.".to_string();
            return;
        };
        let uids: Vec<u32> = self.selected_uids.iter().copied().collect();

        let result: zbus::Result<()> = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            for &uid in &uids {
                proxy.move_message(&from_folder, uid, &target).await?;
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            self.status = format!("Failed to move messages: {e}");
        }

        self.selected_uids.clear();
        self.sync_row_selection_flags();
        self.reload();
    }

    /// Loads every blocked image in the open message at once, reusing
    /// the exact same per-image fetch+swap path a single click would
    /// use — just with one combined confirmation (if any are suspected
    /// trackers) instead of one dialog per tracker image.
    async fn show_all_images(&mut self, root: &adw::ApplicationWindow) {
        let Some(reading) = self.reading.as_ref() else {
            return;
        };
        let images = reading.pending_images.clone();
        if images.is_empty() {
            return;
        }

        let tracker_count = images.iter().filter(|(_, _, is_tracker)| *is_tracker).count();
        if tracker_count > 0 {
            let detail = if tracker_count == images.len() {
                format!(
                    "All {} image(s) in this message look like tracking pixels. Loading them \
                    tells the sender you opened this message. Load them anyway?",
                    images.len()
                )
            } else {
                format!(
                    "{tracker_count} of {} image(s) in this message look like tracking pixels. \
                    Loading them tells the sender you opened this message. Load all images \
                    anyway?",
                    images.len()
                )
            };
            let dialog = gtk::AlertDialog::builder()
                .modal(true)
                .message("Load all images?")
                .detail(detail)
                .buttons(["Cancel", "Load All"])
                .cancel_button(0)
                .default_button(0)
                .build();
            if !matches!(dialog.choose_future(Some(root)).await, Ok(1)) {
                return;
            }
        }

        for (container, src, _) in images {
            glib::spawn_future_local(fetch_and_show_image(container, src));
        }
        if let Some(reading) = self.reading.as_mut() {
            reading.pending_images.clear();
        }
    }

    async fn send_compose(&mut self) {
        let Some((to, subject, in_reply_to, references, attachments, kind)) = self.compose.as_ref().map(|c| {
            (
                c.to.clone(),
                c.subject.clone(),
                c.in_reply_to.clone(),
                c.references.clone(),
                c.attachments.clone(),
                c.kind,
            )
        }) else {
            return;
        };
        let start = self.compose_body_buffer.start_iter();
        let end = self.compose_body_buffer.end_iter();
        let body = self.compose_body_buffer.text(&start, &end, false).to_string();

        if let Some(compose) = self.compose.as_mut() {
            compose.sending = true;
        }
        self.status = "Sending…".to_string();

        let attachment_paths: Vec<String> =
            attachments.iter().map(|p| p.display().to_string()).collect();

        // Generated once, here, rather than left for the daemon to
        // generate inside `send::build_message` as it used to — this
        // exact string is what `cache_sent_body` below keys the cache
        // row under, and there'd be no way to recover it afterward
        // otherwise (see `OutgoingMessage::message_id`'s doc comment).
        let message_id =
            candor_core::send::generate_message_id(self.configured_email.as_deref().unwrap_or(""));

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy
                .send_message(
                    &to,
                    &subject,
                    &body,
                    in_reply_to.as_deref().unwrap_or(""),
                    references.as_deref().unwrap_or(""),
                    attachment_paths,
                    &message_id,
                )
                .await
        }
        .await;

        match result {
            Ok(()) => {
                self.status = "Message sent.".to_string();
                self.contact_popover.popdown();
                self.contact_suggestions.clear();
                // Same reasoning as `backout_of_compose`: sending a
                // draft that was being edited supersedes the old saved
                // copy, which would otherwise just sit in Drafts
                // forever since nothing else ever cleans it up. Backgrounded
                // for the same reason too — the send already completed and
                // the user's done waiting; there's nothing left here worth
                // blocking the UI over.
                let taken = self.compose.take();
                if let Some(origin) = taken.as_ref().map(|c| c.kb_origin) {
                    self.kb_restore_origin(origin);
                }
                let editing_draft = taken.and_then(|c| c.editing_draft);
                if let Some((folder, uid)) = editing_draft {
                    let input_sender = self.input_sender.clone();
                    glib::spawn_future_local(async move {
                        if let Ok(conn) = zbus::Connection::session().await {
                            if let Ok(proxy) = DaemonProxy::new(&conn).await {
                                let _ = proxy.move_message(&folder, uid, "\\Trash").await;
                            }
                        }
                        let _ = input_sender.send(Msg::Refresh);
                    });
                }

                // Cache the body we just sent — exempt from retention
                // forever, same as starring (see `message_bodies`'s
                // caching policy). Zero network cost: we already have
                // the exact text in hand, nothing to fetch back. Not
                // done for Forward — the user's caching policy named
                // new compose/Reply/Reply All specifically, not
                // Forward, and this isn't the place to assume it in.
                // Sent-mail contact auto-harvest — only when every
                // recipient was typed from scratch by the user
                // (New/Forward both start with an empty To field),
                // never Reply/Reply All, whose recipients are
                // pre-filled from the original message, not chosen.
                // See `candor_group6_contacts_plan` in memory for why
                // Reply/Reply All were deliberately left out.
                if matches!(kind, ComposeKind::New | ComposeKind::Forward) {
                    let recipients = split_recipients(&to);
                    glib::spawn_future_local(async move {
                        if let Ok(conn) = zbus::Connection::session().await {
                            if let Ok(proxy) = DaemonProxy::new(&conn).await {
                                for (name, address) in recipients {
                                    let _ = proxy
                                        .add_contact(&address, name.as_deref().unwrap_or(""), "sent")
                                        .await;
                                }
                            }
                        }
                    });
                }

                if !matches!(kind, ComposeKind::Forward) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    glib::spawn_future_local(async move {
                        if let Ok(conn) = zbus::Connection::session().await {
                            if let Ok(proxy) = DaemonProxy::new(&conn).await {
                                let _ = proxy.cache_sent_body(&message_id, &body, now).await;
                            }
                        }
                    });
                }
            }
            Err(e) => {
                self.status = format!("Failed to send: {e}");
                if let Some(compose) = self.compose.as_mut() {
                    compose.sending = false;
                }
            }
        }
    }

    /// Fetches the blocked remote images for the open message (only after
    /// explicit confirmation — loading them tells the sender the message
    /// was opened, which is exactly what blocking them by default avoids)
    /// and re-renders with them in place.
    /// Fetches one image — only after the user's explicit click on its
    /// placeholder, and (for a suspected tracking pixel specifically) an
    /// extra confirmation first — and swaps the placeholder's button for
    /// the real picture in place. Ordinary images don't get a second
    /// confirmation dialog on top of the click itself: that would be
    /// friction for every single image in a message, defeating the point
    /// of loading them one at a time instead of all-or-nothing.

    /// A click on the rendered body: re-lay the same HTML out with
    /// litehtml just to hit-test the click point, and if it landed on a
    /// link, confirm with the user — showing the real target, and calling
    /// out explicitly if it's one of the mismatched links the inspection
    /// pipeline already flagged — before handing off to the system
    /// browser via `xdg-open`. The app itself never navigates anywhere.
    /// A click on the message body: look up which link tag (if any) sits
    /// under the click point, and if there is one, confirm with the user
    /// — showing exactly where it goes (registrable domain called out
    /// specifically, so a look-alike subdomain can't bury it), and
    /// calling out explicitly if it's one of the mismatched links the
    /// inspection pipeline already flagged — before handing off to the
    /// system browser via `xdg-open`. The app itself never navigates
    /// anywhere.
    async fn handle_body_click(&mut self, x: f64, y: f64, root: &adw::ApplicationWindow) {
        if self.reading.is_none() {
            return;
        }
        let Some(url) = body_view::href_at(&self.reading_text_view, x, y) else {
            return;
        };

        let mismatch =
            self.reading.as_ref().and_then(|r| r.link_warnings.iter().find(|w| w.href == url)).cloned();

        // Three choices, not two: "Full Host" strips the tracking
        // redirect / deep-link path down to just the site's own origin
        // (`https://amazon.com`, not the tracking-wrapper URL) — safer
        // and avoids the tracker entirely, but may not land on the
        // specific page the email promised. "Exact Link" follows the
        // real, unmodified href, deep-link/tracker and all. Letting the
        // user pick means they're not forced to choose between "trust
        // the whole link" and "don't go anywhere" when a half-measure
        // would do.
        let dialog = gtk::AlertDialog::builder()
            .modal(true)
            .message("Open this link in your browser?")
            .detail(body_view::describe_link_destination(&url, mismatch.as_ref()))
            .buttons(["Cancel", "Full Host", "Exact Link"])
            .cancel_button(0)
            .default_button(0)
            .build();

        let target = match dialog.choose_future(Some(root)).await {
            Ok(1) => body_view::host_only_url(&url),
            Ok(2) => Some(url.clone()),
            _ => None,
        };
        if let Some(target) = target {
            let _ = std::process::Command::new("xdg-open").arg(&target).spawn();
        }
    }

    async fn submit(&mut self) {
        self.submitting = true;
        self.status = "Checking…".to_string();

        let username = if self.username.trim().is_empty() {
            self.email.clone()
        } else {
            self.username.clone()
        };

        let result = self.call_daemon(&username).await;
        self.submitting = false;

        match result {
            Ok((true, id)) => {
                self.status = format!("Account added ({id}).");
                self.needs_manual = false;
                self.configured_email = Some(self.email.clone());
                self.account_id = Some(id);
                self.reload();
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

    /// Re-reads `accounts.toml`, merges in the latest in-memory
    /// settings, and writes it back — re-reading immediately before
    /// writing, rather than holding one long-lived copy across the
    /// whole session, keeps the window for clobbering an account change
    /// the daemon made in the meantime as small as possible, since
    /// `AccountConfig`s and `AppSettings` share one file but have two
    /// different writers (`candor-daemon` for accounts, `candor-gui`
    /// for settings).
    fn persist_settings(&mut self) {
        let result = config::load().and_then(|mut cfg| {
            cfg.settings = self.settings.clone();
            config::save(&cfg)
        });
        if let Err(e) = result {
            self.status = format!("Failed to save settings: {e}");
        }
    }

    fn open_preferences(&mut self, root: &adw::ApplicationWindow) {
        let dialog = build_preferences_dialog(self.settings.clone(), self.input_sender.clone());
        dialog.present(Some(root));
    }

    /// Prepends the signature (if any) to a compose body — shared by
    /// `open_compose`/`open_reply`/`open_reply_all`/`open_forward`.
    /// `tail` is whatever each of those already builds (an empty string
    /// for a blank new message, or the "\n\n{quoted}"-style block for a
    /// reply/forward); with no signature set, this returns `tail`
    /// completely unchanged, so nobody without one notices any
    /// difference from before this setting existed.
    fn with_signature(&self, tail: &str) -> String {
        if self.settings.signature.trim().is_empty() {
            tail.to_string()
        } else {
            format!("\n\n{}{tail}", self.settings.signature)
        }
    }

    async fn remove_account(&mut self) {
        self.status = "Removing account…".to_string();

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.remove_account().await
        }
        .await;

        match result {
            Ok(true) => {
                self.configured_email = None;
                self.account_id = None;
                self.selected_folder = None;
                self.folders.guard().clear();
                self.messages.guard().clear();
                self.reading = None;
                self.compose = None;
                self.needs_manual = false;
                self.status = "Account removed. Add a new one below.".to_string();
            }
            Ok(false) => {
                self.configured_email = None;
                self.status = "No account was configured.".to_string();
            }
            Err(e) => {
                self.status = format!("Failed to remove account: {e}");
            }
        }
    }

    /// The explicit "search the server too" action — a no-op if the
    /// search box is closed or empty, since there's nothing to broaden.
    /// Merges any server matches into the local index and reloads, so
    /// they show up through the same local `search_messages` call that
    /// already renders the list — no separate "these came from the
    /// server" display needed.
    async fn search_server(&mut self) {
        let query = self.search_query.trim().to_string();
        if !self.search_open || query.is_empty() {
            return;
        }
        let folder = (!self.search_all_folders).then(|| self.selected_folder.clone()).flatten();
        self.status = "Searching server…".to_string();

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.search_server(folder.as_deref().unwrap_or(""), &query).await
        }
        .await;

        match result {
            Ok((true, count)) => {
                self.status = format!("Server search found {count} match(es).");
                self.reload();
            }
            Ok((false, _)) => self.status = "No account to search.".to_string(),
            Err(e) => self.status = format!("Server search failed: {e}"),
        }
    }

    async fn sync_now(&mut self) {
        self.status = "Syncing…".to_string();

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.sync_now().await
        }
        .await;

        match result {
            Ok((true, count)) => {
                self.status = format!("Synced ({count} new/updated).");
                self.reload();
            }
            Ok((false, _)) => {
                self.status = "No account to sync.".to_string();
            }
            Err(e) => {
                self.status = format!("Sync failed: {e}");
            }
        }
    }

    /// Syncs just the Drafts folder — what `Msg::DraftSaved` fires
    /// after a background draft save completes, instead of the full
    /// `sync_now()` (every folder) it used to call. The new draft only
    /// ever shows up in one specific folder; waiting on every other
    /// folder's sync too was needless latency between "saved" and
    /// "actually visible".
    async fn sync_drafts_folder(&mut self) {
        let Some(folder) = self.special_use_folder("\\Drafts") else {
            return;
        };

        let result = async {
            let conn = zbus::Connection::session().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            proxy.sync_folder(&folder).await
        }
        .await;

        match result {
            Ok((true, _)) => {
                self.status = "Draft saved.".to_string();
                self.reload();
            }
            Ok((false, _)) => self.status = "No account to sync.".to_string(),
            Err(e) => self.status = format!("Draft saved, but refreshing the list failed: {e}"),
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

fn header_title(model: &AppModel) -> String {
    if let Some(compose) = &model.compose {
        match compose.kind {
            ComposeKind::New => "New Message".to_string(),
            ComposeKind::Reply => "Reply".to_string(),
            ComposeKind::ReplyAll => "Reply All".to_string(),
            ComposeKind::Forward => "Forward".to_string(),
        }
    } else if let Some(reading) = &model.reading {
        reading.subject.clone()
    } else if let Some(email) = &model.configured_email {
        email.clone()
    } else {
        "Add account".to_string()
    }
}

fn header_subtitle(model: &AppModel) -> String {
    if model.compose.is_some() {
        return String::new();
    }
    model.reading.as_ref().map(|r| r.from.clone()).unwrap_or_default()
}

/// Built fresh each time "Preferences" is opened (not a persistent
/// `AppModel` field like the schedule popovers) — pre-filled from
/// whatever `settings` was at the moment it opened, and every change
/// saves immediately (see `persist_settings`), matching the rest of
/// this app's local-first-instant feel rather than needing an explicit
/// Save button.
fn build_preferences_dialog(settings: config::AppSettings, input_sender: relm4::Sender<Msg>) -> adw::PreferencesDialog {
    let dialog = adw::PreferencesDialog::new();
    dialog.set_title("Preferences");

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

    // Retention for the searchable body cache (`message_bodies`) —
    // starred mail and anything you sent are always kept regardless of
    // these, so this only ever affects ordinary messages you've opened
    // to read. `0` means no limit on either row, the simplest way to
    // express "disabled" without a separate switch per row. Plain text
    // only (no attachments), so even a modest MB figure covers a lot —
    // the subtitle says so explicitly rather than leaving the number to
    // speak for itself.
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
    retention_size_row.set_value(
        settings.body_cache_max_bytes.map(|b| b / 1_000_000).unwrap_or(0) as f64,
    );
    {
        let sender = input_sender.clone();
        retention_size_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetRetentionMaxMb(row.value().round() as u32));
        });
    }
    search_group.add(&retention_size_row);

    // Sync — the real "network polling interval" and a cap on the
    // reading-pane cache (never attachment content — see `body.rs`'s
    // module doc for why attachment bytes are never written to disk at
    // all, only fetched transiently when explicitly saved).
    let sync_group = adw::PreferencesGroup::new();
    sync_group.set_title("Sync");

    let idle_row = adw::SpinRow::with_range(0.0, 60.0, 1.0);
    idle_row.set_title("Check non-Inbox folders every");
    idle_row.set_subtitle("Minutes, 0 for the default (25) — Inbox itself updates immediately via push");
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
        "Megabytes, 0 for no limit — text and headers only, attachments are never cached (see Security below)",
    );
    reading_cache_row.set_value(
        settings.reading_cache_max_bytes.map(|b| b / 1_000_000).unwrap_or(0) as f64,
    );
    {
        let sender = input_sender.clone();
        reading_cache_row.connect_notify_local(Some("value"), move |row, _| {
            let _ = sender.send(Msg::SetReadingCacheMaxMb(row.value().round() as u32));
        });
    }
    sync_group.add(&reading_cache_row);

    // Contacts (Group 6) — autocomplete itself needs no settings (it's
    // always on), so this group is just the one-time CSV import
    // action. See `candor_group6_contacts_plan` in memory for why a
    // live CardDAV/Google Contacts sync was ruled out in favor of this.
    let contacts_group = adw::PreferencesGroup::new();
    contacts_group.set_title("Contacts");
    contacts_group.set_description(Some(
        "Addresses you send new mail to are remembered automatically for autocomplete. \
         Import more from a CSV export (Google, Nextcloud, Outlook, ...) \u{2014} a one-time \
         import, not a live sync.",
    ));
    let import_row = adw::ActionRow::new();
    import_row.set_title("Import Contacts\u{2026}");
    let import_button = gtk::Button::builder().label("Choose File\u{2026}").valign(gtk::Align::Center).build();
    {
        let sender = input_sender.clone();
        import_button.connect_clicked(move |_| {
            let _ = sender.send(Msg::ImportContactsCsv);
        });
    }
    import_row.add_suffix(&import_button);
    contacts_group.add(&import_row);

    page.add(&inbox_group);
    page.add(&compose_group);
    page.add(&sync_group);
    page.add(&search_group);
    page.add(&contacts_group);
    dialog.add(&page);

    dialog
}

/// Builds a "Schedule…" popover offering a few relative-time presets —
/// same plain-button-with-closure pattern as `rebuild_move_to_menu`,
/// just built once (these options never change) rather than rebuilt on
/// every `reload()`. `make_msg` turns the chosen wake time into
/// whichever `Msg` variant this particular button should send
/// (`Msg::ScheduleCurrent` for the reading pane, `Msg::BulkSchedule`
/// for the bulk bar) — letting one function serve both without
/// duplicating the preset list.
fn build_schedule_popover(input_sender: relm4::Sender<Msg>, make_msg: impl Fn(i64) -> Msg + 'static) -> gtk::Popover {
    let list_box = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
    list_box.add_css_class("navigation-sidebar");

    let popover = gtk::Popover::new();
    popover.set_child(Some(&list_box));

    let make_msg = std::rc::Rc::new(make_msg);
    let presets: [(&str, fn() -> i64); 4] = [
        ("In 1 hour", schedule_in_one_hour),
        ("This evening", schedule_this_evening),
        ("Tomorrow morning", schedule_tomorrow_morning),
        ("Next week", schedule_next_week),
    ];

    for (label, compute) in presets {
        let button = gtk::Button::builder().label(label).has_frame(false).build();
        let input_sender = input_sender.clone();
        let popover_for_click = popover.clone();
        let make_msg = make_msg.clone();
        button.connect_clicked(move |_| {
            let _ = input_sender.send(make_msg(compute()));
            popover_for_click.popdown();
        });
        list_box.append(&button);
    }

    popover
}

pub(crate) fn schedule_in_one_hour() -> i64 {
    (chrono::Local::now() + chrono::Duration::hours(1)).timestamp()
}

/// Today at 18:00 local time, or tomorrow at 18:00 if it's already
/// past that today.
pub(crate) fn schedule_this_evening() -> i64 {
    let now = chrono::Local::now();
    let Some(naive) = now.date_naive().and_hms_opt(18, 0, 0) else {
        return schedule_in_one_hour();
    };
    let evening = chrono::Local.from_local_datetime(&naive).single().unwrap_or(now);
    if evening > now { evening } else { evening + chrono::Duration::days(1) }.timestamp()
}

/// Tomorrow at 08:00 local time.
pub(crate) fn schedule_tomorrow_morning() -> i64 {
    let now = chrono::Local::now();
    let Some(naive) = (now.date_naive() + chrono::Duration::days(1)).and_hms_opt(8, 0, 0) else {
        return schedule_in_one_hour();
    };
    chrono::Local.from_local_datetime(&naive).single().unwrap_or(now).timestamp()
}

/// One week from today at 08:00 local time.
pub(crate) fn schedule_next_week() -> i64 {
    let now = chrono::Local::now();
    let Some(naive) = (now.date_naive() + chrono::Duration::days(7)).and_hms_opt(8, 0, 0) else {
        return schedule_in_one_hour();
    };
    chrono::Local.from_local_datetime(&naive).single().unwrap_or(now).timestamp()
}


/// Splits a comma-separated "To" field (as typed by the user, or
/// produced by picking an autocomplete suggestion) into individual
/// `(name, address)` pairs — handles both plain `addr@example.com` and
/// `Name <addr@example.com>` segments, skipping anything that doesn't
/// contain an `@` at all (an in-progress, not-yet-valid segment).
/// Shared by the sent-mail contact auto-harvest (`send_compose`) and
/// the compose "To" autocomplete's own comma-segment parsing.
fn split_recipients(to: &str) -> Vec<(Option<String>, String)> {
    to.split(',')
        .filter_map(|segment| {
            let segment = segment.trim();
            if let Some((name, rest)) = segment.split_once('<') {
                let address = rest.trim_end_matches('>').trim();
                (!address.is_empty() && address.contains('@'))
                    .then(|| (Some(name.trim().to_string()).filter(|n| !n.is_empty()), address.to_string()))
            } else {
                segment.contains('@').then(|| (None, segment.to_string()))
            }
        })
        .collect()
}

/// The recipient currently being typed — everything after the last
/// comma in the "To" field, trimmed. Autocomplete only ever matches
/// against this trailing segment, never recipients already finished
/// (text before the last comma).
fn current_recipient_segment(to: &str) -> &str {
    match to.rfind(',') {
        Some(idx) => to[idx + 1..].trim(),
        None => to.trim(),
    }
}

/// Replaces the in-progress trailing recipient segment (see
/// `current_recipient_segment`) with a chosen autocomplete suggestion,
/// leaving every already-finished recipient before it untouched and
/// appending a trailing `", "` so the user can keep typing the next one
/// immediately.
fn replace_last_recipient_segment(to: &str, replacement: &str) -> String {
    match to.rfind(',') {
        Some(idx) => format!("{}, {replacement}, ", to[..idx].trim()),
        None => format!("{replacement}, "),
    }
}

/// The original sender plus every other `To`/`Cc` recipient, minus our
/// own account address (case-insensitively) and de-duplicated, in the
/// order first seen.
fn reply_all_recipients(reading: &ReadingPane, own_email: Option<&str>) -> String {
    let own = own_email.map(str::to_ascii_lowercase);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    let mut consider = |addr: &str| {
        let addr = addr.trim();
        if addr.is_empty() {
            return;
        }
        let lower = addr.to_ascii_lowercase();
        if Some(&lower) == own.as_ref() {
            return;
        }
        if seen.insert(lower) {
            out.push(addr.to_string());
        }
    };

    consider(&reading.from);
    reading.to.split(',').for_each(&mut consider);
    reading.cc.split(',').for_each(&mut consider);

    out.join(", ")
}

/// A short "filename.txt, other.pdf" summary for the compose attachment
/// row — just names, since the full paths aren't useful to the user here.
fn attachment_summary(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Fetches one image URL directly (no size cap on the server's declared
/// Content-Length is trusted — the read itself is capped). Only ever
/// called after the user has explicitly clicked that specific image's
/// placeholder — nothing here ever touches the network before then.
fn fetch_one_image(url: &str) -> Option<Vec<u8>> {
    const MAX_IMAGE_BYTES: u64 = 10 * 1024 * 1024;

    let mut response = ureq::get(url).call().ok()?;
    let mut buf = Vec::new();
    response.body_mut().as_reader().take(MAX_IMAGE_BYTES).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Fetches one image — only after the user's explicit click on its
/// placeholder, and (for a suspected tracking pixel specifically) an
/// extra confirmation first — and swaps the placeholder's button for the
/// real picture in place. Ordinary images don't get a second
/// confirmation dialog on top of the click itself: that would be
/// friction for every single image in a message, defeating the point of
/// loading them one at a time instead of all-or-nothing. A free function
/// (not an `AppModel` method) because it's spawned via
/// `glib::spawn_future_local` straight from a button's click handler —
/// see the comment on `build_image_placeholder` for why that, rather
/// than routing through `Msg`, is what keeps relm4's channel working at
/// all once a live widget is involved.
async fn load_single_image(container: gtk::Box, src: String, is_tracker: bool, root: adw::ApplicationWindow) {
    if is_tracker {
        let dialog = gtk::AlertDialog::builder()
            .modal(true)
            .message("This looks like a tracking pixel")
            .detail("Loading it tells the sender you opened this message. Load it anyway?")
            .buttons(["Cancel", "Load Anyway"])
            .cancel_button(0)
            .default_button(0)
            .build();
        if !matches!(dialog.choose_future(Some(&root)).await, Ok(1)) {
            return;
        }
    }

    fetch_and_show_image(container, src).await;
}

/// The actual fetch-decode-swap, shared by the per-image click path
/// above and the bulk "Show N images" path — the only difference between
/// them is *when* (or whether) the tracker confirmation dialog happens:
/// once per image there, once total (if any are trackers) for the bulk
/// path, rather than this function caring about that distinction at all.
async fn fetch_and_show_image(container: gtk::Box, src: String) {
    let bytes = tokio::task::spawn_blocking(move || fetch_one_image(&src)).await.ok().flatten();
    let Some(bytes) = bytes else {
        replace_placeholder_with_label(&container, "Failed to load image");
        return;
    };

    let Ok(texture) = gdk::Texture::from_bytes(&glib::Bytes::from(&bytes)) else {
        replace_placeholder_with_label(&container, "Failed to decode image");
        return;
    };

    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
    let picture = gtk::Picture::for_paintable(&texture);
    // Not `can_shrink(true)`: a `Picture`'s minimum size is 0x0 when
    // shrinking is allowed, and `GtkTextView`'s child-anchor layout sizes
    // anchored widgets off their *minimum* request rather than their
    // natural size — the picture would successfully load and then render
    // as a genuinely zero-sized (invisible) widget. `can_shrink(false)`
    // forces it to always request its real natural size, the same
    // pattern the old full-page rendering already relied on.
    picture.set_can_shrink(false);
    picture.set_halign(gtk::Align::Start);
    container.append(&picture);
}

fn replace_placeholder_with_label(container: &gtk::Box, text: &str) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
    let label = gtk::Label::new(Some(text));
    label.add_css_class("dim-label");
    container.append(&label);
}

/// GTK's standard semantic style classes — recoloring the symbolic icon
/// (and, via the same classes, the label) green or red without any
/// bespoke CSS.
fn security_css_classes(ok: bool) -> &'static [&'static str] {
    if ok { &["success"] } else { &["error"] }
}

/// What the bulk bar's single merged mark-read/unread button should do
/// *next* — all-unread selections default to marking read, all-read to
/// marking unread, and a mixed selection defaults to marking read (an
/// arbitrary but deterministic starting point; see
/// `AppModel::bulk_mark_toggle` for what happens after that first
/// click resolves the mix).
fn bulk_mark_target(model: &AppModel) -> bool {
    match model.selected_seen_uniform() {
        Some(all_seen) => !all_seen,
        None => true,
    }
}

/// Same as `bulk_mark_target`, for the star button.
fn bulk_flag_target(model: &AppModel) -> bool {
    match model.selected_flagged_uniform() {
        Some(all_flagged) => !all_flagged,
        None => true,
    }
}

/// Whether the mouse-only bulk-action bar should actually be showing —
/// never while the current selection was built with the keyboard (see
/// `AppModel::kb_select_mode`'s doc comment), since those buttons exist
/// purely to be clicked and the point of selecting with `X` is not
/// reaching for a mouse.
fn bulk_bar_active(model: &AppModel) -> bool {
    model.selected_uids.len() >= model.settings.bulk_select_threshold && !model.kb_select_mode
}

/// Whether the security badge should read as "all clear" vs. "worth a
/// look" — an explicit auth *failure* (not just "no signature to check",
/// which isn't itself suspicious) or any of the other inspection
/// warnings trips it.
fn security_is_ok(v: Option<&MessageVerdict>) -> bool {
    let Some(v) = v else {
        return false;
    };
    v.dkim_verified != Some(false)
        && v.spf_pass != Some(false)
        && v.dmarc_pass != Some(false)
        && v.link_warnings.is_empty()
        && v.attachment_warnings.is_empty()
        && !v.sender_display_mismatch
        && !v.reply_to_mismatch
}

fn summarize_verdict(v: Option<&MessageVerdict>) -> String {
    let Some(v) = v else {
        return "No inspection data available.".to_string();
    };

    let fmt = |label: &str, val: Option<bool>| {
        let state = match val {
            Some(true) => "pass",
            Some(false) => "fail",
            None => "—",
        };
        format!("{label}: {state}")
    };

    let mut parts = vec![
        fmt("DKIM", v.dkim_verified),
        fmt("SPF", v.spf_pass),
        fmt("DMARC", v.dmarc_pass),
    ];

    if !v.blocked_remote_resources.is_empty() {
        parts.push(format!("{} image(s) blocked", v.blocked_remote_resources.len()));
    }
    if !v.link_warnings.is_empty() {
        parts.push(format!("{} link warning(s)", v.link_warnings.len()));
    }
    if !v.attachment_warnings.is_empty() {
        parts.push(format!("{} attachment warning(s)", v.attachment_warnings.len()));
    }
    if v.sender_display_mismatch {
        parts.push("sender name doesn't match address".to_string());
    }
    if v.reply_to_mismatch {
        parts.push("reply-to differs from sender".to_string());
    }

    parts.join(" · ")
}

/// Checked once at startup: account id/email (for the inbox screen) and an
/// optional note. A `Some` note means the check itself failed (e.g. the
/// daemon isn't running) — distinct from a successful check that simply
/// found no account.
struct StartupState {
    account_id: Option<String>,
    email: Option<String>,
    note: Option<String>,
}

async fn check_existing_account() -> StartupState {
    let conn = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            return StartupState {
                account_id: None,
                email: None,
                note: Some(format!("Could not reach the session bus: {e}")),
            };
        }
    };
    let proxy = match DaemonProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            return StartupState {
                account_id: None,
                email: None,
                note: Some(format!("Could not reach candor-daemon: {e}")),
            };
        }
    };
    match proxy.account_summary().await {
        Ok((true, id, email, _display_name)) => StartupState {
            account_id: Some(id),
            email: Some(email),
            note: None,
        },
        Ok((false, _, _, _)) => StartupState {
            account_id: None,
            email: None,
            note: None,
        },
        Err(e) => StartupState {
            account_id: None,
            email: None,
            note: Some(format!("Could not check existing account: {e}")),
        },
    }
}

fn main() {
    let app = RelmApp::new("dev.candor.gui");
    theme::apply_and_watch();
    app.run_async::<AppModel>(());
}

