use candor_core::store::MessageSummary;
use chrono::Datelike;
use relm4::adw;
use relm4::adw::prelude::*;
use relm4::factory::{DynamicIndex, FactoryComponent, FactorySender};
use relm4::gtk;
use relm4::RelmWidgetExt;

/// Per-row quick actions — archive/delete/toggle-unread without having
/// to open the message first, the same three actions the reading pane
/// already offers once a message is open. `ToggleSelect` goes to
/// `AppModel` rather than being handled locally because whether this
/// row's own pop-out should actually show (`revealed`) depends on how
/// *many* rows are selected across the whole list, which no single row
/// can know on its own — see `AppModel::sync_row_selection_flags`.
#[derive(Debug)]
pub enum MessageRowOutput {
    Archive(u32),
    Delete(u32),
    ToggleUnread(u32),
    ToggleFlag(u32),
    ToggleSelect(u32),
    Schedule { uid: u32, wake_at: i64 },
    Reply(u32),
    Forward(u32),
    /// The mouse entered/left this row's bounds — used only to drive
    /// the shared hover-deselect timer across however many rows are
    /// currently selected (see `AppModel::row_hover_enter`/
    /// `row_hover_leave`); sent unconditionally regardless of whether
    /// this row is actually selected, since this row has no way to
    /// know that about itself — `AppModel` is the one that ignores it
    /// when irrelevant.
    HoverEnter(u32),
    HoverLeave(u32),
}

#[derive(Debug)]
pub struct MessageRow {
    pub summary: MessageSummary,
    /// Whether this row's leading circle is checked. Set by
    /// `AppModel`, not toggled locally — see `MessageRowOutput`'s doc
    /// comment.
    pub selected: bool,
    /// Whether THIS row's own pop-out (date replaced by quick-action
    /// icons) is showing. Also set by `AppModel`: true only when this
    /// row is selected *and* the bulk-action bar isn't active.
    pub revealed: bool,
    /// True in Drafts/Sent — set by `AppModel` from
    /// `current_folder_restricted` for every row whenever the folder
    /// changes, since no single row has any way to know which folder
    /// it's actually sitting in. Hides mark-read/unread, star, and
    /// schedule from the pop-out; delete stays available either way.
    pub restricted: bool,
    /// Whether the *keyboard* cursor (Ctrl+2, then j/k) is on this row —
    /// separate from `selected` (the circle, used for bulk actions).
    /// Set by `AppModel::sync_keyboard_focus_flags`.
    pub kb_focused: bool,
    /// Briefly true right after a keyboard-driven landing (Ctrl+2/3, or
    /// returning focus after compose) for the one-shot flash — see
    /// `theme.rs`'s `.kb-flash` rule.
    pub kb_flash: bool,
}

#[relm4::factory(pub)]
impl FactoryComponent for MessageRow {
    type Init = MessageSummary;
    type Input = ();
    type Output = MessageRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        root = adw::ActionRow {
            set_activatable: true,
            set_use_markup: true,
            // Date, then subject, as two lines of the title itself —
            // `subject_markup` builds both. ActionRow's title/subtitle
            // order is fixed (title always above subtitle), so there's
            // no property that puts the date above the subject on its
            // own; folding it into the title string as an explicit
            // first line is what actually gets it there.
            set_title_lines: 2,
            set_title: &subject_markup(&self.summary),
            set_subtitle: &meta_markup(&self.summary),
            // Breathing room between rows — "boxed-list" otherwise
            // stacks them flush with just a hairline separator.
            set_margin_bottom: 3,
            #[watch]
            set_css_classes: match (self.kb_focused, self.kb_flash) {
                (true, true) => &["kb-focused", "kb-flash"],
                (true, false) => &["kb-focused"],
                (false, _) => &[],
            },

            add_controller = gtk::EventControllerMotion {
                connect_enter[sender, uid = self.summary.uid] => move |_, _, _| {
                    sender.output(MessageRowOutput::HoverEnter(uid)).ok();
                },
                connect_leave[sender, uid = self.summary.uid] => move |_| {
                    sender.output(MessageRowOutput::HoverLeave(uid)).ok();
                },
            },

            // Unread indicator: a vertical accent-colored bar, not a
            // dot — a dot read as "one more circle" sitting right next
            // to the select circle, visually crowded and easy to
            // confuse with it. Width is constant regardless of read
            // state (only the CSS class, hence the color, toggles) so
            // this can't reintroduce the layout-shift bug a
            // conditionally-*visible* prefix widget caused earlier —
            // see `theme.rs`'s `STATIC_CSS` for the `.unread-bar` rule.
            add_prefix = &gtk::Box {
                set_width_request: 4,
                set_vexpand: true,
                #[watch]
                set_css_classes: if self.summary.seen { &[] } else { &["unread-bar"] },
            },

            // Selection toggle.
            add_prefix = &gtk::Button {
                // `radio-symbolic` (an empty ring) unselected,
                // `object-select-symbolic` (a checkmark) selected — both
                // verified present in Adwaita/Yaru. Paired with
                // "circular" the button itself is the ring; selected
                // additionally fills it via "suggested-action".
                #[watch]
                set_icon_name: if self.selected { "object-select-symbolic" } else { "radio-symbolic" },
                #[watch]
                set_css_classes: if self.selected {
                    &["circular", "suggested-action"]
                } else {
                    &["circular", "flat"]
                },
                set_tooltip_text: Some("Select"),
                connect_clicked[sender, uid = self.summary.uid] => move |_| {
                    sender.output(MessageRowOutput::ToggleSelect(uid)).ok();
                },
            },

            // Everything trailing lives in one tight-spacing Box rather
            // than several separate `add_suffix` calls — libadwaita's
            // own default gap between suffix widgets reads as too
            // loose once there are several of them side by side.
            add_suffix = &gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 2,

                // One button, one fixed slot, for both "this is
                // starred" (status) and "star this" (action) — having
                // those be two separate widgets in two different box
                // positions, each visible only for the opposite state,
                // made the star visibly jump to a different spot in the
                // row depending on whether it happened to be starred.
                // Visible whenever it's starred (regardless of reveal
                // state, so the status still shows at rest) or whenever
                // revealed (so there's still a way to star an unstarred
                // one); the icon alone carries which case it is. Lives
                // *outside* the revealer below, not inside it: it has
                // to stay visible in a state (starred, not revealed)
                // the revealer itself doesn't have a slot for — a
                // `GtkRevealer` shows or hides its whole child as one
                // unit, it can't reveal just one grandchild while
                // hiding its siblings.
                gtk::Button {
                    #[watch]
                    set_icon_name: if self.summary.flagged { "starred-symbolic" } else { "non-starred-symbolic" },
                    #[watch]
                    set_tooltip_text: Some(if self.summary.flagged { "Unstar" } else { "Star" }),
                    add_css_class: "flat",
                    #[watch]
                    set_visible: !self.restricted && (self.summary.flagged || self.revealed),
                    connect_clicked[sender, uid = self.summary.uid] => move |_| {
                        sender.output(MessageRowOutput::ToggleFlag(uid)).ok();
                    },
                },

                // Everything that only ever shows while selected, as one
                // animated group — plain `set_visible` on each button
                // individually just snapped in and out instantly, which
                // read as more abrupt than the rest of this app's polish.
                // `SlideRight`, not `Crossfade`: confirmed directly
                // (a standalone GTK test, measuring the revealer with
                // `reveal_child: false`) that `Crossfade` — and `None`,
                // for that matter — keep the *entire hidden child*
                // allocated at full size (226px for these six buttons)
                // at all times, only animating opacity; they never
                // collapse to zero width the way the old comment here
                // claimed. Only the `Slide*` transitions actually shrink
                // the allocation to 0 once hidden. In the old full-width
                // single-pane list this went unnoticed — 226px of slack
                // was easy to absorb — but once the list became one
                // column in a side-by-side layout (see `main.rs`'s
                // `wide_layout`), it was eating more than half the
                // column's width on every single row, permanently, just
                // to reserve space for icons that were almost never
                // showing.
                gtk::Revealer {
                    set_transition_type: gtk::RevealerTransitionType::SlideRight,
                    set_transition_duration: 150,
                    #[watch]
                    set_reveal_child: self.revealed,

                    gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 2,

                        gtk::Button {
                            set_icon_name: "mail-reply-sender-symbolic",
                            set_tooltip_text: Some("Reply"),
                            add_css_class: "flat",
                            #[watch]
                            set_visible: !self.restricted,
                            connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                sender.output(MessageRowOutput::Reply(uid)).ok();
                            },
                        },
                        gtk::Button {
                            set_icon_name: "mail-forward-symbolic",
                            set_tooltip_text: Some("Forward"),
                            add_css_class: "flat",
                            #[watch]
                            set_visible: !self.restricted,
                            connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                sender.output(MessageRowOutput::Forward(uid)).ok();
                            },
                        },
                        gtk::MenuButton {
                            set_icon_name: "alarm-symbolic",
                            set_tooltip_text: Some("Schedule…"),
                            add_css_class: "flat",
                            #[watch]
                            set_visible: !self.restricted,
                            #[wrap(Some)]
                            set_popover = &gtk::Popover {
                                #[wrap(Some)]
                                set_child = &gtk::Box {
                                    set_orientation: gtk::Orientation::Vertical,
                                    set_margin_all: 6,

                                    gtk::Button {
                                        set_label: "In 1 hour",
                                        add_css_class: "flat",
                                        connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                            sender.output(MessageRowOutput::Schedule {
                                                uid, wake_at: crate::schedule_in_one_hour(),
                                            }).ok();
                                        },
                                    },
                                    gtk::Button {
                                        set_label: "This evening",
                                        add_css_class: "flat",
                                        connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                            sender.output(MessageRowOutput::Schedule {
                                                uid, wake_at: crate::schedule_this_evening(),
                                            }).ok();
                                        },
                                    },
                                    gtk::Button {
                                        set_label: "Tomorrow morning",
                                        add_css_class: "flat",
                                        connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                            sender.output(MessageRowOutput::Schedule {
                                                uid, wake_at: crate::schedule_tomorrow_morning(),
                                            }).ok();
                                        },
                                    },
                                    gtk::Button {
                                        set_label: "Next week",
                                        add_css_class: "flat",
                                        connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                            sender.output(MessageRowOutput::Schedule {
                                                uid, wake_at: crate::schedule_next_week(),
                                            }).ok();
                                        },
                                    },
                                },
                            },
                        },
                        gtk::Button {
                            // Reflects what the message *currently* is, not
                            // the action the click performs — a read message
                            // shows the (closed) read-mail icon, an unread
                            // one shows the unread icon; clicking flips it
                            // either way.
                            #[watch]
                            set_icon_name: if self.summary.seen { "mail-read-symbolic" } else { "mail-unread-symbolic" },
                            set_tooltip_text: Some(if self.summary.seen { "Mark Unread" } else { "Mark Read" }),
                            add_css_class: "flat",
                            #[watch]
                            set_visible: !self.restricted,
                            connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                sender.output(MessageRowOutput::ToggleUnread(uid)).ok();
                            },
                        },
                        gtk::Button {
                            set_icon_name: "mail-archive-symbolic",
                            set_tooltip_text: Some("Archive"),
                            add_css_class: "flat",
                            #[watch]
                            set_visible: !self.restricted,
                            connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                sender.output(MessageRowOutput::Archive(uid)).ok();
                            },
                        },
                        // Delete is the one action Drafts/Sent *do*
                        // still want — never gated on `restricted`.
                        gtk::Button {
                            set_icon_name: "user-trash-symbolic",
                            set_tooltip_text: Some("Delete"),
                            add_css_class: "flat",
                            connect_clicked[sender, uid = self.summary.uid] => move |_| {
                                sender.output(MessageRowOutput::Delete(uid)).ok();
                            },
                        },
                    },
                },
            },
        }
    }

    fn init_model(summary: Self::Init, _index: &DynamicIndex, _sender: FactorySender<Self>) -> Self {
        Self { summary, selected: false, revealed: false, restricted: false, kb_focused: false, kb_flash: false }
    }
}

/// Date, then subject, as the title's two lines — moved the date here
/// (from its own suffix label) because it and the star/action icons
/// were both landing in the same trailing slot, visually competing for
/// the same space once a row had both a date and a starred status to
/// show. Subject text is attacker-controlled (it's whatever a sender
/// put in a header), so it's always markup-escaped before being
/// embedded in a Pango markup string — otherwise a crafted subject
/// could inject its own formatting (e.g. fake bold "SECURITY ALERT"
/// styling) into the list. Also run through `collapse_whitespace`,
/// same as every other header-derived field now (see its doc comment):
/// a raw `Subject` header is exactly the kind of thing that never goes
/// through the HTML sanitizer at all, and confirmed live elsewhere
/// that the invisible zero-width padding some automated email carries
/// can hang GTK's text shaping outright, not just look ugly.
fn subject_markup(m: &MessageSummary) -> String {
    let date = m.date.map(format_full_date).unwrap_or_default();
    let date_escaped = gtk::glib::markup_escape_text(&date);
    let date_line = format!("<span size=\"small\" alpha=\"65%\">{date_escaped}</span>");

    let subject = crate::richtext::collapse_whitespace(m.subject.as_deref().unwrap_or("(no subject)"));
    let escaped = gtk::glib::markup_escape_text(&subject);
    let subject_line = if m.seen { escaped.to_string() } else { format!("<b>{escaped}</b>") };

    format!("{date_line}\n{subject_line}")
}

/// Just the sender now — the date moved up into the title (see
/// `subject_markup`).
fn meta_markup(m: &MessageSummary) -> String {
    let from = m
        .from_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(m.from_address.as_deref())
        .unwrap_or("(unknown sender)");
    let from = crate::richtext::collapse_whitespace(from);
    gtk::glib::markup_escape_text(&from).to_string()
}

/// A consistent, always-fully-spelled-out date — "Fri, Oct 23" (plus a
/// year once it's not the current one). The old format
/// (`format_relative_date`, bare time for today/"Yesterday"/a lone
/// weekday abbreviation the rest of the week) worked fine as a small,
/// de-emphasized trailing label, but reads as noticeably incomplete now
/// that it's sitting in the more prominent eyebrow line above the
/// subject — every row ought to look like the same kind of thing up
/// there, not a mix of bare times and single weekday letters.
fn format_full_date(ts: i64) -> String {
    let Some(utc_dt) = chrono::DateTime::from_timestamp(ts, 0) else {
        return String::new();
    };
    let dt = chrono::DateTime::<chrono::Local>::from(utc_dt);
    let now = chrono::Local::now();

    if dt.year() == now.year() {
        dt.format("%a, %b %-d").to_string()
    } else {
        dt.format("%a, %b %-d, %Y").to_string()
    }
}
