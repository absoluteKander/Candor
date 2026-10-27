use relm4::factory::{DynamicIndex, FactoryComponent, FactorySender};
use relm4::gtk;
use relm4::gtk::prelude::*;
use relm4::RelmWidgetExt;

use crate::folder_display::FolderDisplay;

/// Purely a display row — selection (which folder is *open*) is handled
/// by the parent `gtk::ListBox`'s own `row-activated` signal (see
/// main.rs). `kb_focused`/`kb_flash` are a separate concept layered on
/// top — which row the *keyboard* cursor is currently on, set by
/// `AppModel::sync_keyboard_focus_flags` — since Ctrl+1/J/K navigation
/// needs to work independently of which folder happens to be open.
#[derive(Debug)]
pub struct FolderRow {
    pub raw_name: String,
    label: String,
    unread: u32,
    pub kb_focused: bool,
    pub kb_flash: bool,
}

#[relm4::factory(pub)]
impl FactoryComponent for FolderRow {
    type Init = FolderDisplay;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        root = gtk::Box {
            set_orientation: gtk::Orientation::Horizontal,
            set_margin_all: 8,
            set_spacing: 8,
            #[watch]
            set_css_classes: match (self.kb_focused, self.kb_flash) {
                (true, true) => &["kb-focused", "kb-flash"],
                (true, false) => &["kb-focused"],
                (false, _) => &[],
            },

            gtk::Label {
                set_label: &self.label,
                set_halign: gtk::Align::Start,
                set_hexpand: true,
                set_ellipsize: gtk::pango::EllipsizeMode::End,
            },

            gtk::Label {
                set_label: &self.unread.to_string(),
                set_visible: self.unread > 0,
                add_css_class: "dim-label",
                add_css_class: "caption",
            },
        }
    }

    fn init_model(display: Self::Init, _index: &DynamicIndex, _sender: FactorySender<Self>) -> Self {
        Self {
            raw_name: display.raw_name,
            label: display.label,
            unread: display.unread,
            kb_focused: false,
            kb_flash: false,
        }
    }
}
