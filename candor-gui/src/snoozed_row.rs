use candor_core::store::SnoozedMessage;
use relm4::adw;
use relm4::adw::prelude::*;
use relm4::factory::{DynamicIndex, FactoryComponent, FactorySender};
use relm4::gtk;

/// One row in the "Snoozed" view — the only interaction it offers is
/// canceling the snooze; actually *reading* a snoozed message isn't
/// wired up here (that would mean teaching `open_message` and every
/// row-action method to resolve a per-row folder instead of assuming
/// `self.selected_folder`, which every other action in this app still
/// assumes). This view exists so a snooze can be seen and undone
/// before it fires, not as a second inbox.
#[derive(Debug)]
pub enum SnoozedRowOutput {
    Unschedule { folder: String, uid: u32 },
}

#[derive(Debug)]
pub struct SnoozedRow {
    pub folder: String,
    pub uid: u32,
    subject: String,
    wake_label: String,
}

#[relm4::factory(pub)]
impl FactoryComponent for SnoozedRow {
    type Init = SnoozedMessage;
    type Input = ();
    type Output = SnoozedRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        root = adw::ActionRow {
            set_title: &self.subject,
            set_subtitle: &format!("{} — wakes {}", self.folder, self.wake_label),

            add_suffix = &gtk::Button {
                set_icon_name: "edit-undo-symbolic",
                set_tooltip_text: Some("Cancel schedule"),
                add_css_class: "flat",
                connect_clicked[sender, folder = self.folder.clone(), uid = self.uid] => move |_| {
                    sender.output(SnoozedRowOutput::Unschedule { folder: folder.clone(), uid }).ok();
                },
            },
        }
    }

    fn init_model(msg: Self::Init, _index: &DynamicIndex, _sender: FactorySender<Self>) -> Self {
        Self {
            folder: msg.folder,
            uid: msg.uid,
            subject: msg.subject.unwrap_or_else(|| "(no subject)".to_string()),
            wake_label: format_wake_time(msg.wake_at),
        }
    }
}

fn format_wake_time(ts: i64) -> String {
    let Some(utc_dt) = chrono::DateTime::from_timestamp(ts, 0) else {
        return String::new();
    };
    let dt = chrono::DateTime::<chrono::Local>::from(utc_dt);
    let now = chrono::Local::now();
    let days_ahead = (dt.date_naive() - now.date_naive()).num_days();

    if days_ahead == 0 {
        format!("today {}", dt.format("%-I:%M %p"))
    } else if days_ahead == 1 {
        format!("tomorrow {}", dt.format("%-I:%M %p"))
    } else {
        dt.format("%b %-d, %-I:%M %p").to_string()
    }
}
