//! Reads Omarchy's active theme palette and applies it as libadwaita
//! named-color overrides, so Candor follows the same accent/background/
//! text colors as the terminal and other themed apps — not just dark vs.
//! light.
//!
//! Omarchy's own theming pipeline (`omarchy-theme-set-gnome`) only sets
//! GNOME's dark/light `color-scheme` and the stock Adwaita theme name; it
//! doesn't propagate the actual palette into any GTK app today. Terminals
//! get the full palette by having `~/.config/omarchy/themed/*.tpl` files
//! rendered with `colors.toml`'s fields into their own config format. This
//! does the equivalent for us: read the same `colors.toml`, map its
//! fields onto libadwaita's own named-color CSS variables.
//!
//! Entirely optional — if `colors.toml` isn't there (no Omarchy, or no
//! theme set yet), Candor just runs with plain libadwaita defaults.

use std::path::PathBuf;

use relm4::adw;
use relm4::gtk::gio::prelude::*;
use relm4::gtk::{self, gdk, gio};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
struct OmarchyColors {
    mode: Option<String>,
    accent: Option<String>,
    background: Option<String>,
    lighter_background: Option<String>,
    foreground: Option<String>,
}

fn colors_toml_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/state/omarchy/current/theme/colors.toml"))
}

fn load() -> Option<OmarchyColors> {
    let raw = std::fs::read_to_string(colors_toml_path()?).ok()?;
    toml::from_str(&raw).ok()
}

fn css_for(colors: &OmarchyColors) -> String {
    let mut out = String::new();
    let mut define = |name: &str, value: &Option<String>| {
        if let Some(v) = value {
            out.push_str(&format!("@define-color {name} {v};\n"));
        }
    };

    define("accent_color", &colors.accent);
    define("accent_bg_color", &colors.accent);
    define("window_bg_color", &colors.background);
    define("window_fg_color", &colors.foreground);
    define("view_bg_color", &colors.background);
    define("view_fg_color", &colors.foreground);
    define("headerbar_bg_color", &colors.background);
    define("headerbar_fg_color", &colors.foreground);

    let card_bg = colors.lighter_background.clone().or_else(|| colors.background.clone());
    define("card_bg_color", &card_bg);
    define("card_fg_color", &colors.foreground);
    define("popover_bg_color", &card_bg);
    define("popover_fg_color", &colors.foreground);

    out
}

fn apply(provider: &gtk::CssProvider) {
    let Some(colors) = load() else {
        return;
    };

    provider.load_from_string(&css_for(&colors));

    if let Some(mode) = colors.mode.as_deref() {
        let scheme = if mode == "light" {
            adw::ColorScheme::ForceLight
        } else {
            adw::ColorScheme::ForceDark
        };
        adw::StyleManager::default().set_color_scheme(scheme);
    }
}

/// Unread indicator for inbox rows: a vertical accent-colored bar in
/// `message_row.rs`, same hue as the rest of the app's accented text/
/// icons rather than a separate dot — `@accent_bg_color` is always
/// defined (either `apply()` above overrides it from Omarchy's
/// `colors.toml`, or libadwaita's own stock stylesheet defines it), so
/// this is theme-aware for free. Loaded through its own
/// always-present provider (not `apply()`'s, which does nothing when
/// `colors.toml` is missing) so the rule exists regardless of whether
/// Omarchy theming is active.
const STATIC_CSS: &str = "
.unread-bar {
    background-color: @accent_bg_color;
    border-radius: 2px;
}

/* Keyboard-navigation cursor (Ctrl+1/2/3, then j/k) in the folder list
   and message list — see `AppModel::sync_keyboard_focus_flags`. Needs
   to read clearly without hovering, unlike the mouse-only affordances
   the rest of this app can lean on, so it's a full row tint plus a
   left border, not just a subtle change. `.kb-flash` is layered on top
   briefly right after a keyboard-driven jump (switching panes, or
   returning from compose); removing it lets the `transition` on
   `.kb-focused` ease the row back down to its quieter resting look
   instead of snapping off abruptly. */
.kb-focused {
    background-color: alpha(@accent_bg_color, 0.14);
    border-left: 3px solid @accent_bg_color;
    transition: background-color 400ms ease-out;
}
.kb-focused.kb-flash {
    background-color: @accent_bg_color;
    color: @accent_fg_color;
}

/* The bespoke tab strip (`tab_strip_row.rs`) that replaces `AdwTabBar`
   — a custom widget, since the per-account lock/mute icons and the
   always-visible fixed order don't fit a generic tab bar's own model.
   `TabColor`'s 8 presets as named tokens, not literal hex baked
   into the widget's own CSS classes, same reasoning as `@accent_bg_color`
   above: a future `apply()` override (if Omarchy ever exposes more than
   one accent) has something to redefine instead of a hunt through Rust
   code for hardcoded colors. Picked one medium-saturation value per hue
   that reads acceptably on both light and dark Adwaita, same pragmatic
   choice this file already makes for `.kb-focused`/`.unread-bar` above
   rather than hand-tuning per color scheme. */
@define-color candor_tab_blue #3584e4;
@define-color candor_tab_green #2ec27e;
@define-color candor_tab_purple #9141ac;
@define-color candor_tab_orange #ff7800;
@define-color candor_tab_red #e01b24;
@define-color candor_tab_teal #2190a4;
@define-color candor_tab_pink #e66ce6;
@define-color candor_tab_yellow #c4a000;

.candor-tab-strip {
    padding: 4px 4px 0 4px;
}
.candor-tab-strip-row {
    padding: 6px 10px;
    border-radius: 10px 10px 0 0;
}
.candor-tab-strip-row:hover {
    background-color: alpha(currentColor, 0.06);
}
.candor-tab-strip-row.selected {
    background-color: alpha(@accent_bg_color, 0.18);
}
.candor-tab-color-dot {
    min-width: 10px;
    min-height: 10px;
    border-radius: 50%;
}
.candor-tab-color-dot.candor-color-blue   { background-color: @candor_tab_blue; }
.candor-tab-color-dot.candor-color-green  { background-color: @candor_tab_green; }
.candor-tab-color-dot.candor-color-purple { background-color: @candor_tab_purple; }
.candor-tab-color-dot.candor-color-orange { background-color: @candor_tab_orange; }
.candor-tab-color-dot.candor-color-red    { background-color: @candor_tab_red; }
.candor-tab-color-dot.candor-color-teal   { background-color: @candor_tab_teal; }
.candor-tab-color-dot.candor-color-pink   { background-color: @candor_tab_pink; }
.candor-tab-color-dot.candor-color-yellow { background-color: @candor_tab_yellow; }

.candor-lock-btn.locked {
    color: @candor_tab_red;
}
.candor-lock-btn.unlocked {
    color: @candor_tab_green;
}

@keyframes candor-notify-pulse {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 1.0; }
}
.candor-notify-btn.has-mail {
    color: @candor_tab_yellow;
    animation: candor-notify-pulse 1.6s ease-in-out infinite;
}
.candor-notify-btn.muted {
    opacity: 0.3;
}
";

/// Call once at startup, after `adw::init()` (relm4 does this itself when
/// built with the `libadwaita` feature) and before showing any window.
pub fn apply_and_watch() {
    let Some(display) = gdk::Display::default() else {
        return;
    };

    let static_provider = gtk::CssProvider::new();
    static_provider.load_from_string(STATIC_CSS);
    gtk::style_context_add_provider_for_display(
        &display,
        &static_provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    let provider = gtk::CssProvider::new();
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    apply(&provider);

    let Some(path) = colors_toml_path() else {
        return;
    };
    let file = gio::File::for_path(&path);
    let Ok(monitor) = file.monitor_file(gio::FileMonitorFlags::NONE, gio::Cancellable::NONE) else {
        return;
    };

    monitor.connect_changed(move |_monitor, _file, _other_file, _event| {
        apply(&provider);
    });

    // Kept alive for the process's whole lifetime — dropping it would stop
    // watching, and there's exactly one of these for the whole app, so an
    // explicit leak is simpler than threading a owner through AppModel.
    std::mem::forget(monitor);
}

