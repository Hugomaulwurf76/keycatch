// Unter Windows kein Konsolenfenster öffnen.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod config;
mod inbox;
mod pin;
mod platform;
#[cfg(windows)]
mod tray;
mod vault;

use eframe::egui;

const ICON_PNG: &[u8] = include_bytes!("../assets/keycatch-256.png");

fn read_clipboard() -> Option<String> {
    let mut cb = arboard::Clipboard::new().ok()?;
    // Nur lesen – die Zwischenablage wird nicht verändert.
    let text = cb.get_text().ok()?;
    let text = text.trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn main() -> eframe::Result {
    #[cfg(target_os = "linux")]
    platform::prepare_graphics();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |names: &[&str]| args.iter().any(|a| names.contains(&a.as_str()));
    let capture = has(&["capture", "--capture", "-c"]);

    if has(&["--help", "-h"]) {
        println!(
            "KeyCatch {}\n\n  keycatch            Übersicht öffnen\n  keycatch capture    Inhalt der Zwischenablage als neuen Eintrag erfassen\n",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }

    #[cfg(windows)]
    {
        if has(&["--tray"]) {
            tray::run();
            return Ok(());
        }
        if has(&["--setup"]) {
            let config = config::Config::load();
            if let Err(e) = platform::setup(&config.settings) {
                eprintln!("{e}");
                std::process::exit(1);
            }
            return Ok(());
        }
    }

    let clipboard = if capture { read_clipboard() } else { None };
    let config = config::Config::load();
    // Beim automatischen Start (Windows-Anmeldung) ggf. minimiert öffnen.
    let start_minimized = has(&["--autostart"]) && config.settings.minimiert_starten;
    #[cfg(windows)]
    if config.settings.infobereich {
        // Läuft das Hintergrundprogramm schon, beendet sich die neue Instanz sofort.
        platform::start_tray();
    }
    let keyring_ok = platform::init_keyring();
    platform::cleanup_print_files();

    let mut viewport = egui::ViewportBuilder::default()
        .with_app_id("keycatch")
        .with_title(if capture { "KeyCatch – Neuer Eintrag" } else { "KeyCatch" });
    if let Ok(icon) = eframe::icon_data::from_png_bytes(ICON_PNG) {
        viewport = viewport.with_icon(icon);
    }
    viewport = if capture {
        viewport.with_inner_size([540.0, 680.0]).with_min_inner_size([420.0, 400.0]).with_always_on_top()
    } else {
        viewport.with_inner_size([980.0, 680.0]).with_min_inner_size([640.0, 420.0])
    };

    let options = eframe::NativeOptions { viewport, centered: true, ..Default::default() };

    eframe::run_native(
        "KeyCatch",
        options,
        Box::new(move |cc| Ok(Box::new(app::KeyCatchApp::new(cc, config, capture, clipboard, keyring_ok, start_minimized)))),
    )
}
