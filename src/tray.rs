//! Windows: Hintergrundprogramm mit Symbol im Infobereich der Taskleiste.
//!
//! - Tastenkombination (global) öffnet „Neuer Eintrag“ aus der Zwischenablage
//! - Linksklick auf das Symbol öffnet die Übersicht
//! - Rechtsklick: Menü mit Erfassen, Öffnen, Beenden
//! - Liest alle 2 Sekunden die Einstellungen: geänderte Tastenkombination wird
//!   übernommen, bei ausgeschaltetem Infobereich-Symbol beendet es sich selbst.

use std::fs::OpenOptions;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::UI::WindowsAndMessaging::{DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE};

use crate::config::Config;
use crate::platform::Hotkey;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ICON_PNG: &[u8] = include_bytes!("../assets/keycatch-32.png");

fn spawn(arg: Option<&str>) {
    if let Ok(exe) = std::env::current_exe() {
        let mut cmd = Command::new(exe);
        if let Some(a) = arg {
            cmd.arg(a);
        }
        let _ = cmd.creation_flags(CREATE_NO_WINDOW).spawn();
    }
}

pub fn run() {
    let config = Config::load();

    // Nur ein Hintergrundprogramm gleichzeitig.
    let _ = std::fs::create_dir_all(&config.data_dir);
    let Ok(lock) = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config.data_dir.join("hintergrund.lock"))
    else {
        return;
    };
    if lock.try_lock().is_err() {
        return;
    }

    let icon = match eframe::icon_data::from_png_bytes(ICON_PNG) {
        Ok(d) => Icon::from_rgba(d.rgba, d.width, d.height).ok(),
        Err(_) => None,
    };

    let menu = Menu::new();
    let item_capture = MenuItem::new("Neuer Eintrag aus Zwischenablage", true, None);
    let item_open = MenuItem::new("KeyCatch öffnen", true, None);
    let item_quit = MenuItem::new("Beenden", true, None);
    let _ = menu.append(&item_capture);
    let _ = menu.append(&item_open);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&item_quit);

    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("KeyCatch");
    if let Some(i) = icon {
        builder = builder.with_icon(i);
    }
    let Ok(_tray) = builder.build() else { return };

    let Ok(manager) = GlobalHotKeyManager::new() else { return };
    let mut hotkey_text = config.settings.tastenkombination.clone();
    let mut current = Hotkey::parse(&hotkey_text).and_then(|h| h.to_global());
    if let Some(h) = current {
        let _ = manager.register(h);
    }

    let mut last_check = Instant::now();
    let mut last_spawn = Instant::now() - Duration::from_secs(10);

    loop {
        // Windows-Nachrichten abarbeiten (nötig für Symbol und Tastenkombination).
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        while let Ok(ev) = GlobalHotKeyEvent::receiver().try_recv() {
            if ev.state == HotKeyState::Pressed
                && current.is_some_and(|h| h.id() == ev.id)
                && last_spawn.elapsed() > Duration::from_millis(800)
            {
                last_spawn = Instant::now();
                spawn(Some("capture"));
            }
        }

        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == *item_capture.id() {
                spawn(Some("capture"));
            } else if ev.id == *item_open.id() {
                spawn(None);
            } else if ev.id == *item_quit.id() {
                return;
            }
        }

        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                spawn(None);
            }
        }

        if last_check.elapsed() > Duration::from_secs(2) {
            last_check = Instant::now();
            let cfg = Config::load();
            if !cfg.settings.infobereich {
                return;
            }
            if cfg.settings.tastenkombination != hotkey_text {
                if let Some(h) = current {
                    let _ = manager.unregister(h);
                }
                hotkey_text = cfg.settings.tastenkombination.clone();
                current = Hotkey::parse(&hotkey_text).and_then(|h| h.to_global());
                if let Some(h) = current {
                    let _ = manager.register(h);
                }
            }
        }

        std::thread::sleep(Duration::from_millis(30));
    }
}
