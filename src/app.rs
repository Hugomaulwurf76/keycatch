use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use zeroize::Zeroize;

use crate::config::{Config, FieldKind, TypeDef};
use crate::inbox;
use crate::platform::{self, Hotkey};
use crate::pin::{self, PinError};
use crate::vault::{
    self, generate_code, new_id, now_string, now_ts, restore_from, Entry, Unlock, Vault, VaultError, CODE_COUNT,
};

const RED: Color32 = Color32::from_rgb(220, 70, 70);
const ORANGE: Color32 = Color32::from_rgb(230, 150, 40);
const GREEN: Color32 = Color32::from_rgb(70, 170, 90);

struct EditState {
    id: Option<String>,
    kind: String,
    title: String,
    secret: String,
    fields: BTreeMap<String, String>,
    show_secret: bool,
    created: String,
}

impl Drop for EditState {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(PartialEq, Clone, Copy)]
enum UnlockMode {
    Pin,
    Password,
    Code,
}

enum Screen {
    Unlock,
    /// Neues Master-Passwort nach Entsperren mit Backup-Code.
    NewPassword { used_code: String },
    List,
    Edit(EditState),
    Settings,
}

struct CodesWindow {
    codes: Vec<String>,
    printed_or_copied: bool,
}

impl Drop for CodesWindow {
    fn drop(&mut self) {
        for c in &mut self.codes {
            c.zeroize();
        }
    }
}

#[derive(Default)]
struct SettingsForm {
    pin: String,
    cur_pw: String,
    new_pw: String,
    new_pw2: String,
    restore_path: Option<PathBuf>,
    restore_pw: String,
    recording_hotkey: bool,
    confirm_reset: bool,
    /// Eingabefelder für Farbcodes (Akzent, Hintergrund, Buttons, Schrift)
    hex: [String; 4],
}

impl Drop for SettingsForm {
    fn drop(&mut self) {
        self.pin.zeroize();
        self.cur_pw.zeroize();
        self.new_pw.zeroize();
        self.new_pw2.zeroize();
        self.restore_pw.zeroize();
    }
}

pub struct KeyCatchApp {
    config: Config,
    capture: bool,
    /// Erfassen ohne Entsperren: Eintrag geht verschlüsselt in den Posteingang.
    inbox_capture: bool,
    keyring_ok: bool,
    system_accent: Option<Color32>,
    pending_clipboard: Option<String>,
    vault: Option<Vault>,
    screen: Screen,
    unlock_mode: UnlockMode,
    password: String,
    password_repeat: String,
    code_input: String,
    error: Option<String>,
    info: Option<String>,
    search: String,
    selected: Option<String>,
    reveal_selected: bool,
    confirm_delete: bool,
    last_activity: Instant,
    last_sync_check: Instant,
    focus_password: bool,
    codes_window: Option<CodesWindow>,
    form: SettingsForm,
}

/// Farbcode #RRGGBB oder #RRGGBBAA (mit Deckkraft).
fn parse_hex_color(s: &str) -> Option<Color32> {
    let s = s.trim().trim_start_matches('#');
    if !(s.len() == 6 || s.len() == 8) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let v = u32::from_str_radix(s, 16).ok()?;
    Some(if s.len() == 6 {
        Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
    } else {
        Color32::from_rgba_unmultiplied((v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8)
    })
}

fn to_hex_color(c: Color32) -> String {
    let [r, g, b, a] = c.to_srgba_unmultiplied();
    if a == 255 { format!("#{r:02x}{g:02x}{b:02x}") } else { format!("#{r:02x}{g:02x}{b:02x}{a:02x}") }
}

/// Schiebeschalter (Ein/Aus).
#[cfg_attr(not(windows), allow(dead_code))]
fn toggle_switch(ui: &mut egui::Ui, on: &mut bool) -> egui::Response {
    let size = ui.spacing().interact_size.y * egui::vec2(2.0, 1.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool_responsive(response.id, *on);
        let visuals = ui.style().interact_selectable(&response, *on);
        let rect = rect.expand(visuals.expansion);
        let radius = 0.5 * rect.height();
        let fill = if *on { ui.visuals().selection.bg_fill } else { visuals.bg_fill };
        ui.painter().rect(rect, radius, fill, visuals.bg_stroke, egui::StrokeKind::Inside);
        let cx = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
        ui.painter().circle(egui::pos2(cx, rect.center().y), 0.75 * radius, visuals.fg_stroke.color, visuals.fg_stroke);
    }
    response
}

/// Relative Helligkeit 0..1 (für Kontrast-Entscheidungen).
fn luminance(c: Color32) -> f32 {
    (0.2126 * c.r() as f32 + 0.7152 * c.g() as f32 + 0.0722 * c.b() as f32) / 255.0
}

impl KeyCatchApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        config: Config,
        capture: bool,
        clipboard: Option<String>,
        keyring_ok: bool,
        start_minimized: bool,
    ) -> Self {
        if start_minimized {
            cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        let error = if config.warnings.is_empty() { None } else { Some(config.warnings.join("\n")) };
        let info = if config.notes.is_empty() { None } else { Some(config.notes.join("\n")) };
        let mut app = KeyCatchApp {
            config,
            capture,
            inbox_capture: false,
            keyring_ok,
            system_accent: platform::system_accent(),
            pending_clipboard: clipboard,
            vault: None,
            screen: Screen::Unlock,
            unlock_mode: UnlockMode::Password,
            password: String::new(),
            password_repeat: String::new(),
            code_input: String::new(),
            error,
            info,
            search: String::new(),
            selected: None,
            reveal_selected: false,
            confirm_delete: false,
            last_activity: Instant::now(),
            last_sync_check: Instant::now(),
            focus_password: true,
            codes_window: None,
            form: SettingsForm::default(),
        };
        app.apply_theme(&cc.egui_ctx);
        app.choose_unlock_mode();
        // Erfassen: Ist der Posteingang eingerichtet, wird nicht entsperrt.
        if capture
            && Vault::exists(&app.config.vault_path)
            && inbox::load_public(&app.inbox_dir()).is_some()
        {
            app.inbox_capture = true;
            app.start_capture_form();
        }
        app
    }

    fn inbox_dir(&self) -> PathBuf {
        inbox::dir_for(&self.config.dirs.inbox, &self.config.vault_path)
    }

    /// Öffnet die Eingabemaske für den Inhalt der Zwischenablage.
    fn start_capture_form(&mut self) {
        let secret = self.pending_clipboard.take().unwrap_or_default();
        if secret.is_empty() {
            self.info =
                Some("Zwischenablage konnte nicht gelesen werden oder ist leer – bitte mit Strg+V einfügen.".into());
        }
        self.screen = Screen::Edit(self.new_edit(secret));
    }

    /// Posteingang einrichten (nur `setup`) und erfasste Einträge übernehmen.
    fn sync_inbox(&mut self, setup: bool) {
        let dir = self.inbox_dir();
        let Some(v) = self.vault.as_mut() else { return };
        let mut msgs: Vec<String> = Vec::new();
        if setup {
            match v.setup_inbox() {
                Ok(true) => msgs.push("Die Schlüsseldatei des Posteingangs war verändert und wurde erneuert.".into()),
                Ok(false) => {}
                Err(e) => {
                    self.error = Some(format!("Posteingang: {e}"));
                    return;
                }
            }
        }
        match v.import_inbox() {
            Ok((0, 0)) => {}
            Ok((n, failed)) => {
                if n > 0 {
                    let text = if n == 1 { "1 erfasster Eintrag".to_string() } else { format!("{n} erfasste Einträge") };
                    self.info = Some(format!("{text} aus dem Posteingang übernommen."));
                }
                if failed > 0 {
                    msgs.push(format!(
                        "{failed} Datei(en) im Posteingang nicht lesbar (andere Datenbank?) – liegen weiter in {}",
                        dir.display()
                    ));
                }
            }
            Err(e) => msgs.push(format!("Posteingang: {e}")),
        }
        if !msgs.is_empty() {
            self.error = Some(msgs.join("\n"));
        }
    }

    // ------------------------------------------------------------ Darstellung

    fn apply_theme(&self, ctx: &egui::Context) {
        let s = &self.config.settings;
        ctx.set_theme(match s.darstellung.as_str() {
            "hell" => egui::ThemePreference::Light,
            "dunkel" => egui::ThemePreference::Dark,
            _ => egui::ThemePreference::System,
        });
        ctx.set_visuals_of(egui::Theme::Dark, egui::Visuals::dark());
        ctx.set_visuals_of(egui::Theme::Light, egui::Visuals::light());
        // Eingabefelder und Buttons immer mit sichtbarem Rahmen.
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            ctx.style_mut_of(theme, |st| {
                let v = &mut st.visuals;
                let away = if v.dark_mode { Color32::WHITE } else { Color32::BLACK };
                v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, v.panel_fill.lerp_to_gamma(away, 0.25));
            });
        }
        let accent = match s.akzent.as_str() {
            "system" => self.system_accent,
            "individuell" => parse_hex_color(&s.akzent_farbe),
            _ => None,
        };
        if let Some(a) = accent {
            for theme in [egui::Theme::Dark, egui::Theme::Light] {
                ctx.style_mut_of(theme, |st| {
                    st.visuals.selection.bg_fill = a;
                    st.visuals.hyperlink_color = a;
                    st.visuals.text_cursor.stroke.color = a;
                    st.visuals.widgets.hovered.bg_stroke.color = a;
                });
            }
        }
        if s.akzent != "individuell" {
            return;
        }
        let bg = parse_hex_color(&s.farbe_hintergrund);
        let mut btn = parse_hex_color(&s.farbe_button);
        let mut text = parse_hex_color(&s.farbe_schrift);
        // Bei eigenem Hintergrund passen sich Schrift und Buttons, die auf
        // „Standard“ stehen, automatisch an, damit alles lesbar bleibt.
        if let Some(bg) = bg {
            let light = luminance(bg) > 0.5;
            let away = if light { Color32::BLACK } else { Color32::WHITE };
            if text.is_none() {
                text = Some(if light { Color32::from_gray(30) } else { Color32::from_gray(230) });
            }
            if btn.is_none() {
                btn = Some(bg.lerp_to_gamma(away, 0.12));
            }
        }
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            ctx.style_mut_of(theme, |st| {
                let v = &mut st.visuals;
                if let Some(bg) = bg {
                    let light = luminance(bg) > 0.5;
                    let away = if light { Color32::BLACK } else { Color32::WHITE };
                    let field = if light { bg.lerp_to_gamma(Color32::BLACK, 0.05) } else { bg.lerp_to_gamma(Color32::BLACK, 0.35) };
                    let line = bg.lerp_to_gamma(away, 0.25);
                    v.dark_mode = !light;
                    v.panel_fill = bg;
                    v.window_fill = bg;
                    v.faint_bg_color = bg.lerp_to_gamma(away, 0.04);
                    v.extreme_bg_color = field;
                    v.text_edit_bg_color = Some(field);
                    v.widgets.noninteractive.bg_fill = bg;
                    v.widgets.noninteractive.weak_bg_fill = bg;
                    v.widgets.noninteractive.bg_stroke.color = line;
                    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, line);
                    v.window_stroke.color = line;
                }
                if let Some(b) = btn {
                    let hover = if luminance(b) > 0.5 { Color32::BLACK } else { Color32::WHITE };
                    v.widgets.inactive.bg_fill = b;
                    v.widgets.inactive.weak_bg_fill = b;
                    v.widgets.hovered.bg_fill = b.lerp_to_gamma(hover, 0.15);
                    v.widgets.hovered.weak_bg_fill = b.lerp_to_gamma(hover, 0.15);
                    v.widgets.active.bg_fill = b.lerp_to_gamma(hover, 0.3);
                    v.widgets.active.weak_bg_fill = b.lerp_to_gamma(hover, 0.3);
                    v.widgets.open.weak_bg_fill = b.lerp_to_gamma(hover, 0.15);
                }
                if let Some(t) = text {
                    v.override_text_color = Some(t);
                    for w in [
                        &mut v.widgets.noninteractive,
                        &mut v.widgets.inactive,
                        &mut v.widgets.hovered,
                        &mut v.widgets.active,
                        &mut v.widgets.open,
                    ] {
                        w.fg_stroke.color = t;
                    }
                }
            });
        }
    }

    // ------------------------------------------------------------ Allgemein

    fn choose_unlock_mode(&mut self) {
        self.unlock_mode = if self.config.settings.pin_aktiv
            && self.keyring_ok
            && pin::active(&self.config.data_dir, &self.config.vault_path)
        {
            UnlockMode::Pin
        } else {
            UnlockMode::Password
        };
    }

    fn default_kind(&self) -> String {
        self.config.types.first().map(|t| t.name.clone()).unwrap_or_else(|| "Sonstiges".into())
    }

    fn new_edit(&self, secret: String) -> EditState {
        EditState {
            id: None,
            kind: self.default_kind(),
            title: String::new(),
            secret,
            fields: BTreeMap::new(),
            show_secret: false,
            created: String::new(),
        }
    }

    /// Sperrt. `end_pin` beendet zusätzlich die PIN-Freigabe.
    fn lock(&mut self, end_pin: bool) {
        if end_pin {
            pin::clear(&self.config.data_dir);
        }
        self.vault = None;
        self.screen = Screen::Unlock;
        self.selected = None;
        self.reveal_selected = false;
        self.confirm_delete = false;
        self.codes_window = None;
        self.form = SettingsForm::default();
        self.password.zeroize();
        self.password_repeat.zeroize();
        self.code_input.zeroize();
        self.focus_password = true;
        self.choose_unlock_mode();
        self.info = Some("Gesperrt.".into());
    }

    /// Nach jedem erfolgreichen Entsperren.
    fn after_unlock(&mut self, start_pin: bool) {
        self.password.zeroize();
        self.password_repeat.zeroize();
        self.code_input.zeroize();
        self.error = None;
        self.info = None;
        self.last_activity = Instant::now();

        if let Some(v) = self.vault.as_mut() {
            match v.merge_conflicts() {
                Ok(0) => {}
                Ok(n) => self.info = Some(format!("{n} Konfliktkopie(n) der Synchronisierung zusammengeführt.")),
                Err(e) => self.error = Some(format!("Konfliktkopien: {e}")),
            }
        }
        if start_pin {
            self.start_pin_window();
        }
        self.sync_inbox(true);

        if self.capture {
            self.start_capture_form();
        } else {
            self.screen = Screen::List;
        }
    }

    fn start_pin_window(&mut self) {
        if !(self.config.settings.pin_aktiv && self.keyring_ok) {
            return;
        }
        let Some(v) = self.vault.as_ref() else { return };
        let Some(pd) = v.data.pin.clone() else { return };
        if let Err(e) = pin::start(&self.config.data_dir, v.path(), v.dek(), &pd) {
            self.error = Some(format!("PIN-Freigabe nicht möglich: {e}"));
        }
    }

    fn save_settings(&mut self, ctx: &egui::Context) {
        if let Err(e) = self.config.save() {
            self.error = Some(e);
        }
        self.apply_theme(ctx);
    }

    // ------------------------------------------------------------ Entsperren

    fn ui_unlock(&mut self, ui: &mut egui::Ui) {
        let exists = Vault::exists(&self.config.vault_path);
        ui.add_space(30.0);
        ui.vertical_centered(|ui| {
            ui.heading(RichText::new("🔑 KeyCatch").size(28.0));
            ui.add_space(6.0);

            if !exists {
                self.ui_create(ui);
            } else {
                match self.unlock_mode {
                    UnlockMode::Pin => self.ui_unlock_pin(ui),
                    UnlockMode::Password => self.ui_unlock_password(ui),
                    UnlockMode::Code => self.ui_unlock_code(ui),
                }
            }

            ui.add_space(16.0);
            ui.label(RichText::new(format!("Datenbank: {}", self.config.vault_path.display())).small().weak());
            ui.label(
                RichText::new(format!("Einstellungen und Typen: {}", self.config.config_dir.display())).small().weak(),
            );
        });
    }

    fn password_field(&mut self, ui: &mut egui::Ui, hint: &str, repeat: bool) -> bool {
        let target = if repeat { &mut self.password_repeat } else { &mut self.password };
        let r = ui.add(egui::TextEdit::singleline(target).password(true).hint_text(hint).desired_width(280.0));
        if self.focus_password && !repeat {
            r.request_focus();
            self.focus_password = false;
        }
        r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
    }

    fn ui_create(&mut self, ui: &mut egui::Ui) {
        ui.label("Neue Datenbank anlegen");
        ui.label(RichText::new("Ohne das Master-Passwort sind die Daten nicht wiederherstellbar.").color(ORANGE));
        ui.add_space(12.0);
        let mut submit = self.password_field(ui, "Master-Passwort", false);
        submit |= self.password_field(ui, "Wiederholen", true);
        ui.add_space(8.0);
        submit |= ui.button("Datenbank anlegen").clicked();
        ui.add_space(8.0);
        if ui.link("Vorhandene Datenbank öffnen …").clicked() {
            self.use_other_database();
            return;
        }
        if submit {
            if self.password.chars().count() < 10 {
                self.error = Some("Das Master-Passwort muss mindestens 10 Zeichen haben.".into());
            } else if self.password != self.password_repeat {
                self.error = Some("Die Passwörter stimmen nicht überein.".into());
            } else {
                match Vault::create(&self.config.vault_path, &self.config.dirs, &self.password) {
                    Ok(v) => {
                        self.vault = Some(v);
                        self.after_unlock(true);
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        }
    }

    fn ui_unlock_password(&mut self, ui: &mut egui::Ui) {
        ui.label("Master-Passwort eingeben");
        ui.add_space(12.0);
        let mut submit = self.password_field(ui, "Master-Passwort", false);
        ui.add_space(8.0);
        submit |= ui.button("Entsperren").clicked();
        if submit {
            match Vault::open(&self.config.vault_path, &self.config.dirs, Unlock::Password(&self.password)) {
                Ok(v) => {
                    self.vault = Some(v);
                    self.after_unlock(true);
                    return;
                }
                Err(e) => {
                    self.error = Some(e.to_string());
                    self.password.zeroize();
                    self.focus_password = true;
                }
            }
        }
        ui.add_space(10.0);
        if ui.link("Master-Passwort vergessen? Backup-Code verwenden").clicked() {
            self.unlock_mode = UnlockMode::Code;
            self.error = None;
        }
        if self.config.settings.pin_aktiv
            && pin::active(&self.config.data_dir, &self.config.vault_path)
            && ui.link("Mit PIN entsperren").clicked()
        {
            self.unlock_mode = UnlockMode::Pin;
            self.focus_password = true;
        }
    }

    fn ui_unlock_pin(&mut self, ui: &mut egui::Ui) {
        if !pin::active(&self.config.data_dir, &self.config.vault_path) {
            self.unlock_mode = UnlockMode::Password;
            return;
        }
        ui.label("PIN eingeben");
        ui.add_space(12.0);
        let mut submit = self.password_field(ui, "PIN", false);
        ui.add_space(8.0);
        submit |= ui.button("Entsperren").clicked();
        if submit {
            let res = pin::unlock(&self.config.data_dir, &self.config.vault_path, &self.password);
            self.password.zeroize();
            self.focus_password = true;
            match res {
                Ok(dek) => match Vault::open(&self.config.vault_path, &self.config.dirs, Unlock::Key(&dek)) {
                    Ok(v) => {
                        self.vault = Some(v);
                        self.after_unlock(true);
                        return;
                    }
                    Err(e) => {
                        pin::clear(&self.config.data_dir);
                        self.unlock_mode = UnlockMode::Password;
                        self.error = Some(e.to_string());
                    }
                },
                Err(PinError::Wrong(0)) | Err(PinError::Gone) => {
                    self.unlock_mode = UnlockMode::Password;
                    self.error = Some("PIN nicht mehr verwendbar – bitte Master-Passwort eingeben.".into());
                }
                Err(PinError::Wrong(n)) => {
                    self.error = Some(format!("Falsche PIN. Noch {n} Versuch(e)."));
                }
                Err(PinError::Other(e)) => self.error = Some(e),
            }
        }
        ui.add_space(10.0);
        if ui.link("Master-Passwort verwenden").clicked() {
            self.unlock_mode = UnlockMode::Password;
            self.focus_password = true;
        }
    }

    fn ui_unlock_code(&mut self, ui: &mut egui::Ui) {
        ui.label("Backup-Code eingeben");
        ui.label(RichText::new("Danach legst du ein neues Master-Passwort fest. Der Code ist dann verbraucht.").weak());
        ui.add_space(12.0);
        let r = ui.add(
            egui::TextEdit::singleline(&mut self.code_input)
                .hint_text("XXXXX-XXXXX-XXXXX-XXXXX")
                .font(egui::TextStyle::Monospace)
                .desired_width(280.0),
        );
        let mut submit = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(8.0);
        submit |= ui.button("Mit Backup-Code entsperren").clicked();
        if submit {
            match Vault::open(&self.config.vault_path, &self.config.dirs, Unlock::Code(&self.code_input)) {
                Ok(v) => {
                    self.vault = Some(v);
                    self.error = None;
                    let used = std::mem::take(&mut self.code_input);
                    self.screen = Screen::NewPassword { used_code: used };
                    self.focus_password = true;
                    return;
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        ui.add_space(10.0);
        if ui.link("Zurück zum Master-Passwort").clicked() {
            self.unlock_mode = UnlockMode::Password;
            self.focus_password = true;
        }
    }

    fn ui_new_password(&mut self, ui: &mut egui::Ui, used_code: &str) -> bool {
        let mut done = false;
        ui.add_space(30.0);
        ui.vertical_centered(|ui| {
            ui.heading("Neues Master-Passwort");
            ui.label("Mit dem Backup-Code entsperrt. Lege jetzt ein neues Master-Passwort fest.");
            ui.add_space(12.0);
            let mut submit = self.password_field(ui, "Neues Master-Passwort", false);
            submit |= self.password_field(ui, "Wiederholen", true);
            ui.add_space(8.0);
            submit |= ui.button("Speichern").clicked();
            if submit {
                if self.password.chars().count() < 10 {
                    self.error = Some("Das Master-Passwort muss mindestens 10 Zeichen haben.".into());
                } else if self.password != self.password_repeat {
                    self.error = Some("Die Passwörter stimmen nicht überein.".into());
                } else if let Some(v) = self.vault.as_mut() {
                    let pw = self.password.clone();
                    let res = v.set_password(&pw).and_then(|_| v.consume_code(used_code));
                    let mut pw = pw;
                    pw.zeroize();
                    match res {
                        Ok(()) => {
                            let left = v.code_slots();
                            self.after_unlock(true);
                            self.info = Some(format!(
                                "Neues Master-Passwort gespeichert. Noch {left} unbenutzte Backup-Code(s)."
                            ));
                            done = true;
                        }
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
            }
        });
        done
    }

    // ------------------------------------------------------------ Übersicht

    fn ui_list(&mut self, ui: &mut egui::Ui) {
        // Änderungen von anderen Fenstern / der Synchronisierung übernehmen.
        if self.last_sync_check.elapsed() > Duration::from_secs(5) {
            self.last_sync_check = Instant::now();
            if let Some(v) = self.vault.as_mut() {
                match v.reload_if_changed().and_then(|_| v.merge_conflicts()) {
                    Ok(n) if n > 0 => self.info = Some(format!("{n} Konfliktkopie(n) zusammengeführt.")),
                    Ok(_) => {}
                    Err(VaultError::Replaced) => {
                        self.lock(true);
                        self.error = Some(VaultError::Replaced.to_string());
                        return;
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
            // Während KeyCatch offen ist, erfasste Einträge gleich übernehmen.
            self.sync_inbox(false);
            ui.ctx().request_repaint_after(Duration::from_secs(5));
        }

        let Some(vault) = self.vault.as_ref() else { return };
        let needle = self.search.to_lowercase();
        let mut items: Vec<(String, String, String)> = vault
            .data
            .entries
            .iter()
            .filter(|e| {
                needle.is_empty()
                    || e.title.to_lowercase().contains(&needle)
                    || e.kind.to_lowercase().contains(&needle)
                    || e.fields.values().any(|v| v.to_lowercase().contains(&needle))
            })
            .map(|e| (e.id.clone(), e.title.clone(), e.kind.clone()))
            .collect();
        items.sort_by_key(|a| a.1.to_lowercase());

        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("➕ Neu").clicked() {
                    self.screen = Screen::Edit(self.new_edit(String::new()));
                }
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("🔍 Suchen …").desired_width(260.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔒 Sperren").clicked() {
                        self.lock(false);
                    }
                    if ui.button("⚙ Einstellungen").clicked() {
                        self.screen = Screen::Settings;
                    }
                });
            });
            ui.add_space(4.0);
        });
        if self.vault.is_none() || !matches!(self.screen, Screen::List) {
            return;
        }

        egui::Panel::left("liste").resizable(true).default_size(320.0).show(ui, |ui| {
            ui.add_space(4.0);
            let n = items.len();
            ui.label(RichText::new(if n == 1 { "1 Eintrag".to_string() } else { format!("{n} Einträge") }).weak());
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                for (id, title, kind) in &items {
                    let sel = self.selected.as_deref() == Some(id.as_str());
                    if ui.add(egui::Button::selectable(sel, format!("{title}\n{kind}"))).clicked() {
                        self.selected = Some(id.clone());
                        self.reveal_selected = false;
                        self.confirm_delete = false;
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            let Some(sel) = self.selected.clone() else {
                ui.label("Eintrag links auswählen.");
                return;
            };
            let Some(entry) =
                self.vault.as_ref().and_then(|v| v.data.entries.iter().find(|e| e.id == sel)).cloned()
            else {
                self.selected = None;
                return;
            };
            self.ui_detail(ui, &entry);
        });
    }

    fn ui_detail(&mut self, ui: &mut egui::Ui, entry: &Entry) {
        ui.heading(&entry.title);
        ui.label(RichText::new(&entry.kind).weak());
        ui.add_space(10.0);

        let typedef = self.config.type_def(&entry.kind).cloned();
        let secret_label = typedef.as_ref().map(|t| t.secret_label.clone()).unwrap_or("Geheimnis".into());

        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            egui::Grid::new("detail").num_columns(2).spacing([14.0, 8.0]).striped(true).show(ui, |ui| {
                ui.label(RichText::new(&secret_label).strong());
                let shown = if self.reveal_selected {
                    entry.secret.clone()
                } else {
                    "•".repeat(entry.secret.chars().count().min(24))
                };
                ui.add(egui::Label::new(RichText::new(shown).monospace()).wrap());
                ui.end_row();

                ui.label("");
                ui.horizontal(|ui| {
                    let t = if self.reveal_selected { "🙈 Verbergen" } else { "👁 Anzeigen" };
                    if ui.button(t).clicked() {
                        self.reveal_selected = !self.reveal_selected;
                    }
                    if ui.button("📋 Kopieren").clicked() {
                        ui.ctx().copy_text(entry.secret.clone());
                        self.info = Some(format!("{secret_label} in die Zwischenablage kopiert."));
                    }
                });
                ui.end_row();

                let mut shown_keys = Vec::new();
                if let Some(td) = &typedef {
                    for f in &td.fields {
                        shown_keys.push(f.key.clone());
                        if let Some(v) = entry.fields.get(&f.key).filter(|v| !v.is_empty()) {
                            ui.label(RichText::new(&f.label).strong());
                            if f.kind == FieldKind::Url && v.starts_with("http") {
                                ui.hyperlink_to(v, v);
                            } else {
                                ui.add(egui::Label::new(v).wrap());
                            }
                            ui.end_row();
                        }
                    }
                }
                for (k, v) in &entry.fields {
                    if !shown_keys.contains(k) && !v.is_empty() {
                        ui.label(RichText::new(k).strong());
                        ui.add(egui::Label::new(v).wrap());
                        ui.end_row();
                    }
                }

                ui.label(RichText::new("Angelegt").weak());
                ui.label(RichText::new(&entry.created).weak());
                ui.end_row();
                ui.label(RichText::new("Geändert").weak());
                ui.label(RichText::new(&entry.updated).weak());
                ui.end_row();
            });

            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button("✏ Bearbeiten").clicked() {
                    self.screen = Screen::Edit(EditState {
                        id: Some(entry.id.clone()),
                        kind: entry.kind.clone(),
                        title: entry.title.clone(),
                        secret: entry.secret.clone(),
                        fields: entry.fields.clone(),
                        show_secret: false,
                        created: entry.created.clone(),
                    });
                }
                if !self.confirm_delete {
                    if ui.button("🗑 Löschen").clicked() {
                        self.confirm_delete = true;
                    }
                } else {
                    ui.label(RichText::new("Wirklich löschen?").color(RED));
                    if ui.button(RichText::new("Ja, löschen").color(RED)).clicked() {
                        let id = entry.id.clone();
                        if let Some(v) = self.vault.as_mut() {
                            match v.modify(|d| d.delete(&id)) {
                                Ok(()) => {
                                    self.selected = None;
                                    self.info = Some("Eintrag gelöscht.".into());
                                }
                                Err(e) => self.error = Some(e.to_string()),
                            }
                        }
                        self.confirm_delete = false;
                    }
                    if ui.button("Abbrechen").clicked() {
                        self.confirm_delete = false;
                    }
                }
            });
        });
    }

    // ------------------------------------------------------------ Bearbeiten

    fn ui_edit(&mut self, ui: &mut egui::Ui, mut edit: EditState) -> Option<EditState> {
        let types = self.config.types.clone();
        let typedef: Option<TypeDef> = types.iter().find(|t| t.name == edit.kind).cloned();
        let mut save = false;
        let mut cancel = false;
        let mut date_errors: Vec<String> = Vec::new();

        egui::Panel::bottom("buttons").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let can_save = !edit.secret.trim().is_empty();
                if ui.add_enabled(can_save, egui::Button::new("💾 Speichern")).clicked() {
                    save = true;
                }
                if ui.button("Abbrechen").clicked() {
                    cancel = true;
                }
                ui.label(RichText::new("Strg+Enter = Speichern").weak().small());
            });
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                ui.heading(if edit.id.is_some() { "Eintrag bearbeiten" } else { "Neuer Eintrag" });
                if self.inbox_capture {
                    ui.label(
                        RichText::new("Wird verschlüsselt gespeichert und beim nächsten Entsperren in die Übersicht übernommen.")
                            .weak(),
                    );
                }
                ui.add_space(8.0);

                egui::Grid::new("edit").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
                    ui.label(RichText::new("Typ").strong());
                    egui::ComboBox::from_id_salt("typ").selected_text(&edit.kind).width(240.0).show_ui(ui, |ui| {
                        for t in &types {
                            ui.selectable_value(&mut edit.kind, t.name.clone(), &t.name);
                        }
                    });
                    ui.end_row();

                    let secret_label = typedef.as_ref().map(|t| t.secret_label.as_str()).unwrap_or("Geheimnis");
                    ui.label(RichText::new(secret_label).strong());
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut edit.secret)
                                .password(!edit.show_secret)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(300.0),
                        );
                        if ui.button(if edit.show_secret { "🙈" } else { "👁" }).clicked() {
                            edit.show_secret = !edit.show_secret;
                        }
                    });
                    ui.end_row();

                    ui.label(RichText::new("Titel").strong());
                    ui.add(egui::TextEdit::singleline(&mut edit.title).hint_text("leer = automatisch").desired_width(340.0));
                    ui.end_row();

                    if let Some(td) = &typedef {
                        for f in &td.fields {
                            ui.label(&f.label);
                            let value = edit.fields.entry(f.key.clone()).or_default();
                            let mut te = match f.kind {
                                FieldKind::Multiline => egui::TextEdit::multiline(value).desired_rows(3),
                                _ => egui::TextEdit::singleline(value),
                            }
                            .desired_width(340.0);
                            if !f.hint.is_empty() {
                                te = te.hint_text(&f.hint);
                            }
                            ui.add(te);
                            ui.end_row();

                            if f.kind == FieldKind::Date
                                && !value.trim().is_empty()
                                && jiff::civil::Date::strptime("%d.%m.%Y", value.trim()).is_err()
                            {
                                date_errors.push(format!("„{}“: Datum bitte als TT.MM.JJJJ eingeben.", f.label));
                            }
                        }
                    }
                });

                for e in &date_errors {
                    ui.colored_label(RED, e);
                }

                if let Some(v) = &self.vault {
                    let s = edit.secret.trim();
                    if !s.is_empty()
                        && let Some(dup) =
                            v.data.entries.iter().find(|e| e.secret == s && Some(&e.id) != edit.id.as_ref())
                    {
                        ui.add_space(6.0);
                        ui.colored_label(ORANGE, format!("Bereits gespeichert als „{}“.", dup.title));
                    }
                }
            });
        });

        if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::Enter)) && !edit.secret.trim().is_empty() {
            save = true;
        }

        if cancel {
            if self.capture {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                return None;
            }
            self.screen = Screen::List;
            return None;
        }

        if save && date_errors.is_empty() {
            let keys: Vec<String> =
                typedef.as_ref().map(|t| t.fields.iter().map(|f| f.key.clone()).collect()).unwrap_or_default();
            let fields: BTreeMap<String, String> = edit
                .fields
                .iter()
                .filter(|(k, v)| keys.contains(k) && !v.trim().is_empty())
                .map(|(k, v)| (k.clone(), v.trim().to_string()))
                .collect();

            let mut title = edit.title.trim().to_string();
            if title.is_empty() {
                let parts: Vec<String> = typedef
                    .as_ref()
                    .map(|t| t.title_from.iter().filter_map(|k| fields.get(k).cloned()).collect())
                    .unwrap_or_default();
                title = if parts.is_empty() { format!("{} vom {}", edit.kind, now_string()) } else { parts.join(" – ") };
            }

            let now = now_string();
            let entry = Entry {
                id: edit.id.clone().unwrap_or_else(new_id),
                kind: edit.kind.clone(),
                title: title.clone(),
                secret: edit.secret.trim().to_string(),
                fields,
                created: if edit.created.is_empty() { now.clone() } else { edit.created.clone() },
                updated: now,
                updated_ts: now_ts(),
            };
            let id = entry.id.clone();

            let result: Result<(), String> = match self.vault.as_mut() {
                Some(v) => v
                    .modify(move |d| {
                        d.deleted.remove(&entry.id);
                        if let Some(pos) = d.entries.iter().position(|e| e.id == entry.id) {
                            d.entries[pos] = entry;
                        } else {
                            d.entries.push(entry);
                        }
                    })
                    .map_err(|e| e.to_string()),
                None if self.inbox_capture => inbox::deposit(&self.inbox_dir(), &entry),
                None => Err("Datenbank ist gesperrt.".into()),
            };
            match result {
                Ok(()) => {
                    if self.capture {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        return None;
                    }
                    self.info = Some(format!("„{title}“ gespeichert."));
                    self.error = None;
                    self.selected = Some(id);
                    self.reveal_selected = false;
                    self.screen = Screen::List;
                    return None;
                }
                Err(e) => self.error = Some(e),
            }
        }
        Some(edit)
    }

    // ------------------------------------------------------------ Einstellungen

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("settings_top").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("⬅ Zurück").clicked() {
                    self.form = SettingsForm::default();
                    self.screen = Screen::List;
                }
                ui.heading("Einstellungen");
            });
            ui.add_space(4.0);
        });
        if !matches!(self.screen, Screen::Settings) {
            return;
        }
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                self.section_appearance(ui);
                ui.separator();
                self.section_security(ui);
                ui.separator();
                self.section_database(ui);
                ui.separator();
                #[cfg(windows)]
                {
                    self.section_autostart(ui);
                    ui.separator();
                }
                self.section_hotkey(ui);
                ui.separator();
                self.section_reset(ui);
                ui.add_space(20.0);
            });
        });
    }

    fn section_appearance(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Darstellung");
        ui.add_space(4.0);
        let before = self.config.settings.clone();
        egui::Grid::new("appearance").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
            ui.label("Modus");
            ui.horizontal(|ui| {
                let s = &mut self.config.settings.darstellung;
                ui.radio_value(s, "automatisch".to_string(), "Automatisch (System)");
                ui.radio_value(s, "hell".to_string(), "Hell");
                ui.radio_value(s, "dunkel".to_string(), "Dunkel");
            });
            ui.end_row();

            ui.label("Farben");
            ui.horizontal(|ui| {
                let s = &mut self.config.settings.akzent;
                ui.radio_value(s, "standard".to_string(), "Standard");
                let sys = if self.system_accent.is_some() { "Systemfarbe" } else { "Systemfarbe (nicht erkannt)" };
                ui.radio_value(s, "system".to_string(), sys);
                ui.radio_value(s, "individuell".to_string(), "Individuell");
            });
            ui.end_row();

            if self.config.settings.akzent == "individuell" {
                let vis = ui.visuals().clone();
                let defaults = [
                    ("Akzent", vis.selection.bg_fill),
                    ("Hintergrund", vis.panel_fill),
                    ("Buttons", vis.widgets.inactive.weak_bg_fill),
                    ("Schrift", vis.text_color()),
                ];
                let mut hex_error = None;
                for (i, (label, fallback)) in defaults.into_iter().enumerate() {
                    let st = &mut self.config.settings;
                    let field = match i {
                        0 => &mut st.akzent_farbe,
                        1 => &mut st.farbe_hintergrund,
                        2 => &mut st.farbe_button,
                        _ => &mut st.farbe_schrift,
                    };
                    let buf = &mut self.form.hex[i];
                    ui.label(label);
                    ui.horizontal(|ui| {
                        let mut c = parse_hex_color(field).unwrap_or(fallback);
                        if ui.color_edit_button_srgba(&mut c).changed() {
                            *field = to_hex_color(c);
                        }
                        let r = ui.add(
                            egui::TextEdit::singleline(buf)
                                .hint_text("#RRGGBB")
                                .font(egui::TextStyle::Monospace)
                                .desired_width(110.0),
                        );
                        if r.lost_focus() {
                            let t = buf.trim().to_string();
                            if t.is_empty() {
                                field.clear();
                            } else if parse_hex_color(&t).is_some() {
                                // Code genau so übernehmen, wie eingegeben (nur vereinheitlicht).
                                *field = format!("#{}", t.trim_start_matches('#').to_lowercase());
                            } else {
                                hex_error = Some(format!("„{t}“ ist kein gültiger Farbcode. Erlaubt: #RRGGBB oder #RRGGBBAA."));
                            }
                        }
                        if !r.has_focus() {
                            *buf = field.clone();
                        }
                        // Immer an derselben Stelle; ausgegraut, solange die Standardfarbe aktiv ist.
                        if ui.add_enabled(!field.is_empty(), egui::Button::new("Standard").small()).clicked() {
                            field.clear();
                            buf.clear();
                        }
                    });
                    ui.end_row();
                }
                if let Some(e) = hex_error {
                    self.error = Some(e);
                }
            }
        });
        if self.config.settings != before {
            let ctx = ui.ctx().clone();
            self.save_settings(&ctx);
        }
    }

    fn section_security(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Sicherheit");
        ui.add_space(4.0);
        let before = self.config.settings.clone();

        egui::Grid::new("security").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
            ui.label("Automatische Sperre");
            ui.horizontal(|ui| {
                ui.add(egui::DragValue::new(&mut self.config.settings.auto_sperre_minuten).range(0..=240).suffix(" min"));
                ui.label(RichText::new("0 = aus").weak());
            });
            ui.end_row();

            ui.label("PIN-Freigabe");
            ui.vertical(|ui| {
                if !self.keyring_ok {
                    ui.colored_label(ORANGE, "Nicht verfügbar: Schlüsselspeicher des Systems nicht erreichbar.");
                    return;
                }
                ui.checkbox(
                    &mut self.config.settings.pin_aktiv,
                    "Nach dem ersten Entsperren mit Master-Passwort nur noch die PIN verlangen",
                );
                let has_pin = self.vault.as_ref().is_some_and(|v| v.data.pin.is_some());
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.form.pin)
                            .password(true)
                            .hint_text(if has_pin { "Neue PIN" } else { "PIN (4–8 Ziffern)" })
                            .desired_width(140.0),
                    );
                    if ui.button("PIN speichern").clicked() {
                        self.save_pin();
                    }
                    ui.label(RichText::new(if has_pin { "PIN ist festgelegt" } else { "Noch keine PIN" }).weak());
                    if has_pin && ui.button("PIN löschen").clicked() {
                        self.delete_pin();
                    }
                });
                if pin::active(&self.config.data_dir, &self.config.vault_path) {
                    ui.label(RichText::new("PIN-Freigabe aktiv").color(GREEN));
                }
            });
            ui.end_row();

            ui.label("Master-Passwort");
            ui.vertical(|ui| {
                let w = 220.0;
                ui.add(egui::TextEdit::singleline(&mut self.form.cur_pw).password(true).hint_text("Aktuelles Passwort").desired_width(w));
                ui.add(egui::TextEdit::singleline(&mut self.form.new_pw).password(true).hint_text("Neues Passwort").desired_width(w));
                ui.add(egui::TextEdit::singleline(&mut self.form.new_pw2).password(true).hint_text("Wiederholen").desired_width(w));
                if ui.button("Master-Passwort ändern").clicked() {
                    self.change_password();
                }
            });
            ui.end_row();

            ui.label("Backup-Codes");
            ui.vertical(|ui| {
                let n = self.vault.as_ref().map(|v| v.code_slots()).unwrap_or(0);
                if n == 0 {
                    ui.colored_label(ORANGE, "Keine Backup-Codes vorhanden.");
                } else {
                    ui.label(format!("{n} von {CODE_COUNT} Codes unbenutzt."));
                }
                if ui.button("Neue Backup-Codes erstellen").clicked() {
                    self.codes_window = Some(CodesWindow {
                        codes: (0..CODE_COUNT).map(|_| generate_code()).collect(),
                        printed_or_copied: false,
                    });
                }
                ui.label(RichText::new("Neue Codes ersetzen alle bisherigen erst nach deiner Bestätigung.").weak().small());
            });
            ui.end_row();
        });

        if self.config.settings != before {
            if !self.config.settings.pin_aktiv {
                pin::clear(&self.config.data_dir);
            }
            let ctx = ui.ctx().clone();
            self.save_settings(&ctx);
        }
    }

    fn save_pin(&mut self) {
        let p = self.form.pin.trim().to_string();
        if !(4..=8).contains(&p.len()) || !p.chars().all(|c| c.is_ascii_digit()) {
            self.error = Some("Die PIN muss aus 4 bis 8 Ziffern bestehen.".into());
            return;
        }
        let pd = match pin::make_pin_data(&p) {
            Ok(pd) => pd,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.form.pin.zeroize();
        let Some(v) = self.vault.as_mut() else { return };
        match v.modify(|d| {
            d.pin = Some(pd);
            d.pin_changed = now_ts();
        }) {
            Ok(()) => {
                self.config.settings.pin_aktiv = true;
                if let Err(e) = self.config.save() {
                    self.error = Some(e);
                }
                self.start_pin_window();
                self.info = Some("PIN gespeichert. Zum Entsperren reicht ab jetzt die PIN.".into());
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Löscht die PIN aus der Datenbank und beendet die Freigabe.
    fn delete_pin(&mut self) {
        pin::clear(&self.config.data_dir);
        let Some(v) = self.vault.as_mut() else { return };
        match v.modify(|d| {
            d.pin = None;
            d.pin_changed = now_ts();
        }) {
            Ok(()) => {
                self.config.settings.pin_aktiv = false;
                if let Err(e) = self.config.save() {
                    self.error = Some(e);
                }
                self.info = Some("PIN gelöscht. Zum Entsperren ist wieder das Master-Passwort nötig.".into());
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn change_password(&mut self) {
        if self.form.new_pw.chars().count() < 10 {
            self.error = Some("Das neue Master-Passwort muss mindestens 10 Zeichen haben.".into());
            return;
        }
        if self.form.new_pw != self.form.new_pw2 {
            self.error = Some("Die neuen Passwörter stimmen nicht überein.".into());
            return;
        }
        if Vault::peek(&self.config.vault_path, Unlock::Password(&self.form.cur_pw)).is_err() {
            self.error = Some("Das aktuelle Master-Passwort ist falsch.".into());
            return;
        }
        let new_pw = self.form.new_pw.clone();
        if let Some(v) = self.vault.as_mut() {
            match v.set_password(&new_pw) {
                Ok(()) => {
                    self.info = Some("Master-Passwort geändert.".into());
                    self.error = None;
                    self.form.cur_pw.zeroize();
                    self.form.new_pw.zeroize();
                    self.form.new_pw2.zeroize();
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        let mut new_pw = new_pw;
        new_pw.zeroize();
    }

    fn section_database(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Datenbank, Synchronisierung und Backup");
        ui.add_space(4.0);
        let vault_path = self.config.vault_path.clone();

        egui::Grid::new("db").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
            ui.label("Speicherort");
            ui.vertical(|ui| {
                ui.label(RichText::new(vault_path.display().to_string()).monospace());
                ui.horizontal(|ui| {
                    if ui.button("In anderen Ordner verschieben …").clicked() {
                        self.move_database();
                    }
                    if ui.button("Andere Datenbank öffnen …").clicked() {
                        self.use_other_database();
                    }
                });
                ui.label(
                    RichText::new(
                        "Synchronisierung: Datenbank in den Nextcloud-Ordner oder auf eine NAS-Freigabe legen und \
                         auf jedem Rechner „Andere Datenbank öffnen“ wählen. Konfliktkopien werden automatisch \
                         zusammengeführt.",
                    )
                    .weak()
                    .small(),
                );
            });
            ui.end_row();

            ui.label("Backup");
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    if ui.button("Backup speichern unter …").clicked() {
                        self.export_backup();
                    }
                    if ui.button("Backup-Ordner öffnen").clicked() {
                        let _ = std::fs::create_dir_all(&self.config.dirs.backups);
                        platform::open_path(&self.config.dirs.backups);
                    }
                });
                ui.label(
                    RichText::new("Automatisch: täglich eine Kopie im Backup-Ordner, die letzten 14 bleiben erhalten.")
                        .weak()
                        .small(),
                );
            });
            ui.end_row();

            ui.label("Wiederherstellen");
            ui.vertical(|ui| {
                if ui.button("Backup auswählen …").clicked() {
                    self.form.restore_path = rfd::FileDialog::new()
                        .set_title("Backup auswählen")
                        .set_directory(&self.config.dirs.backups)
                        .add_filter("KeyCatch-Datenbank", &["kcv", "klv"])
                        .pick_file();
                }
                if let Some(p) = self.form.restore_path.clone() {
                    ui.label(RichText::new(p.display().to_string()).monospace());
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.form.restore_pw)
                                .password(true)
                                .hint_text("Master-Passwort des Backups")
                                .desired_width(220.0),
                        );
                        if ui.button("Prüfen und wiederherstellen").clicked() {
                            self.restore(p);
                        }
                    });
                    ui.label(
                        RichText::new("Die aktuelle Datenbank wird vorher in den Backup-Ordner gesichert.").weak().small(),
                    );
                }
            });
            ui.end_row();
        });
    }

    fn move_database(&mut self) {
        let Some(dir) = rfd::FileDialog::new().set_title("Neuen Speicherort wählen").pick_folder() else { return };
        let target = dir.join(crate::config::DEFAULT_DB_NAME);
        let from = self.config.vault_path.clone();
        // Erfasste Einträge vorher übernehmen (der Posteingang hängt am Speicherort).
        self.sync_inbox(false);
        if let Err(e) = vault::move_vault(&from, &target, &self.config.dirs) {
            self.error = Some(e.to_string());
            return;
        }
        self.config.settings.datenbank = target.display().to_string();
        if let Err(e) = self.config.save() {
            self.error = Some(e);
        }
        let dek = self.vault.as_ref().map(|v| *v.dek());
        pin::clear(&self.config.data_dir);
        match dek.map(|k| Vault::open(&target, &self.config.dirs, Unlock::Key(&k))) {
            Some(Ok(v)) => {
                self.vault = Some(v);
                self.start_pin_window();
                self.info = Some(format!("Datenbank verschoben nach {}", target.display()));
                self.sync_inbox(true);
            }
            Some(Err(e)) => {
                self.lock(true);
                self.error = Some(e.to_string());
            }
            None => self.lock(true),
        }
    }

    fn use_other_database(&mut self) {
        let Some(file) = rfd::FileDialog::new()
            .set_title("KeyCatch-Datenbank öffnen")
            .add_filter("KeyCatch-Datenbank", &["kcv", "klv"])
            .pick_file()
        else {
            return;
        };
        self.config.settings.datenbank = file.display().to_string();
        if let Err(e) = self.config.save() {
            self.error = Some(e);
            return;
        }
        self.lock(true);
        self.info = Some("Bitte mit dem Master-Passwort dieser Datenbank entsperren.".into());
    }

    fn export_backup(&mut self) {
        let name = format!("keycatch-backup-{}.kcv", crate::vault::local_now("%Y-%m-%d"));
        let Some(target) = rfd::FileDialog::new()
            .set_title("Backup speichern")
            .set_file_name(&name)
            .add_filter("KeyCatch-Datenbank", &["kcv", "klv"])
            .save_file()
        else {
            return;
        };
        if let Some(v) = self.vault.as_ref() {
            match v.export_backup(&target) {
                Ok(()) => self.info = Some(format!("Backup gespeichert: {}", target.display())),
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }

    fn restore(&mut self, backup: PathBuf) {
        if let Err(e) = Vault::peek(&backup, Unlock::Password(&self.form.restore_pw)) {
            self.error = Some(format!("Backup lässt sich nicht öffnen: {e}"));
            return;
        }
        match restore_from(&backup, &self.config.vault_path, &self.config.dirs) {
            Ok(()) => {
                self.lock(true);
                self.info = Some("Backup wiederhergestellt. Bitte mit dem Master-Passwort des Backups entsperren.".into());
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Windows: Autostart, Symbol im Infobereich, minimiert starten.
    #[cfg(windows)]
    fn section_autostart(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Programmstart");
        ui.add_space(4.0);
        let before = self.config.settings.clone();

        ui.horizontal(|ui| {
            toggle_switch(ui, &mut self.config.settings.autostart);
            ui.label("Mit Windows starten");
        });
        ui.horizontal(|ui| {
            toggle_switch(ui, &mut self.config.settings.infobereich);
            ui.label("Symbol im Infobereich anzeigen");
        });
        ui.horizontal(|ui| {
            ui.add_enabled_ui(self.config.settings.autostart, |ui| {
                toggle_switch(ui, &mut self.config.settings.minimiert_starten);
                ui.label("Minimiert starten (nur mit „Mit Windows starten“)");
            });
        });
        ui.label(
            RichText::new(
                "Das Symbol im Infobereich übernimmt die Tastenkombination. Linksklick öffnet die Übersicht, Rechtsklick zeigt das Menü.",
            )
            .weak()
            .small(),
        );

        let now = self.config.settings.clone();
        if now == before {
            return;
        }
        let ctx = ui.ctx().clone();
        self.save_settings(&ctx);

        let mut msgs = Vec::new();
        let mut err = None;
        if now.autostart != before.autostart {
            match platform::set_autostart(now.autostart) {
                Ok(()) => msgs.push(if now.autostart { "Autostart eingeschaltet." } else { "Autostart ausgeschaltet." }),
                Err(e) => err = Some(e),
            }
        }
        if now.infobereich != before.infobereich {
            let h = Hotkey::parse(&now.tastenkombination).unwrap_or_default();
            match platform::apply_hotkey(&h, now.infobereich) {
                Ok(_) => {
                    if now.infobereich {
                        platform::start_tray();
                        msgs.push("Symbol im Infobereich eingeschaltet.");
                    } else {
                        msgs.push("Symbol im Infobereich ausgeschaltet – es verschwindet gleich.");
                    }
                }
                Err(e) => err = Some(e),
            }
        }
        if now.minimiert_starten != before.minimiert_starten {
            msgs.push(if now.minimiert_starten { "Startet beim Anmelden minimiert." } else { "Startet beim Anmelden geöffnet." });
        }
        if let Some(e) = err {
            self.error = Some(e);
        } else if !msgs.is_empty() {
            self.info = Some(msgs.join(" "));
            self.error = None;
        }
    }

    fn section_hotkey(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Tastenkombination");
        ui.add_space(4.0);
        let current = Hotkey::parse(&self.config.settings.tastenkombination).unwrap_or_default();

        ui.horizontal(|ui| {
            ui.label("Erfassen aus der Zwischenablage:");
            let text = if self.form.recording_hotkey {
                RichText::new("Tasten drücken … (Esc = Abbrechen)").color(ORANGE)
            } else {
                RichText::new(current.display()).monospace().strong()
            };
            if ui.add(egui::Button::new(text).min_size(egui::vec2(200.0, 24.0))).clicked() {
                self.form.recording_hotkey = true;
            }
        });
        ui.label(RichText::new("Feld anklicken, dann die gewünschte Kombination drücken (mindestens zwei von Strg, Alt, Umschalt plus Buchstabe, Ziffer oder F-Taste).").weak().small());

        if self.form.recording_hotkey {
            let events = ui.input(|i| i.events.clone());
            for ev in events {
                if let egui::Event::Key { key, pressed: true, modifiers, .. } = ev {
                    if key == egui::Key::Escape {
                        self.form.recording_hotkey = false;
                        break;
                    }
                    let name = key.symbol_or_name();
                    let ok_key = (name.len() == 1 && name.chars().all(|c| c.is_ascii_alphanumeric()))
                        || (name.starts_with('F') && name[1..].parse::<u8>().is_ok_and(|n| (1..=12).contains(&n)));
                    if !ok_key {
                        continue;
                    }
                    let h = Hotkey {
                        ctrl: modifiers.ctrl || (modifiers.command && !cfg!(target_os = "macos")),
                        alt: modifiers.alt,
                        shift: modifiers.shift,
                        key: name.to_ascii_uppercase(),
                    };
                    self.form.recording_hotkey = false;
                    if !h.is_valid() {
                        self.error = Some("Bitte mindestens zwei der Tasten Strg, Alt und Umschalt verwenden.".into());
                        break;
                    }
                    match platform::apply_hotkey(&h, cfg!(windows) && self.config.settings.infobereich) {
                        Ok(msg) => {
                            self.config.settings.tastenkombination = h.to_config();
                            let ctx = ui.ctx().clone();
                            self.save_settings(&ctx);
                            self.info = Some(msg);
                            self.error = None;
                        }
                        Err(msg) => {
                            if !cfg!(windows) {
                                self.config.settings.tastenkombination = h.to_config();
                                let ctx = ui.ctx().clone();
                                self.save_settings(&ctx);
                            }
                            self.error = Some(msg);
                        }
                    }
                    break;
                }
            }
        }
    }

    fn section_reset(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Standardwerte");
        ui.add_space(4.0);
        if !self.form.confirm_reset {
            if ui.button("Einstellungen auf Standardwerte zurücksetzen").clicked() {
                self.form.confirm_reset = true;
            }
            ui.label(
                RichText::new("Speicherort der Datenbank, Einträge, PIN und Backup-Codes bleiben erhalten.").weak().small(),
            );
            return;
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new("Wirklich alle Einstellungen zurücksetzen?").color(RED));
            if ui.button(RichText::new("Ja, zurücksetzen").color(RED)).clicked() {
                let keep_db = self.config.settings.datenbank.clone();
                let old_hotkey = self.config.settings.tastenkombination.clone();
                #[cfg(windows)]
                let was_autostart = self.config.settings.autostart;
                let was_tray = self.config.settings.infobereich;
                self.config.settings = crate::config::Settings { datenbank: keep_db, ..Default::default() };
                #[cfg(windows)]
                if was_autostart {
                    let _ = platform::set_autostart(false);
                }
                pin::clear(&self.config.data_dir);
                let ctx = ui.ctx().clone();
                self.save_settings(&ctx);
                self.info = Some("Einstellungen auf Standardwerte zurückgesetzt.".into());
                self.error = None;
                if (old_hotkey != self.config.settings.tastenkombination || was_tray)
                    && let Some(h) = Hotkey::parse(&self.config.settings.tastenkombination)
                    && let Err(e) = platform::apply_hotkey(&h, false)
                {
                    self.error = Some(e);
                }
                self.form.confirm_reset = false;
            }
            if ui.button("Abbrechen").clicked() {
                self.form.confirm_reset = false;
            }
        });
    }

    // ------------------------------------------------------------ Backup-Codes-Fenster

    fn show_codes_window(&mut self, ctx: &egui::Context) {
        let Some(cw) = self.codes_window.as_mut() else { return };
        let mut close = false;
        let mut confirm = false;
        let mut print = false;
        let mut copy = false;
        let codes_text = cw.codes.join("\n");
        let printed = cw.printed_or_copied;
        let codes = cw.codes.clone();

        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("keycatch-backup-codes"),
            egui::ViewportBuilder::default()
                .with_title("KeyCatch – Backup-Codes")
                .with_app_id("keycatch")
                .with_inner_size([480.0, 560.0])
                .with_always_on_top(),
            |ui, _class| {
                if ui.input(|i| i.viewport().close_requested()) {
                    close = true;
                }
                egui::Panel::bottom("codes_buttons").show(ui, |ui| {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("🖨 Drucken").clicked() {
                            print = true;
                        }
                        if ui.button("📋 Kopieren").clicked() {
                            copy = true;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Abbrechen").clicked() {
                                close = true;
                            }
                        });
                    });
                    ui.add_space(6.0);
                    let btn = egui::Button::new(RichText::new("✔ Ich habe die Codes sicher aufbewahrt").strong())
                        .min_size(egui::vec2(ui.available_width(), 30.0));
                    if ui.add_enabled(printed, btn).clicked() {
                        confirm = true;
                    }
                    if !printed {
                        ui.label(RichText::new("Erst drucken oder kopieren, dann bestätigen.").weak().small());
                    }
                    ui.add_space(8.0);
                });
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.heading("Backup-Codes");
                    ui.label("Jeder Code öffnet die Datenbank genau einmal, falls das Master-Passwort vergessen wurde.");
                    ui.colored_label(ORANGE, "Wer einen Code hat, kann die Datenbank öffnen. Sicher aufbewahren, nicht am PC speichern.");
                    ui.add_space(10.0);
                    egui::Grid::new("codes").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                        for (i, c) in codes.iter().enumerate() {
                            ui.label(format!("{}.", i + 1));
                            ui.label(RichText::new(c).monospace().size(17.0));
                            ui.end_row();
                        }
                    });
                });
            },
        );

        if print {
            match self.vault.as_ref().map(|v| platform::print_codes(&codes, v.path())) {
                Some(Ok(())) => {
                    if let Some(cw) = self.codes_window.as_mut() {
                        cw.printed_or_copied = true;
                    }
                }
                Some(Err(e)) => self.error = Some(e),
                None => {}
            }
        }
        if copy {
            ctx.copy_text(codes_text);
            if let Some(cw) = self.codes_window.as_mut() {
                cw.printed_or_copied = true;
            }
            self.info = Some("Codes kopiert. Nach dem Einfügen die Zwischenablage-Historie löschen.".into());
        }
        if confirm {
            if let Some(v) = self.vault.as_mut() {
                match v.set_codes(&codes) {
                    Ok(()) => self.info = Some(format!("{} neue Backup-Codes gespeichert. Alte Codes sind ungültig.", codes.len())),
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
            self.codes_window = None;
        } else if close {
            self.codes_window = None;
            self.info = Some("Abgebrochen – die bisherigen Backup-Codes bleiben gültig.".into());
        }
    }

    // ------------------------------------------------------------ Statuszeile

    fn ui_status(&mut self, ui: &mut egui::Ui) {
        if self.error.is_none() && self.info.is_none() {
            return;
        }
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                if let Some(e) = &self.error {
                    ui.add(egui::Label::new(RichText::new(e).color(RED)).wrap());
                } else if let Some(i) = &self.info {
                    ui.add(egui::Label::new(RichText::new(i).color(GREEN)).wrap());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✖").clicked() {
                        self.error = None;
                        self.info = None;
                    }
                });
            });
            ui.add_space(3.0);
        });
    }
}

impl eframe::App for KeyCatchApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        let active = ui.input(|i| !i.events.is_empty() || i.pointer.is_moving());
        if active {
            self.last_activity = Instant::now();
        }
        let minutes = self.config.settings.auto_sperre_minuten;
        let idle_screen = matches!(self.screen, Screen::List | Screen::Settings) && self.codes_window.is_none();
        if minutes > 0 && self.vault.is_some() && idle_screen {
            if self.last_activity.elapsed() >= Duration::from_secs(minutes * 60) {
                self.lock(false);
            }
            ctx.request_repaint_after(Duration::from_secs(5));
        }

        self.ui_status(ui);

        match std::mem::replace(&mut self.screen, Screen::Unlock) {
            Screen::Unlock => {
                egui::CentralPanel::default().show(ui, |ui| self.ui_unlock(ui));
            }
            Screen::NewPassword { used_code } => {
                let mut done = false;
                egui::CentralPanel::default().show(ui, |ui| done = self.ui_new_password(ui, &used_code));
                if !done && matches!(self.screen, Screen::Unlock) {
                    self.screen = Screen::NewPassword { used_code };
                }
            }
            Screen::List => {
                self.screen = Screen::List;
                self.ui_list(ui);
            }
            Screen::Settings => {
                self.screen = Screen::Settings;
                self.ui_settings(ui);
            }
            Screen::Edit(edit) => {
                if let Some(edit) = self.ui_edit(ui, edit) {
                    self.screen = Screen::Edit(edit);
                }
            }
        }

        self.show_codes_window(&ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_colors() {
        assert_eq!(parse_hex_color("#222774"), Some(Color32::from_rgb(0x22, 0x27, 0x74)));
        assert_eq!(parse_hex_color("22277446").unwrap().a(), 0x46);
        assert_eq!(to_hex_color(parse_hex_color("#AABBCC").unwrap()), "#aabbcc");
        assert!(parse_hex_color("#12345").is_none());
        assert!(parse_hex_color("#gg0000").is_none());
        assert!(parse_hex_color("").is_none());
    }
}
