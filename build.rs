// Bettet unter Windows das Programm-Symbol und die Versionsangaben in die exe ein.
fn main() {
    println!("cargo:rerun-if-changed=assets/keycatch.ico");
    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("assets/keycatch.ico");
            res.set("ProductName", "KeyCatch");
            res.set("FileDescription", "KeyCatch – API-Keys und App-Passwörter verschlüsselt speichern");
            if let Err(e) = res.compile() {
                println!("cargo:warning=Programm-Symbol konnte nicht eingebettet werden: {e}");
            }
        }
    }
}
