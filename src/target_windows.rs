#[cfg(target_os = "windows")]
pub fn register_context_menu(debug_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use winreg::RegKey;
    use winreg::enums::*;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let exe_path = std::env::current_exe()?;
    let command = format!("\"{}\" scan \"%1\"", exe_path.display());

    // Registrierung für Dateien (*)
    let file_path = r"Software\Classes\*\shell\ScanWithDatarowz";
    let (file_key, _) = hkcu.create_subkey(&file_path)?;
    file_key.set_value("", &"Scan with Datarowz")?;

    let file_command_path = format!(r"{}\command", file_path);
    let (file_cmd_key, _) = hkcu.create_subkey(&file_command_path)?;
    file_cmd_key.set_value("", &command)?;

    // Registrierung für Verzeichnisse (Directory)
    let dir_path = r"Software\Classes\Directory\shell\ScanWithDatarowz";
    let (dir_key, _) = hkcu.create_subkey(&dir_path)?;
    dir_key.set_value("", &"Scan with Datarowz")?;

    let dir_command_path = format!(r"{}\command", dir_path);
    let (dir_cmd_key, _) = hkcu.create_subkey(&dir_command_path)?;
    dir_cmd_key.set_value("", &command)?;

    // Registrierung für Verzeichnis-Hintergrund (Directory\Background)
    let bg_path = r"Software\Classes\Directory\Background\shell\ScanWithDatarowz";
    let (bg_key, _) = hkcu.create_subkey(&bg_path)?;
    bg_key.set_value("", &"Scan with Datarowz")?;

    let bg_command_path = format!(r"{}\command", bg_path);
    let (bg_cmd_key, _) = hkcu.create_subkey(&bg_command_path)?;
    // Für Hintergrund-Rechtsklick verwenden wir %V (current directory)
    let bg_command = format!("\"{}\" scan \"%V\"", exe_path.display());
    bg_cmd_key.set_value("", &bg_command)?;

    if !debug_mode {
        return Ok(());
    }

    println!("Registered context menu for:");
    println!("  - Files: {}", command);
    println!("  - Directories: {}", command);
    println!("  - Directory Background: {}", bg_command);
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn unregister_context_menu() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::RegKey;
    use winreg::enums::*;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Entfernen von Dateien (*)
    if let Ok(key) = hkcu.open_subkey_with_flags(r"Software\Classes\*\shell", KEY_WRITE) {
        match key.delete_subkey_all("ScanWithDatarowz") {
            Ok(_) => println!("✓ Context menu for files removed"),
            Err(_) => println!("⚠ Context menu for files not found"),
        }
    }

    // Entfernen von Verzeichnissen (Directory)
    if let Ok(key) = hkcu.open_subkey_with_flags(r"Software\Classes\Directory\shell", KEY_WRITE) {
        match key.delete_subkey_all("ScanWithDatarowz") {
            Ok(_) => println!("✓ Context menu for directories removed"),
            Err(_) => println!("⚠ Context menu for directories not found"),
        }
    }

    // Entfernen von Verzeichnis-Hintergrund (Directory\Background)
    if let Ok(key) =
        hkcu.open_subkey_with_flags(r"Software\Classes\Directory\Background\shell", KEY_WRITE)
    {
        match key.delete_subkey_all("ScanWithDatarowz") {
            Ok(_) => println!("✓ Context menu for directory background removed"),
            Err(_) => println!("⚠ Context menu for directory background not found"),
        }
    }

    Ok(())
}
