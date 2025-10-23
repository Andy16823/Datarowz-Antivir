#[cfg(target_os = "unix")]
pub fn register_context_menu(debug_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Context menu registration is not implemented for Unix-like systems
    if debug_mode {
        println!("Context menu registration is not supported on Unix-like systems.");
    }
    Ok(())
}