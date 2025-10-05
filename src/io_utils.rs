use std::{fs::File, io::Read};

// Define the result of checking file access
#[allow(dead_code)]
pub enum FileAccessResult {
    Accessible,
    Locked,
    PermissionDenied,
    NotFound,
    OtherError(String),
}

// Check if a file is accessible, locked, or has other issues
pub fn check_file_access(filepath: &str) -> FileAccessResult {
    match File::open(filepath) {
        Ok(mut file) => match file.read(&mut [0u8; 1]) {
            Ok(_) => FileAccessResult::Accessible,
            Err(e) => {
                if let Some(32) = e.raw_os_error() {
                    FileAccessResult::Locked
                } else {
                    FileAccessResult::OtherError(e.to_string())
                }
            }
        },
        Err(e) => {
            if let Some(os_error) = e.raw_os_error() {
                match os_error {
                    2 | 3 => FileAccessResult::NotFound,
                    5 => FileAccessResult::PermissionDenied,
                    32 => FileAccessResult::Locked,
                    _ => FileAccessResult::OtherError(format!("OS Error {}: {}", os_error, e)),
                }
            } else {
                FileAccessResult::OtherError(e.to_string())
            }
        }
    }
}

// Check if a file exists
pub fn exist_file(filepath: &str) -> bool {
    std::path::Path::new(filepath).exists()
}
