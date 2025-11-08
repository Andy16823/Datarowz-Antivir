use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct FileWatcher {
    pub paths: Vec<String>,
    pub interval_secs: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    pub hash_algorithm: String,
    pub hash_file: String,
    pub context_menu: bool,
    pub chunk_size_mb: usize,
    pub file_watcher: Option<FileWatcher>,
}

impl FileWatcher {
    fn new(paths: Vec<String>, interval_secs: u64) -> Self {
        FileWatcher {
            paths,
            interval_secs,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        let file_watcher = FileWatcher::new(
            vec!["/path/to/watch1".to_string(), "/path/to/watch2".to_string()],
            300,
        );

        Config {
            version: "1.0".to_string(),
            hash_algorithm: "SHA256".to_string(),
            hash_file: "{executable_path}/data/full_sha256.txt".to_string(),
            context_menu: false,
            chunk_size_mb: 10,
            file_watcher: Some(file_watcher),
        }
    }
}