use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FileWatcher {
    pub paths: Vec<String>,
    pub interval_secs: u64,
}

#[derive(Serialize, Deserialize)]
pub struct DomainWatcher {
    pub trusted_domains: Vec<String>,
    pub similarity_threshold: f32,
    pub addr: String
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    pub hash_algorithm: String,
    pub hash_file: String,
    pub context_menu: bool,
    pub chunk_size_mb: usize,
    pub file_watcher: Option<FileWatcher>,
    pub domain_watcher: Option<DomainWatcher>,
}

impl FileWatcher {
    fn new(paths: Vec<String>, interval_secs: u64) -> Self {
        FileWatcher {
            paths,
            interval_secs,
        }
    }
}

impl DomainWatcher {
    fn new(trusted_domains: Vec<String>, similarity_threshold: f32, addr: String) -> Self {
        DomainWatcher {
            trusted_domains,
            similarity_threshold,
            addr,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        let file_watcher = FileWatcher::new(
            vec!["/path/to/watch1".to_string(), "/path/to/watch2".to_string()],
            300,
        );

        let domain_watcher = DomainWatcher::new(
            vec!["google.com".to_string(), "microsoft.com".to_string()],
            0.7,
            "127.0.0.1:8080".to_string()
        );

        Config {
            version: "1.0".to_string(),
            hash_algorithm: "SHA256".to_string(),
            hash_file: "{executable_path}/data/full_sha256.txt".to_string(),
            context_menu: false,
            chunk_size_mb: 10,
            file_watcher: Some(file_watcher),
            domain_watcher: Some(domain_watcher),
        }
    }
}