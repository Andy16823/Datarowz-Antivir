use crate::io_utils::FileAccessResult;
use crate::io_utils::check_file_access;
use crate::io_utils::exist_file;
use crate::{HashAlgorithm, scan_file, scan_result::ScanResult};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use notify::event::{EventKind, ModifyKind, CreateKind};

// Try to scan a file, retrying if it's locked or inaccessible
pub fn try_file_scan(
    filepath: &str,
    hashset: &HashSet<String>,
    algorithm: HashAlgorithm,
    max_attempts: u32,
    chunk_size: usize
) -> Option<ScanResult> {
    let mut attempts = 0;

    while attempts < max_attempts {
        match check_file_access(filepath) {
            FileAccessResult::Accessible => return Some(scan_file(filepath, hashset, algorithm, chunk_size)),
            _ => {}
        }
        attempts += 1;
        thread::sleep(Duration::from_millis(200));
    }
    None
}

pub fn watch_dirs(paths: Vec<String>, hashset: &HashSet<String>, algorithm: HashAlgorithm, chunk_size: usize) {

    let mut debounce_list: HashMap<String, Instant> = HashMap::new();
    let (tx, rx) = channel();
    let mut watcher =
        RecommendedWatcher::new(move |res| tx.send(res).unwrap(), Config::default()).unwrap();

    for path in paths {
        watcher
            .watch(path.as_ref(), RecursiveMode::Recursive)
            .unwrap();
        println!("Watching directory: {}", path);
    }
    loop {
        let now = Instant::now();

        // Check for files we can scan
        let mut files_to_scan: Vec<String> = Vec::new();
        debounce_list.retain(|filepath, last_time| {
            if now.duration_since(*last_time) > Duration::from_secs(5) {
                files_to_scan.push(filepath.clone());
                false // Remove from debounce list
            } else {
                true // Keep in debounce list
            }
        });

        // Scan the files that are ready
        for file_path in files_to_scan {
            if exist_file(&file_path) {
                println!("Scanning file: {}", file_path);
                let scan_result = try_file_scan(&file_path, hashset, algorithm, 5, chunk_size);
                match scan_result {
                    Some(result) => {
                        if result.malicious_found() {
                            println!("Malicious file detected: {}", file_path);
                        }
                        else {
                            println!("File is clean: {}", file_path);
                        }
                    }
                    None => {
                        println!("Failed to scan file after multiple attempts: {}", file_path);
                    }
                }
            }
        }

        // Wait for file system events and update debounce list
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                if let Ok(ev) = event {
                    // Only scan on Create or Modify events
                    match &ev.kind {
                        EventKind::Create(CreateKind::File) | EventKind::Modify(ModifyKind::Data(_)) => {
                            for path in ev.paths {
                                let file_path = path.to_str().unwrap().to_string();
                                debounce_list.insert(file_path.clone(), now);
                                println!("Detected change in file: {}", file_path);
                            }
                        }
                        _ => {} // Ignore other events
                    }
                } else {
                    println!("Watch error: {:?}", event);
                }
            }
            _ => {} // Timeout, continue loop
        }
    }
}
