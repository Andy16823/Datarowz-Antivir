use crate::io_utils::FileAccessResult;
use crate::io_utils::check_file_access;
use crate::io_utils::exist_file;
use crate::{HashAlgorithm, scan_file, scan_result::ScanResult};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use notify::event::{EventKind, ModifyKind, CreateKind};

// Try to scan a file, retrying if it's locked or inaccessible
pub fn try_file_scan(
    filepath: &str,
    hashset: &HashSet<String>,
    algorithm: HashAlgorithm,
    max_attempts: u32,
) -> Option<ScanResult> {
    let mut attempts = 0;

    while attempts < max_attempts {
        match check_file_access(filepath) {
            FileAccessResult::Accessible => return Some(scan_file(filepath, hashset, algorithm)),
            _ => {}
        }
        attempts += 1;
        thread::sleep(Duration::from_millis(200));
    }
    None
}

pub fn watch_dirs(paths: Vec<String>, hashset: &HashSet<String>, algorithm: HashAlgorithm) {

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
        match rx.recv() {
            Ok(event) => {
                if let Ok(ev) = event {
                    // Only scan on Create or Modify events
                    match &ev.kind {
                        EventKind::Create(CreateKind::File) | EventKind::Modify(ModifyKind::Data(_)) => {
                            for path in ev.paths {
                                let file_path = path.to_str().unwrap().to_string();
                                if !exist_file(&file_path) {
                                    continue;
                                }
                                let scan_result = try_file_scan(&file_path, hashset, algorithm, 5);
                                match scan_result {
                                    Some(result) => {
                                        if result.malicious_found() {
                                            println!(
                                                "Malicious file detected: {}",
                                                result.malicious_files_list[0]
                                            );
                                        }
                                    }
                                    None => {
                                        println!("File {} is locked or inaccessible.", file_path);
                                    }
                                }
                            }
                        }
                        _ => {} // Ignore other events
                    }
                } else {
                    println!("Watch error: {:?}", event);
                }
            }
            Err(e) => println!("Watch error: {:?}", e),
        }
    }
}
