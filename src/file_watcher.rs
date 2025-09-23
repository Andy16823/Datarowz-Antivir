use crate::{HashAlgorithm, scan_file, scan_result::ScanResult};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashSet, HashMap};
use std::hash::Hash;
use std::sync::mpsc::channel;

pub struct WatcherFile {
    pub path: String,
    pub scan_result: Option<ScanResult>,
}

pub fn watch_dirs(paths: Vec<String>, hashset: &HashSet<String>, algorithm: HashAlgorithm) {
    let mut changed_files: HashMap<String, WatcherFile> = HashMap::new();
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
                    for path in ev.paths {
                        println!("Change detected at: {:?}", path);
                        changed_files.insert(path.to_str().unwrap().to_string(), WatcherFile {
                            path: path.to_str().unwrap().to_string(),
                            scan_result: None,
                        });
                        println!("Changed files: {:?}", changed_files.keys());
                    }
                } else {
                    println!("Watch error: {:?}", event);
                }
                // Here you can implement logic to handle the change,
                // e.g., re-scan the directory or specific files.
            }
            Err(e) => println!("Watch error: {:?}", e),
        }
    }
}
