use ini::Ini;
use md5;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::Path;

mod scan_result;
use scan_result::ScanResult;

mod file_watcher;
mod io_utils;
mod target_windows;
mod target_unix;

// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
}

// Create a default configuration file
fn create_config(filename: &str) -> Ini {
    let mut conf = Ini::new();
    conf.with_section(Some("settings"))
        .set("hash_algorithm", "sha256")
        .set("hash_file", "{executable_path}/data/full_sha256.txt")
        .set("context_menu", "true")
        .set("chunk_size_mb", "8");
    conf.with_section(Some("file_watcher"))
        .set("directories", "");
    conf.write_to_file(filename).unwrap();
    return conf;
}

fn load_watch_dirs(conf: &Ini) -> Vec<String> {
    let dirs = conf
        .section(Some("file_watcher"))
        .and_then(|s| s.get("directories"))
        .unwrap_or("");
    dirs.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn load_chunk_size(conf: &Ini) -> usize {
    let chunk_size_mb = conf
        .section(Some("settings"))
        .and_then(|s| s.get("chunk_size_mb"))
        .unwrap_or("8")
        .parse::<usize>()
        .unwrap_or(8);
    chunk_size_mb * 1024 * 1024 // Convert MB to bytes
}

// Load configuration from an INI file
fn load_config(filename: &str) -> Option<Ini> {
    match Ini::load_from_file(filename) {
        Ok(conf) => Some(conf),
        Err(_) => None,
    }
}

// Get the hash algorithm from the configuration
fn load_algorithm(conf: &Ini) -> HashAlgorithm {
    let algo_str = conf
        .section(Some("settings"))
        .and_then(|s| s.get("hash_algorithm"))
        .unwrap_or("md5")
        .to_lowercase();
    match algo_str.as_str() {
        "md5" => HashAlgorithm::MD5,
        "sha1" => HashAlgorithm::SHA1,
        "sha256" => HashAlgorithm::SHA256,
        _ => {
            println!("Unknown hash algorithm '{}', defaulting to MD5", algo_str);
            HashAlgorithm::MD5
        }
    }
}

// Get the hash file path from the configuration, replacing placeholders
fn load_hash_file(conf: &Ini, exe_dir: &str) -> String {
    let hash_file_template = conf
        .section(Some("settings"))
        .and_then(|s| s.get("hash_file"))
        .unwrap_or("{executable_path}/data/full_md5.txt");
    hash_file_template.replace("{executable_path}", exe_dir)
}

// Load MD5 hashes from a file into a HashSet
fn create_hashset(filename: &str) -> HashSet<String> {
    let file = File::open(filename).expect("Could not open file");
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| line.expect("Could not read line"))
        .collect::<HashSet<String>>()
}

// Compute the hash of a file using the specified algorithm
#[allow(dead_code)]
fn hash_of_file(filename: &str, algorithm: HashAlgorithm) -> Result<String, std::io::Error> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    match algorithm {
        HashAlgorithm::MD5 => {
            let digest = md5::compute(&buffer);
            Ok(format!("{:x}", digest))
        }
        HashAlgorithm::SHA1 => {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&buffer);
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        }
        HashAlgorithm::SHA256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        }
    }
}

// Compute the hash of a file in chunks to handle large files
fn hash_of_file_chunked(filename : &str, algorithm: HashAlgorithm, chunk_size: usize) -> Result<String, std::io::Error> {
    let mut file = File::open(filename)?;
    let mut buffer = vec![0; chunk_size];
    match algorithm {
        HashAlgorithm::MD5 => {
            let mut context = md5::Context::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                context.consume(&buffer[..bytes_read]);
            }
            let digest = context.finalize();
            Ok(format!("{:x}", digest))
        }
        HashAlgorithm::SHA1 => {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        }
        HashAlgorithm::SHA256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        }
    }
}

// Scan a single file and check if its MD5 hash is in the hashset
fn scan_file(filepath: &str, hashset: &HashSet<String>, algorithm: HashAlgorithm, chunk_size: usize) -> ScanResult {

    match hash_of_file_chunked(filepath, algorithm, chunk_size) {
        Ok(filehash) => {
            println!("File: {} Hash: {}", filepath, filehash);
            if hashset.contains(&filehash) {
                ScanResult {
                    total_files: 1,
                    malicious_files_list: vec![filepath.to_string()],
                }
            } else {
                ScanResult {
                    total_files: 1,
                    malicious_files_list: vec![],
                }
            }
        }
        Err(e) => {
            panic!("Could not open file {}: {}", filepath, e);
        }
    }
}

// Recursively scan a directory for files and check each file's MD5 hash
fn scan_dir(dirpath: &str, hashset: &HashSet<String>, algorithm: HashAlgorithm, chunk_size: usize) -> ScanResult {
    let mut total_files = 0;
    let mut malicious_files_list = Vec::new();
    let paths = std::fs::read_dir(dirpath).expect("Could not read directory");
    for path in paths {
        let path = path.expect("Could not get path").path();
        if path.is_file() {
            let filepath = path.to_str().unwrap();
            let result = scan_file(filepath, hashset, algorithm, chunk_size);
            total_files += result.total_files;
            malicious_files_list.extend(result.malicious_files_list);
        } else if path.is_dir() {
            let dirpath = path.to_str().unwrap();
            let result = scan_dir(dirpath, hashset, algorithm, chunk_size);
            total_files += result.total_files;
            malicious_files_list.extend(result.malicious_files_list);
        }
    }
    ScanResult {
        total_files,
        malicious_files_list,
    }
}

fn action_scan(args: Vec<String>, conf: &Ini, exe_dir: &str) {
    let algorithm = load_algorithm(&conf);
    println!("Using hash algorithm: {:?}", algorithm);
    let hash_file = load_hash_file(&conf, exe_dir);
    let data_file = Path::new(&hash_file);

    if data_file.exists() == false {
        panic!(
            "Hash file {} does not exist. Please check your configuration.",
            data_file.to_str().unwrap()
        );
    }

    let hashset = create_hashset(&data_file.to_str().unwrap());
    println!(
        "Loaded {} hashes from {}",
        hashset.len(),
        data_file.to_str().unwrap()
    );

    let filepath = if args.len() > 2 {
        args[2].clone()
    } else {
        panic!("Please provide a file path as an argument.");
    };

    let chunk_size = load_chunk_size(&conf);

    let scan_start = std::time::Instant::now();
    println!("Scanning path: {}", filepath);
    let result = if Path::new(&filepath).is_dir() {
        scan_dir(&filepath, &hashset, algorithm, chunk_size)
    } else {
        scan_file(&filepath, &hashset, algorithm, chunk_size)
    };
    let scan_duration = scan_start.elapsed();
    println!(
        "Scan completed in {:.2?} - scanned {} files {} malicious",
        scan_duration,
        result.total_files,
        result.malicious_files()
    );

    if result.malicious_found() {
        println!("Malicious files detected.");
        for file in result.malicious_files_list {
            println!(" - {}", file);
        }
    } else {
        println!("No malicious files detected.");
    }
}


fn action_create_menu(_debug_mode: bool) {
    #[cfg(target_os = "windows")]
    {
        use crate::target_windows::register_context_menu;

        if let Err(e) = register_context_menu(_debug_mode) {
            println!("Could not register context menu: {}", e);
        }
    }
}

fn action_unregister_menu() {
    #[cfg(target_os = "windows")]
    {
        use crate::target_windows::unregister_context_menu;

        if let Err(e) = unregister_context_menu() {
            println!("Could not unregister context menu: {}", e);
        }
    }
}

fn action_watch(conf: &Ini, exe_dir: &std::path::Path) {
    let algorithm = load_algorithm(&conf);
    println!("Using hash algorithm: {:?}", algorithm);
    let hash_file = load_hash_file(&conf, exe_dir.to_str().unwrap());
    let data_file = Path::new(&hash_file);
    let hashset = create_hashset(&data_file.to_str().unwrap());

    let dirs = load_watch_dirs(conf);
    if dirs.is_empty() {
        println!("No directories configured to watch. Please update the configuration.");
        return;
    }
    let chunk_size = load_chunk_size(&conf);
    file_watcher::watch_dirs(dirs, &hashset, algorithm, chunk_size);
}

fn main() {
    // Get the path of the executable and its directory
    let exe_path = std::env::current_exe().expect("Could not get current exe path");
    let exe_dir = exe_path.parent().expect("Could not get parent directory");

    // Parse the command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <action>", args[0]);
        return;
    }
    let action = &args[1];

    // Load or create configuration
    let conf = load_config(exe_dir.join("cofig.ini").to_str().unwrap());
    let conf = match conf {
        Some(c) => c,
        None => {
            println!("Configuration file not found. Creating default config.ini");
            create_config(exe_dir.join("cofig.ini").to_str().unwrap())
        }
    };

    // Update context menus if its enabled
    if conf
        .section(Some("settings"))
        .and_then(|s| s.get("context_menu"))
        .unwrap_or("false")
        .to_lowercase()
        == "true"
    {
        action_create_menu(false);
    }

    // Perform the requested action
    match action.as_str() {
        "scan" => action_scan(args, &conf, exe_dir.to_str().unwrap()),
        "register_context_menu" => action_create_menu(true),
        "unregister_context_menu" => action_unregister_menu(),
        "watch" => {
            action_watch(&conf, exe_dir);
        }
        _ => {
            println!("Unknown action: {}", action);
            println!("Available actions: scan, register_context_menu, unregister_context_menu");
        }
    }

    // Wait for user input
    println!("Press Enter to exit...");
    let mut exit_input = String::new();
    std::io::stdin().read_line(&mut exit_input).unwrap();
    std::process::exit(0);
}
