use ini::Ini;
use md5;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::Path;

// Struct to hold the result of a scan
struct ScanResult {
    malicious_found: bool,
    malicious_files: i64,
    total_files: i64,
}

// Load configuration from an INI file
fn load_config(filename: &str) -> Ini {
    let conf = Ini::load_from_file(filename).unwrap();
    return conf;
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
fn load_md5_hashset(filename: &str) -> HashSet<String> {
    let file = File::open(filename).expect("Could not open file");
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| line.expect("Could not read line"))
        .collect::<HashSet<String>>()
}

// Compute the MD5 hash of a file
fn md5_hash_of_file(filename: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let digest = md5::compute(&buffer);
    Ok(format!("{:x}", digest))
}

// Scan a single file and check if its MD5 hash is in the hashset
fn scan_file(filepath: &str, hashset: &HashSet<String>) -> ScanResult {
    match md5_hash_of_file(filepath) {
        Ok(filehash) => {
            if hashset.contains(&filehash) {
                println!(
                    "File {} - {} is malicious (in hashset)!",
                    filepath, filehash
                );
                ScanResult {
                    malicious_found: true,
                    malicious_files: 1,
                    total_files: 1,
                }
            } else {
                ScanResult {
                    malicious_found: false,
                    malicious_files: 0,
                    total_files: 1,
                }
            }
        }
        Err(e) => {
            panic!("Could not open file {}: {}", filepath, e);
        }
    }
}

// Recursively scan a directory for files and check each file's MD5 hash
fn scan_dir(dirpath: &str, hashset: &HashSet<String>) -> ScanResult {
    let mut malicious_found = false;
    let mut total_files = 0;
    let mut malicious_files = 0;
    let paths = std::fs::read_dir(dirpath).expect("Could not read directory");
    for path in paths {
        let path = path.expect("Could not get path").path();
        if path.is_file() {
            let filepath = path.to_str().unwrap();
            let result = scan_file(filepath, hashset);
            if result.malicious_found {
                malicious_found = true;
            }
            total_files += result.total_files;
            malicious_files += result.malicious_files;
        } else if path.is_dir() {
            let dirpath = path.to_str().unwrap();
            let result = scan_dir(dirpath, hashset);
            if result.malicious_found {
                malicious_found = true;
            }
            total_files += result.total_files;
            malicious_files += result.malicious_files;
        }
    }
    ScanResult {
        malicious_found,
        malicious_files,
        total_files,
    }
}

fn main() {
    let exe_path = std::env::current_exe().expect("Could not get current exe path");
    let exe_dir = exe_path.parent().expect("Could not get parent directory");
    let conf = load_config(exe_dir.join("cofig.ini").to_str().unwrap());
    let hash_file = load_hash_file(&conf, exe_dir.to_str().unwrap());
    let data_file = Path::new(&hash_file);

    if data_file.exists() == false {
        panic!(
            "Hash file {} does not exist. Please check your configuration.",
            data_file.to_str().unwrap()
        );
    }

    let hashset = load_md5_hashset(&data_file.to_str().unwrap());
    println!(
        "Loaded {} hashes from {}",
        hashset.len(),
        data_file.to_str().unwrap()
    );

    let args: Vec<String> = std::env::args().collect();
    let filepath = if args.len() > 1 {
        args[1].clone()
    } else {
        panic!("Please provide a file path as an argument.");
    };

    let scan_start = std::time::Instant::now();
    println!("Scanning path: {}", filepath);
    let result = if Path::new(&filepath).is_dir() {
        scan_dir(&filepath, &hashset)
    } else {
        scan_file(&filepath, &hashset)
    };
    let scan_duration = scan_start.elapsed();
    println!(
        "Scan completed in {:.2?} - scanned {} files {} malicious",
        scan_duration, result.total_files, result.malicious_files
    );

    if result.malicious_found {
        println!("Malicious files detected.");
        std::process::exit(1);
    } else {
        println!("No malicious files detected.");
        std::process::exit(0);
    }
}
