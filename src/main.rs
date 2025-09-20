use ini::Ini;
use md5;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::Path;

mod scan_result;
use scan_result::ScanResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
}

// Load configuration from an INI file
fn load_config(filename: &str) -> Ini {
    let conf = Ini::load_from_file(filename).unwrap();
    return conf;
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

// Scan a single file and check if its MD5 hash is in the hashset
fn scan_file(filepath: &str, hashset: &HashSet<String>, algorithm: HashAlgorithm) -> ScanResult {
    match hash_of_file(filepath, algorithm) {
        Ok(filehash) => {
            // println!("File: {} Hash: {}", filepath, filehash);
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
fn scan_dir(dirpath: &str, hashset: &HashSet<String>, algorithm: HashAlgorithm) -> ScanResult {
    let mut total_files = 0;
    let mut malicious_files_list = Vec::new();
    let paths = std::fs::read_dir(dirpath).expect("Could not read directory");
    for path in paths {
        let path = path.expect("Could not get path").path();
        if path.is_file() {
            let filepath = path.to_str().unwrap();
            let result = scan_file(filepath, hashset, algorithm);
            total_files += result.total_files;
            malicious_files_list.extend(result.malicious_files_list);
        } else if path.is_dir() {
            let dirpath = path.to_str().unwrap();
            let result = scan_dir(dirpath, hashset, algorithm);
            total_files += result.total_files;
            malicious_files_list.extend(result.malicious_files_list);
        }
    }
    ScanResult {
        total_files,
        malicious_files_list,
    }
}

fn main() {
    let exe_path = std::env::current_exe().expect("Could not get current exe path");
    let exe_dir = exe_path.parent().expect("Could not get parent directory");
    let conf = load_config(exe_dir.join("cofig.ini").to_str().unwrap());
    let algorithm = load_algorithm(&conf);
    println!("Using hash algorithm: {:?}", algorithm);
    let hash_file = load_hash_file(&conf, exe_dir.to_str().unwrap());
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

    let args: Vec<String> = std::env::args().collect();
    let filepath = if args.len() > 1 {
        args[1].clone()
    } else {
        panic!("Please provide a file path as an argument.");
    };

    let scan_start = std::time::Instant::now();
    println!("Scanning path: {}", filepath);
    let result = if Path::new(&filepath).is_dir() {
        scan_dir(&filepath, &hashset, algorithm)
    } else {
        scan_file(&filepath, &hashset, algorithm)
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
        std::process::exit(1);
    } else {
        println!("No malicious files detected.");
        std::process::exit(0);
    }
}
