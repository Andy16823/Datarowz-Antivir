use md5;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::Path;

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
fn scan_file(filepath: &str, hashset: &HashSet<String>) -> bool {
    match md5_hash_of_file(filepath) {
        Ok(filehash) => {
            if hashset.contains(&filehash) {
                println!(
                    "File {} - {} is malicious (in hashset)!",
                    filepath, filehash
                );
                true
            } else {
                false
            }
        }
        Err(e) => {
            panic!("Could not open file {}: {}", filepath, e);
        }
    }
}

// Recursively scan a directory for files and check each file's MD5 hash
fn scan_dir(dirpath: &str, hashset: &HashSet<String>) -> bool {
    let mut malicious_found = false;
    let paths = std::fs::read_dir(dirpath).expect("Could not read directory");
    for path in paths {
        let path = path.expect("Could not get path").path();
        if path.is_file() {
            let filepath = path.to_str().unwrap();
            if scan_file(filepath, hashset) {
                malicious_found = true;
            }
        } else if path.is_dir() {
            let dirpath = path.to_str().unwrap();
            if scan_dir(dirpath, hashset) {
                malicious_found = true;
            }
        }
    }
    malicious_found
}

fn main() {
    let hashset = load_md5_hashset(&"full_md5.txt");

    let args: Vec<String> = std::env::args().collect();
    let filepath = if args.len() > 1 {
        args[1].clone()
    } else {
        panic!("Please provide a file path as an argument.");
    };

    let scan_start = std::time::Instant::now();
    println!("Scanning path: {}", filepath);
    let malicious_found = if Path::new(&filepath).is_dir() {
        scan_dir(&filepath, &hashset)
    } else {
        scan_file(&filepath, &hashset)
    };
    let scan_duration = scan_start.elapsed();
    println!("Scan completed in {:.2?}", scan_duration);

    if malicious_found {
        println!("Malicious files detected.");
        std::process::exit(1);
    } else {
        println!("No malicious files detected.");
        std::process::exit(0);
    }
}
