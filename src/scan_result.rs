pub struct ScanResult {
    pub total_files: i64,
    pub malicious_files_list: Vec<String>,
}

#[allow(dead_code)]
impl ScanResult {
    pub fn new() -> Self {
        ScanResult {
            total_files: 0,
            malicious_files_list: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: ScanResult) {
        self.total_files += other.total_files;
        self.malicious_files_list.extend(other.malicious_files_list);
    }

    pub fn malicious_found(&self) -> bool {
        !self.malicious_files_list.is_empty()
    }

    pub fn malicious_files(&self) -> i64 {
        self.malicious_files_list.len() as i64
    }
}
