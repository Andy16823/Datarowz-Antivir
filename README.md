# DataRowz

**DataRowz** is a free and open-source antivirus tool for everyone.  
Our mission: **Security should not be a luxury. Every person deserves the ability to check files for known malware — free of charge.**

## ✨ Features

- 🔍 Scan single files or entire directories
- 🧩 Compare file hashes against a known malware database
- ⚡ Fast detection using in-memory HashSet lookup
- 📂 Recursive folder scanning
- 🖥️ Planned: GUI for easy drag & drop usage
- 🌐 Open Source and forever free

## 🚀 Installation

Requirements:
- [Rust](https://www.rust-lang.org/) (version 1.70 or newer)

Clone the repository:

```bash
git clone https://github.com/<your-username>/datarowz.git
cd datarowz
```

Build:

```bash
cargo build --release
```

The executable will be located at:

```
target/release/datarowz
```

## 🛠️ Usage

Example: scan a directory

```bash
./datarowz /path/to/folder
```

Example: scan a single file

```bash
./datarowz /path/to/file.exe
```

**Exit codes:**
- `0` → No malware found
- `1` → Malware detected

## 📚 Data Sources

- [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) – Hash values of known malware

The hash database (`full_md5.txt`, `full_sha256.csv`) must be downloaded locally and is loaded on startup.

## 🔒 License

This project is licensed under the **GPLv3**.  
That means:
- The code will always remain free and open.  
- Derivative works must also be released under GPLv3.  
- Nobody can close or exclusively commercialize DataRowz.  

See [LICENSE](LICENSE) for full details.

---

✍️ *DataRowz is developed as an open source project. Contributions are welcome!*
