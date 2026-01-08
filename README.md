# File Integrity Monitor (Python)

## Author

**PedroZoro**  

A lightweight, real-time **File Integrity Monitoring (FIM)** tool written in Python.  
It watches a directory, hashes files, detects tampering, deletions, renames, and new files — and logs everything like a paranoid butler (the good kind).

This tool is useful for:
- Malware / ransomware detection
- Incident response & forensics labs
- USB / drop-folder monitoring
- Blue-team experimentation
- Answering the eternal question: *who touched my files?*

---

## Features

- Recursive directory monitoring  
- SHA1 + SHA256 hashing  
- Real-time detection using `watchdog`  
- Debounced filesystem events (less noise, more signal)  
- Persistent baseline stored as JSON  
- Automatic baseline updates on changes  
- Graceful shutdown (Ctrl+C)  
- Timestamped alerts  

---

## Directory Structure

```
.
├── watch_dir/              # Directory being monitored
├── hash_store/
│   └── hashes.json         # Stored baseline hashes
├── monitor.py              # Main script
```

---

## How It Works

1. **Initial Run**
   - Scans `watch_dir/`
   - Computes SHA1 and SHA256 hashes
   - Stores them as a baseline

2. **Runtime Monitoring**
   - Watches filesystem events in real time
   - Detects:
     - `[TAMPERED]` file modifications
     - `[NEW FILE]` creations
     - `[DELETED]` removals
     - `[RENAMED]` moves / renames
   - Updates baseline accordingly

3. **Noise Reduction**
   - Debouncing prevents duplicate alerts
   - Delayed reads ensure writes are complete

---

## Requirements

- Python **3.8+**
- Linux / Windows / macOS

### Dependency

```bash
pip install watchdog
```

---

## Usage

```bash
python monitor.py
```

- Place files inside `watch_dir/`
- Modify, delete, or add files
- Observe integrity alerts in real time

Stop the monitor using **Ctrl+C**.

---

## Sample Output

```
[✓] File Integrity Monitor started at 2026-01-08 22:41:03
[✓] Monitoring directory: /home/user/watch_dir

[2026-01-08 22:42:11] [NEW FILE] payload.exe
[2026-01-08 22:43:02] [TAMPERED] config.json
    Old Hash: a9f3c91d8b3a4c12...
    New Hash: 77b9e2af10c94d55...

[2026-01-08 22:44:10] [DELETED] notes.txt
```

---

## Hashing Details

- Reads files in **4KB chunks**
- Includes retry logic to handle race conditions
- Hash algorithms used:
  - SHA1 (legacy compatibility)
  - SHA256 (primary integrity check)

---

## Limitations

- User-space monitoring only (not kernel-level)
- Baseline file is not cryptographically protected
- If an attacker controls the system and the hash store, integrity is compromised
- Designed for learning, labs, and lightweight monitoring — not enterprise EDR

---

## License

MIT License.  
Use it, break it, improve it — just don’t pretend you wrote it.
