import os
import hashlib
import json
import time
import signal
import sys
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from threading import Lock

WATCH_DIR = Path("watch_dir")
HASH_STORE = Path("hash_store/hashes.json")

CHUNK_SIZE = 4096

# Debouncing mechanism
PENDING_EVENTS = {}
EVENT_LOCK = Lock()
DEBOUNCE_TIME = 0.5


def compute_hashes(file_path):
    """Compute SHA1 and SHA256 hashes with retry logic"""
    max_retries = 5
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            with open(file_path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    sha1.update(chunk)
                    sha256.update(chunk)

            return {
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest()
            }
        except (IOError, OSError) as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                raise e


def generate_baseline():
    hashes = {}

    for file in WATCH_DIR.rglob("*"):
        if file.is_file():
            hashes[str(file.relative_to(WATCH_DIR))] = compute_hashes(file)

    HASH_STORE.parent.mkdir(exist_ok=True)
    with open(HASH_STORE, "w") as f:
        json.dump(hashes, f, indent=4)

    print("[+] Baseline hashes created.")


def load_baseline():
    if not HASH_STORE.exists():
        return None
    with open(HASH_STORE, "r") as f:
        return json.load(f)


def update_baseline(file_path, hashes):
    """Update the baseline with new hashes for a file"""
    baseline = load_baseline() or {}
    baseline[str(file_path)] = hashes
    HASH_STORE.parent.mkdir(exist_ok=True)
    with open(HASH_STORE, "w") as f:
        json.dump(baseline, f, indent=4)


def verify_integrity():
    baseline = load_baseline()
    if baseline is None:
        print("[!] No baseline found. Creating one now...")
        generate_baseline()
        return

    current_files = {}
    for file in WATCH_DIR.rglob("*"):
        if file.is_file():
            current_files[str(file.relative_to(WATCH_DIR))] = compute_hashes(file)

    # Check for tampering
    for file, hashes in baseline.items():
        if file not in current_files:
            print(f"[DELETED] {file}")
        elif hashes != current_files[file]:
            print(f"[TAMPERED] {file}")

    # Check for new files
    for file in current_files:
        if file not in baseline:
            print(f"[NEW FILE] {file}")

    print("[✓] Integrity check completed.")


class FileIntegrityHandler(FileSystemEventHandler):
    """Real-time file system event handler for integrity monitoring"""

    def _debounce_event(self, file_path):
        """Check if event should be processed based on debouncing"""
        with EVENT_LOCK:
            current_time = time.time()
            file_key = str(file_path)
            
            if file_key in PENDING_EVENTS:
                last_time = PENDING_EVENTS[file_key]
                if current_time - last_time < DEBOUNCE_TIME:
                    return False
            
            PENDING_EVENTS[file_key] = current_time
            return True

    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if not file_path.is_file():
            return
        
        if not self._debounce_event(file_path):
            return
        
        # Wait longer to ensure file write is complete
        time.sleep(0.7)
        
        try:
            rel_path = str(file_path.relative_to(WATCH_DIR))
            baseline = load_baseline() or {}
            
            if rel_path in baseline:
                current_hashes = compute_hashes(file_path)
                old_hashes = baseline[rel_path]
                
                if current_hashes != old_hashes:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [TAMPERED] {rel_path}")
                    print(f"    Old Hash: {old_hashes['sha256'][:16]}...")
                    print(f"    New Hash: {current_hashes['sha256'][:16]}...")
                    update_baseline(rel_path, current_hashes)
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Failed to check {event.src_path}: {e}")

    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if not file_path.is_file():
            return
        
        if not self._debounce_event(file_path):
            return
        
        # Wait to ensure file is fully written
        time.sleep(0.7)
        
        try:
            rel_path = str(file_path.relative_to(WATCH_DIR))
            baseline = load_baseline() or {}
            
            if rel_path not in baseline:
                hashes = compute_hashes(file_path)
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [NEW FILE] {rel_path}")
                update_baseline(rel_path, hashes)
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Failed to process new file {event.src_path}: {e}")

    def on_moved(self, event):
        """Handle file renames and moves"""
        if event.is_directory:
            return
        
        dest_path = Path(event.dest_path)
        src_path = Path(event.src_path)
        
        if not dest_path.is_file():
            return
        
        try:
            src_rel = str(src_path.relative_to(WATCH_DIR))
            dest_rel = str(dest_path.relative_to(WATCH_DIR))
            baseline = load_baseline() or {}
            
            # If source exists in baseline, rename it
            if src_rel in baseline:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [RENAMED] {src_rel} -> {dest_rel}")
                baseline[dest_rel] = baseline.pop(src_rel)
                HASH_STORE.parent.mkdir(exist_ok=True)
                with open(HASH_STORE, "w") as f:
                    json.dump(baseline, f, indent=4)
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Failed to process rename {event.src_path} -> {event.dest_path}: {e}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        
        try:
            rel_path = str(Path(event.src_path).relative_to(WATCH_DIR))
            baseline = load_baseline() or {}
            
            if rel_path in baseline:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DELETED] {rel_path}")
                del baseline[rel_path]
                HASH_STORE.parent.mkdir(exist_ok=True)
                with open(HASH_STORE, "w") as f:
                    json.dump(baseline, f, indent=4)
        except Exception as e:
            print(f"[ERROR] Failed to process deletion {event.src_path}: {e}")


if __name__ == "__main__":
    # Create watch directory if it doesn't exist
    WATCH_DIR.mkdir(exist_ok=True)
    
    # Generate baseline if it doesn't exist
    baseline = load_baseline()
    if baseline is None:
        print("[!] No baseline found. Creating one now...")
        generate_baseline()
    
    print(f"[✓] File Integrity Monitor started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[✓] Monitoring directory: {WATCH_DIR.absolute()}")
    print("[!] Press Ctrl+C to stop monitoring\n")
    
    # Set up real-time file system monitoring
    event_handler = FileIntegrityHandler()
    observer = Observer()
    observer.schedule(event_handler, str(WATCH_DIR), recursive=True)
    observer.start()
    
    # Graceful shutdown handler
    def signal_handler(sig, frame):
        print(f"\n[!] Stopping monitor... ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
        observer.stop()
        observer.join()
        print("[✓] Monitor stopped.")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Keep the monitor running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
