import psutil
import subprocess
import time
import os
import csv

# === CONFIGURATION ===
CPU_THRESHOLD = 30.0          # CPU % above which a process is considered suspicious
SCAN_INTERVAL = 30            # Seconds between scans
DUMP_DIR = "memory_dumps"     # Folder to store .dmp files
METADATA_FILE = "dump_metadata.csv"
PROCDUMP_PATH = "procdump.exe"  # Full path to procdump.exe if not in system PATH

# === Ensure dump directory exists ===
os.makedirs(DUMP_DIR, exist_ok=True)

# === Initialize CSV if not exists ===
if not os.path.exists(METADATA_FILE):
    with open(METADATA_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Timestamp', 'PID', 'ProcessName', 'CPU%', 'DumpFilename'])

# === Monitor and Dump ===
print("Monitoring started... Press Ctrl+C to stop.")
try:
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] > CPU_THRESHOLD:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    cpu = proc.info['cpu_percent']
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    dump_filename = f"{name}_{pid}_{timestamp}.dmp"
                    full_path = os.path.join(DUMP_DIR, dump_filename)

                    print(f"[+] High CPU Detected: {name} (PID {pid}) - CPU {cpu}%")
                    print(f"    Dumping memory to {dump_filename}...")

                    subprocess.run([PROCDUMP_PATH, "-ma", str(pid), full_path])

                    with open(METADATA_FILE, 'a', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow([timestamp, pid, name, cpu, dump_filename])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(SCAN_INTERVAL)

except KeyboardInterrupt:
    print("Monitoring stopped by user.")
