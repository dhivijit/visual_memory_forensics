# volatility_run_on_dmp.py

import os, re, csv, time, json, math, hashlib, subprocess, psutil
from datetime import datetime
from pathlib import Path

# =========================
# CONFIG
# =========================
CPU_THRESHOLD = 30.0          # sustained CPU % to trigger a dump
WINDOW_SECONDS = 10           # how long the CPU must stay above threshold
SCAN_INTERVAL = 5             # how often we sample CPU (seconds)

ROOT_OUT = Path("forensics_out")
DUMPS_DIR = ROOT_OUT / "dumps"
RULES_DIR = ROOT_OUT / "rules"
TOOLS_DIR = ROOT_OUT / "tools"      # optional: place procdump here

# Path overrides
PROCDUMP = os.environ.get("PROCDUMP_PATH", "procdump.exe")  # or r"C:\tools\procdump.exe"
VOL_PY   = os.environ.get("VOLATILIT_PATH", r"C:/Users/dhivi/portable apps/volatility3/vol.py")

YARA_RULEFILE = RULES_DIR / "crypto_webminer.yar"

# Strings / indicators
import sys
import glob
import shutil
import argparse

URL_RE   = re.compile(rb"https?://[^\s\"'<>]{5,}")
WSS_RE   = re.compile(rb"wss?://[^\s\"'<>]{5,}")
STRATUM  = re.compile(rb"stratum\+tcp")
WALLET_XMR = re.compile(rb"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{90,100}")  # loose Base58
WASM_MAGIC = b"\x00asm"
MZ = b"MZ"; PE = b"PE\x00\x00"

# =========================
# UTILS
# =========================
def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def run(cmd, cwd=None, out_path: Path|None=None, check=False):
    print("[>] ", " ".join(map(str, cmd)))
    if out_path:
        with open(out_path, "w", encoding="utf-8", errors="ignore") as f:
            return subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT, check=check)
    else:
        return subprocess.run(cmd, cwd=cwd, check=check)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()

def shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0]*256
    for b in buf:
        counts[b] += 1
    ent = 0.0
    n = len(buf)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def zero_ratio(buf: bytes) -> float:
    if not buf: return 0.0
    return buf.count(0) * 100.0 / len(buf)

def find_all(hay: bytes, needle: bytes):
    off = 0
    while True:
        i = hay.find(needle, off)
        if i < 0: break
        yield i
        off = i + 1

def extract_strings(buf: bytes, minlen=6):
    out = []
    cur = bytearray()
    for b in buf:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur))
            cur.clear()
    if len(cur) >= minlen:
        out.append(bytes(cur))
    return out

# =========================
# YARA RULES (triage)
# =========================
YARA_RULES_TEXT = r"""
rule WASM_Magic { strings: $m = { 00 61 73 6D } condition: $m }
rule Stratum_Indicators {
  strings:
    $s1 = "stratum+tcp"
    $s2 = "mining.subscribe"
    $s3 = "mining.authorize"
    $s4 = "mining.notify"
    $ws = "wss://"
  condition: any of them
}
rule Crypto_Kernels {
  strings:
    $a1 = "cryptonight"
    $a2 = "argon2"
    $a3 = "keccak"
    $a4 = "blake2"
    $a5 = "salsa20"
  condition: any of them
}
"""

# =========================
# VOLATILITY HELPERS (Vol3 syntax)
# =========================
def volatility_json(dump: Path, plugin: str, out_json: Path, extra: list[str]|None=None):
    # Vol 3: use --output-format/--output-file
    args = ["python", str(VOL_PY), "-f", str(dump), plugin,
            "--output-format", "json", "--output-file", str(out_json)]
    if extra:
        args += extra
    run(args, check=True)

def volatility_yara(dump: Path, rulefile: Path, out_json: Path):
    args = ["python", str(VOL_PY), "-f", str(dump), "yarascan.YaraScan",
            "--yara-rules", str(rulefile),
            "--output-format", "json", "--output-file", str(out_json)]
    run(args, check=True)

def volatility_vadump(dump: Path, out_dir: Path):
    mkdir(out_dir)
    args = ["python", str(VOL_PY), "-f", str(dump),
            "windows.vadump", "--dump-dir", str(out_dir)]
    run(args, check=True)

# =========================
# CARVED REGION ANALYZER
# =========================
def analyze_carved_regions(vadump_dir: Path, summary_json: Path, max_regions: int|None=None):
    results = []
    files = sorted(vadump_dir.glob("*.dmp"))
    if max_regions:
        files = files[:max_regions]
    for f in files:
        try:
            with open(f, "rb") as fh:
                buf = fh.read()
            base = None
            m = re.search(r"([0-9A-Fa-f]{8,16})", f.name)
            if m: base = "0x" + m.group(1)

            blk = 4096
            ents = [shannon_entropy(buf[i:i+blk]) for i in range(0, len(buf), blk)]
            mean_ent = sum(ents)/len(ents) if ents else 0.0
            zr = zero_ratio(buf)

            mz_pe_hits = [{"off": off} for off in find_all(buf, MZ)]
            wasm_hits  = [{"off": off} for off in find_all(buf, WASM_MAGIC)]

            urls  = [m.group(0).decode("ascii", "ignore") for m in URL_RE.finditer(buf)]
            wsss  = [m.group(0).decode("ascii", "ignore") for m in WSS_RE.finditer(buf)]
            has_stratum = bool(STRATUM.search(buf))
            wallets = [m.group(0).decode("ascii", "ignore") for m in WALLET_XMR.finditer(buf)]

            score = 0.0
            if mean_ent >= 7.5: score += 0.35
            if wasm_hits: score += 0.25
            if has_stratum or wsss: score += 0.25
            if mz_pe_hits: score += 0.10
            if wallets: score += 0.15
            score = min(score, 0.99)

            results.append({
                "file": str(f),
                "base": base,
                "size": len(buf),
                "entropy_mean": round(mean_ent, 3),
                "zero_pct": round(zr, 2),
                "mz_pe_hits": mz_pe_hits[:20],
                "wasm_hits": wasm_hits[:20],
                "urls_sample": urls[:20],
                "wss_sample": wsss[:20],
                "wallet_candidates": wallets[:5],
                "has_stratum_literal": has_stratum,
                "suspicion_score": round(score, 2)
            })
        except Exception as e:
            results.append({"file": str(f), "error": str(e)})
    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

# =========================
# OS CONTEXT + BUNDLE
# =========================
def capture_os_context(pid: int, dump_dir: Path):
    run(["cmd", "/c", "netstat -ano"], out_path=dump_dir / f"netstat_{pid}.txt")
    run(["cmd", "/c", "ipconfig /displaydns"], out_path=dump_dir / f"dns_{pid}.txt")
    run(["cmd", "/c", f"tasklist /m /fi \"PID eq {pid}\""], out_path=dump_dir / f"modules_{pid}.txt")

def write_yara_rules():
    mkdir(RULES_DIR)
    with open(YARA_RULEFILE, "w", encoding="utf-8") as f:
        f.write(YARA_RULES_TEXT)

def build_bundle(dump_path: Path, proc_meta: dict, out_dir: Path):
    bundle = {
        "context": {
            "dump_file": str(dump_path),
            "dump_sha256": sha256_file(dump_path),
            "process": proc_meta,
            "artifacts": [f"netstat_{proc_meta['pid']}.txt",
                          f"modules_{proc_meta['pid']}.txt",
                          f"dns_{proc_meta['pid']}.txt"]
        },
        "volatility": {
            "vadinfo": "vadinfo.json",
            "malfind": "malfind.json",
            "dlllist": "dlllist.json",
            "yarascan": "yara.json",
            "threads": "threads.json"
        },
        "carving": {
            "dir": "carved_regions",
            "regions_summary": "regions_summary.json"
        },
        "image_mapping": {
            "scheme": "row-major, 3 bytes per pixel",
            "formula": "offset = (row*2048 + col)*3"
        }
    }
    with open(out_dir / "bundle.json", "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

# =========================
# DUMP + TRIAGE ONE PROCESS
# =========================
def dump_and_triage(proc: psutil.Process):
    try:
        if proc.pid == 0:
            print(f"[!] Skipping PID 0")
            return
    except Exception:
        return

    pinfo = proc.as_dict(attrs=["pid","name","username","ppid","num_threads","create_time"])
    pinfo["cpu_percent_1s"] = proc.cpu_percent(interval=1.0)
    try:
        mem = proc.memory_info()
        pinfo["rss"] = mem.rss; pinfo["vms"] = mem.vms
    except Exception:
        pinfo["rss"] = pinfo["vms"] = 0
    try:
        pinfo["cmdline"] = " ".join(proc.cmdline() or [])
    except psutil.AccessDenied:
        pinfo["cmdline"] = ""

    stamp = ts()
    case_dir = ROOT_OUT / f"{pinfo['name']}_{pinfo['pid']}_{stamp}"
    mkdir(case_dir); mkdir(DUMPS_DIR)

    dump_path = case_dir / f"{pinfo['name']}_{pinfo['pid']}_{stamp}.dmp"
    print(f"[+] High CPU: {pinfo['name']} ({pinfo['pid']}) — dumping to {dump_path.name}")
    run([PROCDUMP, "-accepteula", "-ma", str(pinfo["pid"]), str(dump_path)], check=False)

    # OS context
    capture_os_context(pinfo["pid"], case_dir)

    # Volatility JSON triage
    vadinfo_json  = case_dir / "vadinfo.json"
    malfind_json  = case_dir / "malfind.json"
    dlllist_json  = case_dir / "dlllist.json"
    yara_json     = case_dir / "yara.json"
    threads_json  = case_dir / "threads.json"

    volatility_json(dump_path, "windows.vadinfo", vadinfo_json)
    volatility_json(dump_path, "windows.malfind", malfind_json)
    volatility_json(dump_path, "windows.dlllist", dlllist_json)
    volatility_json(dump_path, "windows.threads", threads_json)

    write_yara_rules()
    volatility_yara(dump_path, YARA_RULEFILE, yara_json)

    # VAD carving + analysis
    vadump_dir = case_dir / "carved_regions"
    volatility_vadump(dump_path, vadump_dir)
    analyze_carved_regions(vadump_dir, case_dir / "regions_summary.json")

    build_bundle(dump_path, pinfo, case_dir)
    print(f"[✓] Triage complete: {case_dir}")
    print(f"    -> bundle.json is ready for the LLM")

# =========================
# WATCHER LOOP
# =========================
def watcher():
    mkdir(ROOT_OUT)
    print("Monitoring started… Ctrl+C to stop.")
    above = {}
    last_sample = {}

    while True:
        try:
            for proc in psutil.process_iter(['pid','name']):
                pid = proc.info['pid']
                if pid == 0:
                    continue
                try:
                    cur = proc.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    above.pop(pid, None)
                    continue

                now = time.time()
                last = last_sample.get(pid, now)
                last_sample[pid] = now

                entry = above.get(pid, {"t0": None, "max": 0.0})
                if cur >= CPU_THRESHOLD:
                    if entry["t0"] is None:
                        entry["t0"] = now
                        entry["max"] = cur
                    else:
                        entry["max"] = max(entry["max"], cur)
                    above[pid] = entry
                    if (now - entry["t0"]) >= WINDOW_SECONDS:
                        try:
                            dump_and_triage(psutil.Process(pid))
                        except Exception as e:
                            print(f"[!] triage failed for PID {pid}: {e}")
                        finally:
                            above.pop(pid, None)
                else:
                    above.pop(pid, None)
            time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            print("\nStopped by user.")
            break

if __name__ == "__main__":
    mkdir(ROOT_OUT); mkdir(DUMPS_DIR); mkdir(RULES_DIR)
    parser = argparse.ArgumentParser(description="Run volatility triage on either live processes (watcher) or on an existing .dmp file.")
    parser.add_argument("--dmp", help="Path to an existing .dmp file to triage (if provided, watcher will not run)")
    parser.add_argument("--out", help="Optional output directory for the triage results (default: forensics_out/<dmpbasename>_manual_<ts>)")
    args = parser.parse_args()

    # Ensure a minimal manifest exists for compatibility with other tools/scripts
    manifest = ROOT_OUT / "dump_manifest.csv"
    if not manifest.exists():
        with open(manifest, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp","name","pid","dump_dir"])

    def process_existing_dmp(dmp_path: str, out_override: str|None = None):
        dmp = Path(dmp_path)
        if not dmp.exists():
            print(f"❌ Provided dmp does not exist: {dmp}")
            return
        stamp = ts()
        base = dmp.stem
        if out_override:
            case_dir = Path(out_override)
        else:
            case_dir = ROOT_OUT / f"{base}_manual_{stamp}"
        mkdir(case_dir)

        # Copy or reference the dmp into the case dir (we will reference in place to avoid large copies)
        # If you prefer a local copy, uncomment the copy below.
        # local_dmp = case_dir / dmp.name
        # shutil.copy2(dmp, local_dmp)
        local_dmp = dmp

        # Prepare output paths
        vadinfo_json  = case_dir / "vadinfo.json"
        malfind_json  = case_dir / "malfind.json"
        dlllist_json  = case_dir / "dlllist.json"
        yara_json     = case_dir / "yara.json"
        threads_json  = case_dir / "threads.json"

        # Run volatility plugins
        print(f"[>] Running volatility triage on {local_dmp} -> {case_dir}")
        volatility_json(local_dmp, "windows.vadinfo", vadinfo_json)
        volatility_json(local_dmp, "windows.malfind", malfind_json)
        volatility_json(local_dmp, "windows.dlllist", dlllist_json)
        volatility_json(local_dmp, "windows.threads", threads_json)

        # YARA
        write_yara_rules()
        volatility_yara(local_dmp, YARA_RULEFILE, yara_json)

        # VAD carving
        vadump_dir = case_dir / "carved_regions"
        volatility_vadump(local_dmp, vadump_dir)
        analyze_carved_regions(vadump_dir, case_dir / "regions_summary.json")

        # Build a minimal proc_meta for the bundle (we don't have runtime process info)
        proc_meta = {"pid": 0, "name": base, "username": "", "ppid": 0, "num_threads": 0, "create_time": stamp}
        build_bundle(local_dmp, proc_meta, case_dir)
        print(f"[✓] Triaged existing dmp: {local_dmp} -> {case_dir}")

    if args.dmp:
        process_existing_dmp(args.dmp, args.out)
    else:
        watcher()
