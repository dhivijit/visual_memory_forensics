#!/usr/bin/env python3
"""
proc_dump_pipeline.py

Usage:
    python proc_dump_pipeline.py -i <dumpfile.dmp> -o <output_dir> [--yara-rules rules.yar]

Produces:
  - cdb.txt                    : raw WinDbg/cdb output
  - strings.txt                : ascii + utf-16 strings
  - pe_sieve_report.json       : pe-sieve JSON if run
  - pe_sieve_dumps/            : any dumped in-memory PEs/shellcode
  - analyzer_report.json       : combined, LLM-friendly JSON
  - per-dumped-file analysis (rizin outputs, hashes, yara matches)
"""

import argparse
import os
import subprocess
import shutil
import json
import hashlib
import re
import math
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# === Config: adjust if tools are not in PATH or have different names ===
CDB_CMD = "cdb"               # cdb (WinDbg CLI). Use full path if needed.
STRINGS_CMD = "strings"       # Sysinternals strings or GNU strings
PE_SIEVE_CMD = "pe-sieve64.exe"  # pe-sieve executable
YARA_CMD = "yara64"             # yara binary
RIZIN_CMD = "rizin"           # or "radare2" if you prefer (script adjustments needed)

# === helpers ===
def run_cmd(cmd: List[str], timeout: int = 120, capture_output: bool = True) -> Dict[str, Any]:
    """Run command, return dict with returncode, stdout, stderr"""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE if capture_output else None,
                              stderr=subprocess.PIPE if capture_output else None,
                              timeout=timeout, check=False, text=True, shell=False)
        return {"rc": proc.returncode, "stdout": proc.stdout if capture_output else "", "stderr": proc.stderr if capture_output else ""}
    except subprocess.TimeoutExpired as e:
        return {"rc": -1, "stdout": getattr(e, "stdout", ""), "stderr": f"TIMEOUT after {timeout}s"}

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

# simple IoC regexes
RE_URL = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
RE_DOMAIN = re.compile(r"\b([a-z0-9\.-]+\.[a-z]{2,})\b", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b")

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    urls = RE_URL.findall(text)
    ips = RE_IPV4.findall(text)
    domains = RE_DOMAIN.findall(text)
    # deduplicate while preserving order:
    def uniq(seq): 
        seen=set(); out=[]
        for s in seq:
            if s not in seen:
                seen.add(s); out.append(s)
        return out
    return {"urls": uniq(urls), "ips": uniq(ips), "domains": uniq(domains)}

# === main pipeline functions ===
def run_cdb_on_dump(dump_path: Path, out_dir: Path) -> Path:
    """
    Runs cdb (WinDbg CLI) on the dump with useful commands and saves output to cdb.txt
    """
    out_file = out_dir / "cdb.txt"
    # commands to run inside cdb; end with 'q' to quit
    cdb_commands = [
        ".symfix",
        ".reload",
        "!peb",
        "lm",                # modules
        "!handle",           # handles
        "~* k",              # thread call stacks
        "!heap -s",          # heap summary
        "!address -summary", # memory regions
        ".imgscan",          # find images in memory
        "!analyze -v",
        "q"
    ]
    # join into one -c argument; cdb handles semicolon-separated commands
    cmd = [CDB_CMD, "-z", str(dump_path), "-c", "; ".join(cdb_commands)]
    print("[*] Running cdb:", " ".join(cmd))
    result = run_cmd(cmd, timeout=240, capture_output=True)
    with open(out_file, "w", encoding="utf-8", errors="replace") as f:
        header = f"=== cdb run on {dump_path} at {datetime.utcnow().isoformat()}Z ===\n"
        f.write(header)
        f.write(result.get("stdout", "") or "")
        if result.get("stderr"):
            f.write("\n=== STDERR ===\n")
            f.write(result.get("stderr"))
    return out_file

def run_strings_on_file(path: Path, out_dir: Path) -> Path:
    out_file = out_dir / "strings.txt"
    # try to extract ASCII and UTF-16 strings (if strings supports -e l or -n)
    # Generic invocation:
    cmd = [STRINGS_CMD, "-a", "-n", "6", str(path)]
    print("[*] Running strings:", " ".join(cmd))
    res = run_cmd(cmd, timeout=120)
    with open(out_file, "w", encoding="utf-8", errors="replace") as f:
        f.write(res.get("stdout", ""))
        if res.get("stderr"):
            f.write("\n=== STDERR ===\n")
            f.write(res.get("stderr"))
    return out_file

def run_pe_sieve_on_file(path: Path, out_dir: Path) -> Optional[Path]:
    """
    Runs pe-sieve -f <file> -o <outdir>
    Expects pe-sieve to produce a JSON report in the output dir.
    """
    if not shutil.which(PE_SIEVE_CMD):
        print("[!] pe-sieve not found in PATH; skipping pe-sieve step.")
        return None
    ps_outdir = out_dir / "pe_sieve_results"
    ps_outdir.mkdir(exist_ok=True)
    cmd = [PE_SIEVE_CMD, "-f", str(path), "-o", str(ps_outdir), "--json"]
    print("[*] Running pe-sieve:", " ".join(cmd))
    res = run_cmd(cmd, timeout=120)
    # pe-sieve writes files into ps_outdir; try to find a scan_report.json or similar
    # Save cummulative output
    with open(ps_outdir / "pe_sieve_stdout.txt", "w", encoding="utf-8", errors="replace") as f:
        f.write(res.get("stdout",""))
        if res.get("stderr"):
            f.write("\n=== STDERR ===\n")
            f.write(res.get("stderr"))
    # try to find json report
    json_candidates = list(ps_outdir.glob("**/*.json"))
    if json_candidates:
        return json_candidates[0]
    # else return the ps_outdir for inspection
    return ps_outdir

def run_yara_on_file(yara_rules_path: Path, target_path: Path, out_dir: Path) -> Optional[Path]:
    if not shutil.which(YARA_CMD):
        print("[!] yara not present in PATH; skipping yara scans.")
        return None
    out_file = out_dir / f"yara_{target_path.name}.txt"
    cmd = [YARA_CMD, "-r", str(yara_rules_path), str(target_path)]
    print("[*] Running yara:", " ".join(cmd))
    res = run_cmd(cmd, timeout=60)
    with open(out_file, "w", encoding="utf-8", errors="replace") as f:
        f.write(res.get("stdout",""))
        if res.get("stderr"):
            f.write("\n=== STDERR ===\n")
            f.write(res.get("stderr"))
    return out_file

def analyze_dumped_pe(dumped_path: Path, out_dir: Path) -> Dict[str, Any]:
    """
    For each dumped PE, compute hashes, entropy, try rizin to get imports/strings if available.
    """
    info = {"path": str(dumped_path), "sha256": sha256(dumped_path), "md5": md5(dumped_path)}
    # entropy
    with open(dumped_path,"rb") as f:
        data = f.read()
    info["entropy"] = entropy(data)
    info["size"] = dumped_path.stat().st_size
    # rizin analysis (if present)
    if shutil.which(RIZIN_CMD):
        r_out = out_dir / (dumped_path.stem + "_rizin.txt")
        # quick rizin command to print imports and strings
        # -q quiet; -c commands; -c q to quit
        r_cmd = [RIZIN_CMD, "-q", "-c", "aa; ie; iz; afl; q", str(dumped_path)]
        print("[*] Running rizin on", dumped_path.name)
        res = run_cmd(r_cmd, timeout=60)
        with open(r_out, "w", encoding="utf-8", errors="replace") as f:
            f.write(res.get("stdout",""))
            if res.get("stderr"):
                f.write("\n=== STDERR ===\n")
                f.write(res.get("stderr"))
        info["rizin_report"] = str(r_out)
    else:
        info["rizin_report"] = None
    return info

def parse_pe_sieve_json(json_path: Path) -> List[Path]:
    """
    Parse pe-sieve JSON (if present) to enumerate dumped files produced by pe-sieve.
    Common pattern: pe-sieve dumps files in the specified output dir; names vary.
    This returns Path list of likely dumped binaries (by extension or heuristic).
    """
    dumped = []
    try:
        j = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        print("[!] Unable to parse pe-sieve JSON:", json_path)
        return dumped
    # pe-sieve JSON structure varies; look for keys that reference dumped file paths
    def walk(obj):
        if isinstance(obj, dict):
            for k,v in obj.items():
                if isinstance(v, str) and ("dump" in v.lower() or v.endswith(".bin") or v.endswith(".dll") or v.endswith(".exe") or v.endswith(".shc")):
                    p = Path(v)
                    if p.exists():
                        dumped.append(p)
                else:
                    walk(v)
        elif isinstance(obj, list):
            for e in obj:
                walk(e)
    walk(j)
    # fallback: look for any bin/dll/exe/shc under the folder of json
    candidates = list(json_path.parent.glob("*.*"))
    for c in candidates:
        if c.suffix.lower() in [".bin", ".dll", ".exe", ".shc"]:
            if c not in dumped:
                dumped.append(c)
    return dumped

def build_summary(cdb_txt_path: Path, strings_path: Path, pe_sieve_json: Optional[Path], carved_infos: List[Dict[str,Any]]) -> Dict[str,Any]:
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "cdb_output": str(cdb_txt_path),
        "strings_output": str(strings_path),
        "pe_sieve_report": str(pe_sieve_json) if pe_sieve_json else None,
        "carved_files": carved_infos,
        "iocs": {},
        "notes": []
    }
    # parse cdb for simple fields: image path, cmdline, pid, modules, threads -- use regex heuristics
    cdb_text = cdb_txt_path.read_text(encoding="utf-8", errors="replace")
    # attempt to find "CommandLine" from !peb output
    m_cmdline = re.search(r"CommandLine\s*:\s*(.+)", cdb_text)
    if m_cmdline:
        report["process_command_line"] = m_cmdline.group(1).strip()
    # collect module lines (lm output typically: start-end module path)
    modules = []
    for line in cdb_text.splitlines():
        # very rough heuristic
        if line.strip().startswith("0x") and "   " in line:
            modules.append(line.strip())
    report["raw_modules_lines"] = modules
    # extract raw stacks section (between lines containing "Stack" perhaps); easier: capture "~* k" block by locating that command's output
    # crude: include all lines that contain "!" or "ntdll!" or "kernel32!" or "LoadLibrary"
    stacks = [ln for ln in cdb_text.splitlines() if ("!" in ln and "!" in ln.split()[0]) or "LoadLibrary" in ln or "VirtualAlloc" in ln or "CreateRemoteThread" in ln]
    report["interesting_stack_lines"] = stacks[:500]  # limit size
    # extract iocs from strings file
    stext = strings_path.read_text(encoding="utf-8", errors="replace")
    iocs = extract_iocs_from_text(stext)
    report["iocs"] = iocs
    report["summary_indicators"] = {
        "num_urls": len(iocs.get("urls",[])),
        "num_ips": len(iocs.get("ips",[])),
        "num_domains": len(iocs.get("domains",[])),
        "num_carved_files": len(carved_infos)
    }
    return report

# === main CLI ===
def main():
    ap = argparse.ArgumentParser(description="Process-only dump pipeline: cdb, strings, pe-sieve, yara, rizin, hashes.")
    ap.add_argument("-i", "--input", required=True, help="Process dump file (proc_1234.dmp)")
    ap.add_argument("-o", "--outdir", required=True, help="Output directory")
    ap.add_argument("--yara-rules", help="YARA rules file (optional)")
    args = ap.parse_args()

    dump_path = Path(args.input).resolve()
    out_dir = Path(args.outdir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) run cdb and capture output
    cdb_txt = run_cdb_on_dump(dump_path, out_dir)

    # 2) run strings
    strings_txt = run_strings_on_file(dump_path, out_dir)

    # 3) run pe-sieve on the raw dump
    pe_sieve_json = run_pe_sieve_on_file(dump_path, out_dir)

    # 4) analyze carved files from pe-sieve result
    carved_infos = []
    if pe_sieve_json:
        # if pe_sieve_json is a directory fallback, try to find JSON inside
        if isinstance(pe_sieve_json, Path) and pe_sieve_json.is_dir():
            # try to find json files in dir
            candidates = list(pe_sieve_json.glob("**/*.json"))
            if candidates:
                pe_sieve_json = candidates[0]
        if pe_sieve_json and pe_sieve_json.exists():
            dumped_paths = parse_pe_sieve_json(pe_sieve_json)
            for dp in dumped_paths:
                info = analyze_dumped_pe(dp, out_dir)
                # run yara on each dumped file if rules given
                if args.yara_rules:
                    yara_out = run_yara_on_file(Path(args.yara_rules), dp, out_dir)
                    info["yara_match_file"] = str(yara_out) if yara_out else None
                carved_infos.append(info)
        else:
            print("[*] pe-sieve produced no JSON report; scanning output directory for dumped files...")
            # fallback: scan the pe_sieve_results dir for dumped bins
            ps_dir = out_dir / "pe_sieve_results"
            if ps_dir.exists():
                for c in ps_dir.glob("*"):
                    if c.suffix.lower() in [".bin", ".dll", ".exe", ".shc"]:
                        carved_infos.append(analyze_dumped_pe(c, out_dir))

    # 5) run yara on the raw dump if rules provided
    if args.yara_rules:
        run_yara_on_file(Path(args.yara_rules), dump_path, out_dir)

    # 6) compute top-level hashes for the dump
    dump_hashes = {"sha256": sha256(dump_path), "md5": md5(dump_path), "size": dump_path.stat().st_size}
    with open(out_dir / "dump_hashes.json", "w") as f:
        json.dump(dump_hashes, f, indent=2)

    # 7) build final summary JSON for LLM consumption
    summary = build_summary(cdb_txt, strings_txt, pe_sieve_json if isinstance(pe_sieve_json, Path) else None, carved_infos)
    summary["dump_hashes"] = dump_hashes
    summary["carved_files_detailed"] = carved_infos
    with open(out_dir / "analyzer_report.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("[*] Finished. Outputs in:", out_dir)
    print("  - cdb output:", cdb_txt)
    print("  - strings:", strings_txt)
    print("  - analyzer JSON:", out_dir / "analyzer_report.json")
    if pe_sieve_json:
        print("  - pe-sieve report:", pe_sieve_json)

if __name__ == "__main__":
    main()
