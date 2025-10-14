#!/usr/bin/env python3
"""
llm_call.py

Focused forensic-to-LLM pipeline (ASCII-cleaned + noise-filter + final aggregation).
Processes a folder containing:
  analyzer_report.json
  cdb.txt
  dump_hashes.json
  yara_msedge.exe_*.txt
  strings.txt
  pe_results/imports.json

Usage examples:
  python llm_call.py --folder /path/to/forensics_out
  python llm_call.py --folder /path/to/forensics_out --api gpt --gpt-key sk-...
  python llm_call.py --folder /path/to/forensics_out --dry-run --verbose

Notes:
 - Default API is Perplexity unless --api gpt is specified.
 - Perplexity API call is a placeholder (replace URL/payload with the real endpoint).
"""

import os, sys, argparse, json, time, re, textwrap, math
from typing import Optional, Dict, Any, List

try:
    import requests
except ImportError:
    requests = None

# ---------------- CONFIGURATION ----------------

TARGET_FILES = [
    "analyzer_report.json",
    "cdb.txt",
    "dump_hashes.json",
    "yara_msedge.exe_1856_20250824_101044.dmp.txt",
    os.path.join("pe_results", "imports.json"),
    "strings.txt",
]

MINER_KEYWORDS = [
    "stratum","minexmr","xmr","pool","miner","cryptonight","randomx",
    "opencl","cuda","vulkan","vkCreate","vkDestroy","clCreate",
    "VirtualAlloc","VirtualProtect","GetProcAddress","WriteProcessMemory",
    "CreateRemoteThread","LoadLibrary","CryptAcquireContext","CryptCreateHash",
    "powershell","mshta","cmd.exe","injected","InjectedMemory","CodeInjection",
    "Watchdog","GPU","gpu-process"
]

STRINGS_HEAD_LINES = 400
STRINGS_TAIL_LINES = 200
STRINGS_KEYWORD_CONTEXT = 6
CHUNK_CHAR_LIMIT = 3800

# Noise thresholds (tweakable)
MIN_LINE_LEN = 4
ALNUM_RATIO_MIN = 0.25      # drop lines with <25% alnum (unless containing a keyword)
REPEAT_RUN_LEN = 6          # drop if any char repeats >= 6 consecutively (unless keyword)
SMALL_CHARSET_DROP_LEN = 50 # drop if len>50 and unique charset size <= 4 (unless keyword)

# ---------------- HELPERS ----------------

def clean_ascii(s: str) -> str:
    """Keep only basic ASCII characters (32–126 range and newline/tab)."""
    return ''.join(ch for ch in s if 32 <= ord(ch) <= 126 or ch in '\n\r\t')

def has_long_repeat(line: str, n: int = REPEAT_RUN_LEN) -> bool:
    """Detect long repeated-char runs like ')))))))'."""
    return re.search(r'(.)\1{' + str(n-1) + r',}', line) is not None

def is_mostly_symbols(line: str) -> bool:
    """True if line is composed only of whitespace and punctuation."""
    # \w = [A-Za-z0-9_]; if removing all non-word leaves nothing, it's all symbols/space
    return re.fullmatch(r'[\W_ \t\r\n]+', line) is not None

def alnum_ratio(line: str) -> float:
    if not line:
        return 0.0
    alnum = sum(ch.isalnum() for ch in line)
    return alnum / max(1, len(line))

def is_low_charset_variety(line: str) -> bool:
    """Very low character diversity -> likely noise art."""
    return len(line) > SMALL_CHARSET_DROP_LEN and len(set(line)) <= 4

def contains_keyword(line: str, keywords: List[str]) -> bool:
    L = line.lower()
    return any(k.lower() in L for k in keywords)

def is_noise_line(line: str, keywords: List[str]) -> bool:
    """Decide if a line from strings.txt is gibberish/noise and should be skipped."""
    if not line or len(line.strip()) < MIN_LINE_LEN:
        return True
    # Keep if keyword present (even if noisy)
    if contains_keyword(line, keywords):
        return False
    # Drop if only symbols/whitespace
    if is_mostly_symbols(line):
        return True
    # Drop if long repeated char runs
    if has_long_repeat(line, REPEAT_RUN_LEN):
        return True
    # Drop if too few alphanumerics overall
    if alnum_ratio(line) < ALNUM_RATIO_MIN:
        return True
    # Drop if extremely low diversity (ASCII "art")
    if is_low_charset_variety(line):
        return True
    return False

def load_text(path: str) -> str:
    with open(path, 'r', errors='replace') as f:
        return clean_ascii(f.read())

def load_json_text(path: str) -> str:
    try:
        with open(path, 'r', errors='replace') as fh:
            j = json.load(fh)
        txt = json.dumps(j, indent=2)
    except Exception:
        txt = load_text(path)
    return clean_ascii(txt)

def grep_context(lines: List[str], i: int, ctx: int) -> List[str]:
    start = max(0, i - ctx)
    end = min(len(lines), i + ctx + 1)
    return lines[start:end]

def prepare_strings_chunks(folder: str):
    p = os.path.join(folder, "strings.txt")
    if not os.path.exists(p):
        return []
    raw_lines = open(p, 'r', errors='replace').read().splitlines()
    # ASCII-clean first
    ascii_lines = [clean_ascii(l) for l in raw_lines]
    # Filter noise
    lines = [l for l in ascii_lines if not is_noise_line(l, MINER_KEYWORDS)]

    chunks = []

    # Head (filtered)
    head = "\n".join(lines[:STRINGS_HEAD_LINES])
    if head.strip():
        chunks.append(("strings_head", head))

    # Tail (filtered)
    if len(lines) > STRINGS_HEAD_LINES + STRINGS_TAIL_LINES:
        tail = "\n".join(lines[-STRINGS_TAIL_LINES:])
        if tail.strip():
            chunks.append(("strings_tail", tail))

    # Keyword contexts from original ASCII-clean (to ensure we don't miss keywords filtered by noise rules)
    lower_ascii = [l.lower() for l in ascii_lines]
    matched_idx = set()
    for i, L in enumerate(lower_ascii):
        if any(k in L for k in MINER_KEYWORDS):
            matched_idx.add(i)

    for idx in sorted(matched_idx):
        ctx_lines = grep_context(ascii_lines, idx, STRINGS_KEYWORD_CONTEXT)
        # Re-apply noise filter to context block but ALWAYS keep the hit line
        kept = []
        for j, line in enumerate(ctx_lines):
            if j == STRINGS_KEYWORD_CONTEXT:  # not reliable index; keep simpler: keep all, then drop noise except the center
                kept.append(line)
            else:
                if not is_noise_line(line, MINER_KEYWORDS) or contains_keyword(line, MINER_KEYWORDS):
                    kept.append(line)
        txt = "\n".join(kept)
        if txt.strip():
            chunks.append((f"strings_kw_{idx}", txt))

    # Merge small chunks to reduce API calls
    final = []
    buf = []
    for k, t in chunks:
        if len(t) < 200:
            buf.append(t)
            if len("\n".join(buf)) > 1000:
                final.append(("strings_combined", "\n".join(buf)))
                buf = []
        else:
            final.append((k, t))
    if buf:
        final.append(("strings_combined_tail", "\n".join(buf)))

    # Enforce per-chunk size
    out = []
    for k, t in final:
        if len(t) > CHUNK_CHAR_LIMIT:
            n = math.ceil(len(t)/CHUNK_CHAR_LIMIT)
            for i in range(n):
                out.append((f"{k}_part{i}", t[i*CHUNK_CHAR_LIMIT:(i+1)*CHUNK_CHAR_LIMIT]))
        else:
            out.append((k, t))
    return out

def prepare_prompts(folder: str):
    prompts: List[tuple] = []
    strings_chunks: List[tuple] = []

    # First collect all non-strings files
    for fname in TARGET_FILES:
        path = os.path.join(folder, fname)
        if not os.path.exists(path):
            continue

        # Defer strings processing until after other files
        if os.path.basename(fname) == "strings.txt":
            # store the chunks to append later
            strings_chunks = prepare_strings_chunks(folder)
            continue

        if fname.endswith(".json"):
            txt = load_json_text(path)
            prompts.append((fname, txt))
        else:
            txt = load_text(path)  # ASCII-clean
            if len(txt) > CHUNK_CHAR_LIMIT:
                prompts.append((fname + "::head", txt[:CHUNK_CHAR_LIMIT]))
                prompts.append((fname + "::tail", txt[-CHUNK_CHAR_LIMIT:]))
            else:
                prompts.append((fname, txt))

    # Append strings chunks at the end (if any)
    for k, t in strings_chunks:
        prompts.append((f"strings::{k}", t))

    return prompts

def build_prompt(name: str, body: str, truncate: bool = True) -> str:
    header = (
        "You are a senior malware analyst. You will receive a focused excerpt from a forensics dataset "
        "captured from a suspicious high-CPU process. Perform a deep, evidence-driven analysis of THIS EXCERPT ONLY, "
        "but treat it as part of a cryptojacking/fileless-malware triage. Be concise and structured.\n\n"
        "MANDATORY ANALYSIS CHECKLIST (cover each explicitly):\n"
        "1) High-signal artifacts: suspicious API names (allocation, protection, injection, dynamic resolution), crypto primitives, GPU/compute usage, stratum/miner endpoints, config blobs.\n"
        "2) Behavior pattern inference: does this excerpt suggest hashing loops, reflective loading, LOLBins, or benign browser/security operations?\n"
        "3) Indicators of Compromise (IoCs): extract URLs/domains/IPs, pool names, wallet patterns, user-agents, base64 indicators (ASCII-only), notable DLLs/APIs.\n"
        "4) MITRE ATT&CK mapping: include technique IDs if suggested (e.g., T1496 Resource Hijacking, T1055 Process Injection, T1027 Obfuscated/Compressed Files, T1059.* Command and Scripting Interpreter, T1105 Exfil over C2, etc.).\n"
        "5) Evasion and stealth signals: API hashing, manual mapping, high-entropy segments (if evident), unusual timestamps, unsigned modules (only if excerpt shows it).\n"
        "6) Alternative benign explanations (e.g., browser TLS/DPAPI crypto, graphics pipelines, telemetry), if applicable.\n"
        "7) Evidence gaps: what concrete proof is missing to make a call (e.g., stratum frames, pool endpoints, CPU stacks, OpenCL/CUDA calls, persistence keys)?\n"
        "8) Decision: verdict and confidence (do not hedge). Provide a numeric risk_score 0–100.\n"
        "9) Prioritized next steps (exact commands/artifacts to collect) to close gaps.\n\n"
        "OUTPUT FORMAT: Return STRICT JSON with these keys ONLY:\n"
        "{\n"
        '  "summary": "1–3 bullet lines (concise)",\n'
        '  "findings": ["short evidence bullets drawn from the excerpt"],\n'
        '  "iocs": ["URLs/domains/IPs/paths/APIs/keywords/wallet-like strings"],\n'
        '  "mitre_mapping": ["T1496","T1055",...],\n'
        '  "behaviors": ["e.g., dynamic API resolution","reflective loading","hashing loop suspected","benign TLS crypto"],\n'
        '  "evasion_signals": ["e.g., API hashing","manual mapping","obfuscation hints"],\n'
        '  "verdict": "cryptojacking|fileless_suspect|benign|inconclusive",\n'
        '  "confidence": "low|medium|high",\n'
        '  "risk_score": 0-100,\n'
        '  "missing_evidence": ["specific proofs to collect to confirm/deny"],\n'
        '  "next_steps": ["3-6 prioritized, concrete steps with tooling/commands"],\n'
        '  "evidence_refs": ["short quoted snippets from THIS excerpt that justify key points"]\n'
        "}\n\n"
        "CONSTRAINTS:\n"
        "- Analyze ONLY the excerpt below. Do not invent data. If data is ambiguous, state it under missing_evidence.\n"
        "- Do NOT reveal chain-of-thought. Provide concise, evidence-linked bullets and concrete actions.\n"
        "- All content is ASCII; non-ASCII is already removed.\n"
    )
    body = clean_ascii(body)
    if truncate and len(body) > CHUNK_CHAR_LIMIT:
        body = body[:CHUNK_CHAR_LIMIT] + "\n<<TRUNCATED>>"
    return f"{header}\n---BEGIN EXCERPT ({name})---\n{body}\n---END EXCERPT---"

# ---------------- API CALLS ----------------

def call_gpt_api(prompt: str, model: str, api_key: Optional[str]):
    if requests is None:
        raise RuntimeError("Install requests first")
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        raise ValueError("OpenAI API key missing")
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    messages = [
        {"role": "system", "content": "You are a precise malware analyst. Respond with strict JSON."},
        {"role": "user", "content": prompt}
    ]
    payload = {"model": model, "messages": messages, "max_tokens": 1200, "temperature": 0.0}
    r = requests.post(url, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()

def call_perplexity_api(prompt: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Perplexity example call (chat/completions). Adjust to your exact API.
    """
    if requests is None:
        raise RuntimeError("Install 'requests' first (pip install requests)")
    key = api_key or os.getenv("PERPLEXITY_API_KEY")
    if not key:
        return {"mock": True, "message": "PERPLEXITY_API_KEY missing; returning mock response."}
    url = "https://api.perplexity.ai/chat/completions"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    payload = {
        "model": "sonar-pro",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "temperature": 0.7,
    }
    r = requests.post(url, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    # normalize a "text" field for aggregator
    if "choices" in data and data["choices"]:
        text = data["choices"][0]["message"].get("content", "")
        return {"success": True, "text": text, "raw": data}
    return {"success": False, "error": "No choices returned", "raw": data}


def send_final_analysis(out_dir: str, api: str, gpt_model: str, gpt_key: Optional[str], perplexity_key: Optional[str], dry_run: bool, verbose: bool, sleep: float = 1.0):
    """Read final_analysis.txt from out_dir, send to selected API, save raw JSON and write conclusion.txt, and print the aggregated response.

    Uses the same prompt template (build_prompt) so we keep the original instructions.
    """
    final_txt_path = os.path.join(out_dir, "final_analysis.txt")
    if not os.path.exists(final_txt_path):
        print(f"[final] final_analysis.txt not found at {final_txt_path}")
        return

    # Verbose diagnostics: size, lines, preview
    try:
        stat = os.stat(final_txt_path)
        size = stat.st_size
    except Exception:
        size = None
    raw_lines = open(final_txt_path, 'r', errors='replace').read().splitlines()
    body = clean_ascii("\n".join(raw_lines))
    if verbose:
        print(f"final_analysis.txt -> {final_txt_path}")
        if size is not None:
            print(f"  size: {size} bytes")
        print(f"  lines: {len(raw_lines)}")
        if len(raw_lines) > 0:
            head_preview = "\n".join(raw_lines[:5])
            tail_preview = "\n".join(raw_lines[-5:])
            print("  preview (first 5 lines):\n" + head_preview)
            print("  preview (last 5 lines):\n" + tail_preview)
    name = "final_analysis"
    # For the final aggregated pass, do not truncate the body — send it in one go
    prompt = build_prompt(name, body, truncate=False)

    prompt_path = os.path.join(out_dir, f"final__{name}.prompt.txt")
    with open(prompt_path, "w", encoding="utf-8") as f:
        f.write(prompt)

    if verbose:
        try:
            print(f"Wrote final prompt -> {prompt_path} (chars: {len(prompt)})")
        except Exception:
            pass

    if dry_run:
        print(f"[DRY] Would send final analysis prompt: {prompt_path}")
        return

    # Call the selected API
    try:
        if api == "gpt":
            resp = call_gpt_api(prompt, model=gpt_model, api_key=gpt_key)
            agg_text = ""
            try:
                if "choices" in resp and resp["choices"]:
                    agg_text = resp["choices"][0]["message"].get("content", "")
            except Exception:
                agg_text = ""
        else:
            resp = call_perplexity_api(prompt, api_key=perplexity_key)
            agg_text = resp.get("text") or ""
    except Exception as e:
        resp = {"error": str(e)}
        agg_text = ""

    # Save raw JSON response and concise conclusion
    out_json = os.path.join(out_dir, f"final__{name}.response.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(resp, f, indent=2, ensure_ascii=False)

    conclusion_path = os.path.join(out_dir, "conclusion.txt")
    with open(conclusion_path, "w", encoding="utf-8") as f:
        if agg_text:
            f.write(agg_text.strip() + "\n")
        else:
            try:
                f.write(json.dumps(resp, ensure_ascii=False) + "\n")
            except Exception:
                f.write(str(resp) + "\n")

    # Print to terminal
    print("\n=== FINAL LLM CONCLUSION ===")
    if agg_text:
        print(agg_text.strip())
    else:
        try:
            print(json.dumps(resp, ensure_ascii=False))
        except Exception:
            print(str(resp))
    print("============================\n")

    if verbose:
        print(f"Saved final response JSON -> {out_json}")
        print(f"Saved conclusion text -> {conclusion_path}")
    time.sleep(sleep)

# ---------------- MAIN ----------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Send selected forensic outputs to LLM (ASCII only, noise-filtered).")
    parser.add_argument("--folder", "-f", required=True, help="Folder containing forensic files")
    parser.add_argument("--api", choices=["gpt","perplexity"], default="perplexity")
    parser.add_argument("--gpt-model", default="gpt-4o-mini")
    parser.add_argument("--gpt-key", default=None)
    parser.add_argument("--perplexity-key", default=None)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--final", action="store_true", help="Send final_analysis.txt to the LLM and save a conclusion.txt")
    parser.add_argument("--final-only", action="store_true", help="Skip chunking and send an existing final_analysis.txt from out-dir to the LLM")
    parser.add_argument("--sleep", type=float, default=1.0)
    args = parser.parse_args(argv)

    folder = os.path.abspath(args.folder)
    out_dir = args.out_dir or os.path.join(folder, "llm_outputs")
    os.makedirs(out_dir, exist_ok=True)

    # final aggregation file (append mode) - only create/truncate when not running final-only
    final_txt_path = os.path.join(out_dir, "final_analysis.txt")
    if not args.final_only:
        with open(final_txt_path, "w", encoding="utf-8") as f:
            f.write("=== LLM Triaged Analysis (Aggregated) ===\n\n")

    # If the user wants to only run the final step, do it now using the existing final_analysis.txt
    if args.final_only:
        if args.verbose:
            print("Running final-only: sending existing final_analysis.txt to LLM")
        send_final_analysis(
            out_dir=out_dir,
            api=args.api,
            gpt_model=args.gpt_model,
            gpt_key=args.gpt_key,
            perplexity_key=args.perplexity_key,
            dry_run=args.dry_run,
            verbose=args.verbose,
            sleep=args.sleep,
        )
        print("Final-only run complete. Exiting.")
        return

    chunks = prepare_prompts(folder)
    if args.verbose:
        print(f"Prepared {len(chunks)} ASCII-clean, noise-filtered chunks")

    for i, (name, text) in enumerate(chunks):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]
        prompt = build_prompt(name, text)
        prompt_path = os.path.join(out_dir, f"{i:03d}__{safe}.prompt.txt")
        with open(prompt_path, "w", encoding="utf-8") as f:
            f.write(prompt)

        if args.dry_run:
            if args.verbose: print(f"[DRY] {prompt_path}")
            continue

        # Call the selected API
        try:
            if args.api == "gpt":
                resp = call_gpt_api(prompt, model=args.gpt_model, api_key=args.gpt_key)
                # Try to extract assistant text for aggregator
                agg_text = ""
                try:
                    if "choices" in resp and resp["choices"]:
                        agg_text = resp["choices"][0]["message"].get("content", "")
                except Exception:
                    agg_text = ""
            else:
                resp = call_perplexity_api(prompt, api_key=args.perplexity_key)
                agg_text = resp.get("text") or ""
        except Exception as e:
            resp = {"error": str(e)}
            agg_text = ""

        # Save raw JSON response
        out_json = os.path.join(out_dir, f"{i:03d}__{safe}.response.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(resp, f, indent=2, ensure_ascii=False)
        if args.verbose:
            print(f"[{i+1}/{len(chunks)}] saved -> {out_json}")

        # Append to final_analysis.txt
        with open(final_txt_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- Chunk {i+1}/{len(chunks)}: {name} ---\n")
            if agg_text:
                f.write(agg_text.strip() + "\n")
            else:
                # fallback: write compact JSON
                try:
                    f.write(json.dumps(resp, ensure_ascii=False) + "\n")
                except Exception:
                    f.write(str(resp) + "\n")

        time.sleep(args.sleep)

    print("Done.")
    print("Prompts/responses in:", out_dir)
    print("Aggregated text report:", final_txt_path)

    # If requested, send the aggregated final_analysis.txt to the LLM for a single-conclusion pass
    if args.final:
        if args.verbose:
            print("Sending final aggregated analysis to LLM (--final)")
        send_final_analysis(
            out_dir=out_dir,
            api=args.api,
            gpt_model=args.gpt_model,
            gpt_key=args.gpt_key,
            perplexity_key=args.perplexity_key,
            dry_run=args.dry_run,
            verbose=args.verbose,
            sleep=args.sleep,
        )

if __name__ == "__main__":
    main()
