import os
import sys
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime

import streamlit as st

# ----------------------------
# Utility helpers
# ----------------------------

def run_cmd(cmd, cwd=None):
    """Run a command and stream its output line-by-line to Streamlit."""
    st.code(" ".join([str(c) for c in cmd]), language="bash")
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    log = st.empty()
    lines = []
    for line in process.stdout:
        lines.append(line)
        log.text("".join(lines[-200:]))  # keep last 200 lines visible
    ret = process.wait()
    if ret != 0:
        st.error(f"Command exited with non-zero status: {ret}")
    else:
        st.success("Done.")
    return ret


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_uploaded_file(uploaded_file, dst_dir: Path) -> Path:
    ensure_dir(dst_dir)
    dst = dst_dir / uploaded_file.name
    with open(dst, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return dst


def pretty_json_view(path: Path, expand=False):
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            st.json(data, expanded=expand)
        except Exception:
            st.warning(f"{path} isn't valid JSON; showing text preview.")
            st.text(path.read_text(errors="ignore")[:10000])
    else:
        st.info(f"{path} not found yet.")


def list_files(folder: Path, patterns=("*.txt", "*.json")):
    files = []
    if folder.exists():
        for pat in patterns:
            files.extend(folder.rglob(pat))
    return sorted(files)

# ----------------------------
# Sidebar configuration
# ----------------------------
st.set_page_config(page_title="LLM Memory-Dump Triage Orchestrator", layout="wide")

st.sidebar.title("⚙️ Configuration")
python_exe = st.sidebar.text_input("Python executable", value=sys.executable)

base_out = Path(st.sidebar.text_input(
    "Base output folder",
    value=str(Path.home() / "Experiments/VMFProjectCodebase/forensics_out")
))
ensure_dir(base_out)

# NOTE: API keys and model selection moved to the separate Config page.
# Try to pre-fill from persisted config (keyring or file), then env vars as fallback.
try:
    from config_store import get_nonsecret, get_secret
    persisted_model = get_nonsecret('llm_model', os.environ.get('LLM_MODEL', 'Perplexity'))
    persisted_pplx = get_secret('perplexity_key') or os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
    persisted_openai = get_secret('openai_key') or os.environ.get('OPENAI_API_KEY')
except Exception:
    persisted_model = os.environ.get('LLM_MODEL', 'Perplexity')
    persisted_pplx = os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
    persisted_openai = os.environ.get('OPENAI_API_KEY')

if 'llm_model' not in st.session_state:
    st.session_state['llm_model'] = persisted_model
if 'perplexity_key' not in st.session_state:
    st.session_state['perplexity_key'] = persisted_pplx or ""
if 'openai_key' not in st.session_state:
    st.session_state['openai_key'] = persisted_openai or ""

scripts_root = Path(st.sidebar.text_input(
    "Scripts folder (where *.py live)",
    value=str(Path.cwd())
))

# Optional: default subfolders
default_stage_out = ensure_dir(base_out / "malware_testing")
final_out = ensure_dir(base_out / "malware_finalanalysis")

st.sidebar.markdown("---")
mode = st.sidebar.radio("Dump Source", ["Upload .dmp", "Use local path"], index=0)

# ----------------------------
# Header
# ----------------------------
st.title("🧠 LLM-Driven Memory Dump Triage — Streamlit Orchestrator")
st.caption("Run your full dump → forensics → carving → imports → LLM (shards → final) pipeline without touching the CLI.")

# ----------------------------
# Step 0: Select or upload dump + optional YARA
# ----------------------------
st.header("Step 0 — Select Memory Dump & Optional YARA Rules")

with st.container(border=True):
    dump_path = None
    yara_path = None

    if mode == "Upload .dmp":
        up = st.file_uploader("Drop a Windows process memory dump (.dmp)", type=["dmp"], accept_multiple_files=False)
        if up is not None:
            dump_path = save_uploaded_file(up, ensure_dir(base_out / "uploads"))
            st.success(f"Saved dump to {dump_path}")
    else:
        dump_path_str = st.text_input("Local dump path (.dmp)", value="")
        if dump_path_str:
            dump_path = Path(dump_path_str)
            if dump_path.exists():
                st.success(f"Found: {dump_path}")
            else:
                st.error("Path not found.")

    up_yara = st.file_uploader("(Optional) YARA rules file", type=["yar", "yara"], accept_multiple_files=False)
    if up_yara is not None:
        yara_path = save_uploaded_file(up_yara, ensure_dir(base_out / "yara"))
        st.info(f"Using YARA rules: {yara_path}")

    stage_out = Path(st.text_input("Stage output folder (forensics_out)", value=str(default_stage_out)))
    ensure_dir(stage_out)

# ----------------------------
# Tabs for each stage
# ----------------------------

tabs = st.tabs([
    "1) Forensics (cdb, strings, hashes)",
    "2) Carve PEs",
    "3) Extract Imports",
    "4) LLM Sharded",
    "5) LLM Final",
    "6) Review Outputs",
])

# Unpack tab context managers
T1, T2, T3, T4, T5, T6 = tabs

# 1) Forensics
with T1:
    st.subheader("Run mem_dump_analysis.py")
    col1, col2 = st.columns(2)
    with col1:
        cdb_txt = stage_out / "cdb.txt"
        strings_txt = stage_out / "strings.txt"
        analyzer_json = stage_out / "analyzer_report.json"
        hashes_json = stage_out / "dump_hashes.json"
    with col2:
        st.write("Expected outputs:")
        st.write("- cdb.txt\n- strings.txt\n- analyzer_report.json\n- dump_hashes.json\n- yara_*.txt (if rules provided)")

    run_forensics = st.button("▶️ Run Forensics", use_container_width=True, type="primary")
    if run_forensics:
        if not dump_path or not Path(dump_path).exists():
            st.error("Please provide a valid dump file.")
        else:
            cmd = [python_exe, str(scripts_root / "mem_dump_analysis.py"),
                   "-i", str(dump_path),
                   "-o", str(stage_out)]
            if yara_path:
                cmd += ["--yara-rules", str(yara_path)]
            run_cmd(cmd)

    cols_preview = st.columns(2)
    with cols_preview[0]:
        st.markdown("**cdb.txt** (head)")
        if cdb_txt.exists():
            st.text(Path(cdb_txt).read_text(errors="ignore")[:10000])
        else:
            st.info("Not generated yet.")
    with cols_preview[1]:
        st.markdown("**strings.txt** (head)")
        if strings_txt.exists():
            st.text(Path(strings_txt).read_text(errors="ignore")[:10000])
        else:
            st.info("Not generated yet.")

    st.markdown("**analyzer_report.json**")
    pretty_json_view(analyzer_json)
    st.markdown("**dump_hashes.json**")
    pretty_json_view(hashes_json)

# 2) Carve PEs
with T2:
    st.subheader("Run carve_pe_from_procdump.py")
    carved_dir = stage_out / "carved_pe"
    ensure_dir(carved_dir)

    if st.button("🧩 Carve PEs", use_container_width=True):
        if not dump_path or not Path(dump_path).exists():
            st.error("Please provide a valid dump file.")
        else:
            cmd = [python_exe, str(scripts_root / "carve_pe_from_procdump.py"),
                   str(dump_path), str(carved_dir)]
            run_cmd(cmd)

    st.markdown("**Carved files**")
    files = list_files(carved_dir, patterns=("*.bin", "*.exe", "*.dll"))
    if files:
        for f in files[:200]:
            st.write(f"{f.name} — {f.stat().st_size} bytes")
    else:
        st.info("No carved files found yet.")

# 3) Extract Imports
with T3:
    st.subheader("Run extract_imports_from_bins.py")
    pe_results_dir = ensure_dir(stage_out / "pe_results")
    imports_json = pe_results_dir / "imports.json"

    if st.button("📦 Extract Imports", use_container_width=True):
        cmd = [python_exe, str(scripts_root / "extract_imports_from_bins.py"),
               "--input", str(carved_dir),
               "--output", str(imports_json)]
        run_cmd(cmd)

    st.markdown("**pe_results/imports.json**")
    pretty_json_view(imports_json)

# 4) LLM Sharded
with T4:
    st.subheader("Run llm_call.py (sharded)")
    out_dir = final_out
    out_dir = Path(st.text_input("Final analysis output folder", value=str(out_dir)))
    ensure_dir(out_dir)

    extra_args = st.text_input("Extra llm_call args (optional)", value="--verbose")

    if st.button("🧩 Build shards & run per-shard LLM", type="primary", use_container_width=True):
        provider = st.session_state.get('llm_model', 'Perplexity')
        if provider == 'Perplexity':
            key = st.session_state.get('perplexity_key', '')
            if not key:
                st.error("Perplexity key is required for the selected model.")
                st.stop()
            key_flag = ["--perplexity-key", key]
        elif provider == 'OpenAI':
            key = st.session_state.get('openai_key', '')
            if not key:
                st.error("OpenAI key is required for the selected model.")
                st.stop()
            key_flag = ["--openai-key", key]
        else:
            key_flag = []

        cmd = [python_exe, str(scripts_root / "llm_call.py"),
               "--folder", str(stage_out),
               "--out-dir", str(out_dir)]
        if key_flag:
            cmd += key_flag
            if extra_args:
                cmd += extra_args.split()
            run_cmd(cmd)

    st.markdown("**Sharded outputs (head)**")
    shard_txt = out_dir / "shard_responses.txt"
    if shard_txt.exists():
        st.text(shard_txt.read_text(errors="ignore")[:15000])
    else:
        st.info("No shard_responses.txt yet.")

# 5) LLM Final
with T5:
    st.subheader("Run llm_call.py (final aggregation)")
    extra_args_final = st.text_input("Extra llm_call final args (optional)", value="--verbose --final")

    if st.button("✅ Run Final Verdict", type="primary", use_container_width=True):
        provider = st.session_state.get('llm_model', 'Perplexity')
        if provider == 'Perplexity':
            key = st.session_state.get('perplexity_key', '')
            if not key:
                st.error("Perplexity key is required for the selected model.")
                st.stop()
            key_flag = ["--perplexity-key", key]
        elif provider == 'OpenAI':
            key = st.session_state.get('openai_key', '')
            if not key:
                st.error("OpenAI key is required for the selected model.")
                st.stop()
            key_flag = ["--openai-key", key]
        else:
            key_flag = []

        cmd = [python_exe, str(scripts_root / "llm_call.py"),
               "--folder", str(stage_out),
               "--out-dir", str(out_dir)]
        if key_flag:
            cmd += key_flag
        if extra_args_final:
            cmd += extra_args_final.split()
        run_cmd(cmd)

    # Try common final filenames
    candidates = [
        out_dir / "final_verdict.json",
        out_dir / "conclusion.json",
        out_dir / "final" / "final_verdict.json",
        out_dir / "final" / "conclusion.json",
    ]

    st.markdown("**Final verdict (auto-detect)**")
    shown = False
    for c in candidates:
        if c.exists():
            st.success(f"Found: {c}")
            pretty_json_view(c, expand=True)
            shown = True
            break
    if not shown:
        st.info("Final verdict JSON not found yet. Check the out_dir contents below.")

# 6) Review outputs
with T6:
    st.subheader("Browse Output Folders")
    st.write("**Forensics stage:**", stage_out)
    st.write("**Final analysis:**", out_dir)

    colA, colB = st.columns(2)
    with colA:
        st.markdown("### Forensics files")
        for f in list_files(stage_out):
            st.write(f"• {f.relative_to(stage_out)}")
    with colB:
        st.markdown("### Final analysis files")
        for f in list_files(out_dir):
            st.write(f"• {f.relative_to(out_dir)}")

# # Config moved to a separate Streamlit page under pages/Config.py

# st.sidebar.markdown("---")
# st.sidebar.caption("Tip: On Windows, run Streamlit via the same Python env that has your tooling: `python -m streamlit run app.py`")
