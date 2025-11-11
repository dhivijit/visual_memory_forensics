import os
import sys
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime

import streamlit as st
import logger

# ----------------------------
# Utility helpers
# ----------------------------

def run_cmd(cmd, cwd=None):
    """Run a command and stream its output line-by-line to Streamlit."""
    cmd_str = " ".join([str(c) for c in cmd])
    st.markdown(f"**Running:** `{cmd_str}`")
    logger.log_command(cmd)
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
    # capture final output snippet for logging (don't re-run entire capture)
    final_output = "".join(lines[-200:])
    logger.log_output(cmd, ret, final_output)
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
st.set_page_config(page_title="VISUAL MEMORY FORENSICS: AN LLM-DRIVEN PROCESS-CENTRIC FRAMEWORK FOR DETECTING FILELESS CRYPTOJACKING MALWARE", layout="wide")

# NOTE: API keys and model selection moved to the separate Config page.
# Try to pre-fill from persisted config (file), then env vars as fallback.
try:
    import config_store
    get_nonsecret = config_store.get_nonsecret
    get_secret = config_store.get_secret
    persisted_model = get_nonsecret('llm_model') or os.environ.get('LLM_MODEL', 'Perplexity')
    persisted_pplx = get_secret('perplexity_key') or os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
    persisted_openai = get_secret('openai_key') or os.environ.get('OPENAI_API_KEY')
    persisted_anthropic = get_secret('anthropic_key') or os.environ.get('ANTHROPIC_API_KEY')
    persisted_gemini = get_secret('gemini_key') or os.environ.get('GEMINI_API_KEY')
    persisted_base_out = get_nonsecret('base_out')
    persisted_stage_out = get_nonsecret('stage_out')
    persisted_final_out = get_nonsecret('final_out')
except Exception:
    # If config_store import fails for any reason, try to read the JSON config file directly
    cfg_path = Path.home() / ".vmf_config.json"
    try:
        if cfg_path.exists():
            with open(cfg_path, 'r', encoding='utf-8') as fh:
                cfg = json.load(fh)
        else:
            cfg = {}
        persisted_model = cfg.get('llm_model', os.environ.get('LLM_MODEL', 'Perplexity'))
        secrets = cfg.get('_secrets', {})
        persisted_pplx = secrets.get('perplexity_key') or os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
        persisted_openai = secrets.get('openai_key') or os.environ.get('OPENAI_API_KEY')
        persisted_anthropic = secrets.get('anthropic_key') or os.environ.get('ANTHROPIC_API_KEY')
        persisted_gemini = secrets.get('gemini_key') or os.environ.get('GEMINI_API_KEY')
        persisted_base_out = cfg.get('base_out')
        persisted_stage_out = cfg.get('stage_out')
        persisted_final_out = cfg.get('final_out')
    except Exception:
        persisted_model = os.environ.get('LLM_MODEL', 'Perplexity')
        persisted_pplx = os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
        persisted_openai = os.environ.get('OPENAI_API_KEY')
        persisted_anthropic = os.environ.get('ANTHROPIC_API_KEY')
        persisted_base_out = None
        persisted_stage_out = None
        persisted_final_out = None
        persisted_gemini = os.environ.get('GEMINI_API_KEY')

# Helper to persist non-secret values (use config_store when available, otherwise write JSON directly)
def _persist_nonsecret(key: str, value: str):
    try:
        import config_store as _cs
        _cs.set_nonsecret(key, value)
        return
    except Exception:
        pass
    cfg_path = Path.home() / ".vmf_config.json"
    try:
        if cfg_path.exists():
            with open(cfg_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        else:
            data = {}
    except Exception:
        data = {}
    data[key] = value
    tmp = cfg_path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2)
    try:
        os.replace(tmp, cfg_path)
    except Exception:
        try:
            tmp.rename(cfg_path)
        except Exception:
            pass

# Callbacks for Streamlit inputs
def _save_base_out():
    v = st.session_state.get('base_out_input')
    if v:
        _persist_nonsecret('base_out', v)

def _save_stage_out():
    v = st.session_state.get('stage_out_input')
    if v:
        _persist_nonsecret('stage_out', v)

def _save_final_out():
    v = st.session_state.get('final_out_input')
    if v:
        _persist_nonsecret('final_out', v)

st.sidebar.title("⚙️ Configuration")
python_exe = st.sidebar.text_input("Python executable", value=sys.executable)

# Base output folder (persisted)
default_base = persisted_base_out or str(Path.home() / "Experiments/VMFProjectCodebase/forensics_out")
st.sidebar.text_input("Base output folder", value=str(default_base), key="base_out_input", on_change=_save_base_out)
base_out = Path(st.session_state.get('base_out_input', str(default_base)))
ensure_dir(base_out)

if 'llm_model' not in st.session_state:
    st.session_state['llm_model'] = persisted_model
if 'perplexity_key' not in st.session_state:
    st.session_state['perplexity_key'] = persisted_pplx or ""
if 'openai_key' not in st.session_state:
    st.session_state['openai_key'] = persisted_openai or ""
if 'anthropic_key' not in st.session_state:
    st.session_state['anthropic_key'] = persisted_anthropic or ""
if 'gemini_key' not in st.session_state:
    st.session_state['gemini_key'] = persisted_gemini or ""
if 'base_out_input' not in st.session_state:
    st.session_state['base_out_input'] = str(default_base)
if 'stage_out_input' not in st.session_state:
    # prefer persisted_stage_out, then persisted_base_out-based default
    st.session_state['stage_out_input'] = persisted_stage_out or str((Path(st.session_state['base_out_input']) / "malware_testing"))
if 'final_out_input' not in st.session_state:
    st.session_state['final_out_input'] = persisted_final_out or str((Path(st.session_state['base_out_input']) / "malware_finalanalysis"))

scripts_root = Path(st.sidebar.text_input(
    "Scripts folder (where *.py live)",
    value=str(Path.cwd())
))

# Optional: default subfolders (based on current base_out)
default_stage_out = ensure_dir(base_out / "malware_testing")
final_out = ensure_dir(base_out / "malware_finalanalysis")

st.sidebar.markdown("---")
mode = st.sidebar.radio("Dump Source", ["Upload .dmp", "Use local path"], index=0)

# ----------------------------
# Header
# ----------------------------
st.title("🧠 VISUAL MEMORY FORENSICS")
st.caption("AN LLM-DRIVEN PROCESS-CENTRIC FRAMEWORK FOR DETECTING FILELESS CRYPTOJACKING MALWARE.")
st.caption("Run your full dump → forensics → carving → imports → LLM (shards → final) pipeline without touching the CLI.")

# ----------------------------
# Step 0: Select or upload dump + optional YARA
# ----------------------------
st.header("Select Memory Dump & Optional YARA Rules")

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

    # Stage output folder (persisted)
    stage_default = persisted_stage_out or str(default_stage_out)
    st.text_input("Stage output folder (forensics_out)", value=str(stage_default), key='stage_out_input', on_change=_save_stage_out)
    stage_out = Path(st.session_state.get('stage_out_input', str(stage_default)))
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
    st.subheader("Run Initial Memory Dump Analysis")
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
    st.subheader("Run Carve PEs from Dump")
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
    st.subheader("Run Extract Imports from Carved PEs")
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
    st.subheader("Shard and get LLM analysis")
    # Final analysis output folder (persisted)
    final_default = persisted_final_out or str(final_out)
    st.text_input("Final analysis output folder", value=str(final_default), key='final_out_input', on_change=_save_final_out)
    out_dir = Path(st.session_state.get('final_out_input', str(final_default)))
    ensure_dir(out_dir)

    extra_args = st.text_input("Extra llm_call args (optional)", value="--verbose --limit 40")

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
            key_flag = ["--gpt-key", key]
        elif provider == 'Claude':
            key = st.session_state.get('anthropic_key', '')
            if not key:
                st.error("Anthropic/Claude key is required for the selected model.")
                st.stop()
            key_flag = ["--anthropic-key", key]
        elif provider == 'Gemini':
            key = st.session_state.get('gemini_key', '')
            if not key:
                st.error("Gemini key is required for the selected model.")
                st.stop()
            key_flag = ["--gemini-key", key]
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

    # Show individual shard JSONs as collapsible expanders
    st.markdown("**Shard JSONs (individual responses)**")
    # common shard filename patterns: shard_*.json, shard-*.json, shard.*.json
    # include common response naming from llm_call.py (e.g., '000__name.response.json')
    shard_patterns = ["*.response.json", "*__*.response.json", "shard_*.json", "shard-*.json", "shard.*.json", "shard_*.out.json"]
    shard_files = []
    for pat in shard_patterns:
        shard_files.extend(sorted(out_dir.glob(pat)))
    # deduplicate while preserving order
    seen = set()
    shard_files_unique = []
    for p in shard_files:
        if p not in seen:
            shard_files_unique.append(p)
            seen.add(p)

    if shard_files_unique:
        for p in shard_files_unique:
            try:
                # Use an expander so each shard JSON is collapsed by default
                with st.expander(f"{p.name}", expanded=False):
                    pretty_json_view(p, expand=False)
            except Exception:
                st.text(f"Unable to display {p}")
    else:
        st.info("No individual shard JSON files found in out_dir yet.")

# 5) LLM Final
with T5:
    st.subheader("LLM Final Aggregation")
    extra_args_final = st.text_input("Extra llm_call final args (optional)", value="--verbose --final-only")

    # If a conclusion.txt exists from a previous run, show it at the top for quick review
    conclusion_candidates = [
        out_dir / "conclusion.txt",
        out_dir / "final" / "conclusion.txt",
    ]
    for ctxt in conclusion_candidates:
        if ctxt.exists():
            try:
                st.markdown("**Final conclusion (text)**")
                txt = ctxt.read_text(errors="ignore")
                # show the conclusion prominently
                st.text_area("Conclusion (from conclusion.txt)", value=txt, height=300)
            except Exception:
                st.text(f"Found conclusion file but couldn't read: {ctxt}")
            break

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
            key_flag = ["--gpt-key", key]
        elif provider == 'Claude':
            key = st.session_state.get('anthropic_key', '')
            if not key:
                st.error("Anthropic/Claude key is required for the selected model.")
                st.stop()
            key_flag = ["--anthropic-key", key]
        elif provider == 'Gemini':
            key = st.session_state.get('gemini_key', '')
            if not key:
                st.error("Gemini key is required for the selected model.")
                st.stop()
            key_flag = ["--gemini-key", key]
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
