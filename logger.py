import os
from datetime import datetime
from pathlib import Path
from typing import List

LOG_DIR = Path.home() / ".vmf_logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "commands.log"


def _now_iso():
    return datetime.utcnow().isoformat() + "Z"


def format_cmd(cmd: List[str]) -> str:
    return " ".join([str(x) for x in cmd])


def log_command(cmd: List[str]):
    line = f"{_now_iso()} CMD: {format_cmd(cmd)}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def log_output(cmd: List[str], exit_code: int, output: str):
    header = f"{_now_iso()} OUT: {format_cmd(cmd)} EXIT={exit_code}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(output)
        f.write("\n---\n")
