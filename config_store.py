import json
import os
from pathlib import Path
from typing import Optional

# Use a simple JSON file in the user's home directory for storing config and secrets.
# Per user's request, do NOT use keyring or any OS secret stores — plain text file only.
_CONFIG_FILE = Path.home() / ".vmf_config.json"


def _read_file_config() -> dict:
    if not _CONFIG_FILE.exists():
        return {}
    try:
        with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_file_config(data: dict):
    # ensure parent
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # write atomically
    tmp = _CONFIG_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, _CONFIG_FILE)
    try:
        # restrict permissions to user only
        _CONFIG_FILE.chmod(0o600)
    except Exception:
        pass


def get_nonsecret(key: str, default=None):
    data = _read_file_config()
    return data.get(key, default)


def set_nonsecret(key: str, value):
    data = _read_file_config()
    data[key] = value
    _write_file_config(data)


def delete_nonsecret(key: str):
    data = _read_file_config()
    if key in data:
        del data[key]
        _write_file_config(data)


def get_secret(name: str) -> Optional[str]:
    """Get a secret by name from the local JSON config file.

    Returns None if not found.
    """
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    return secrets.get(name)


def set_secret(name: str, value: str):
    """Set a secret by name into the local JSON config file.

    This stores secrets in plain text inside ~/.vmf_config.json as requested.
    """
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    secrets[name] = value
    data["_secrets"] = secrets
    _write_file_config(data)


def set_secret_force_file(name: str, value: str):
    """Alias to set_secret for backwards compatibility."""
    set_secret(name, value)


def delete_secret(name: str):
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    if name in secrets:
        del secrets[name]
        data["_secrets"] = secrets
        _write_file_config(data)


def list_nonsecrets() -> dict:
    return _read_file_config()
