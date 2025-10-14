import json
import os
from pathlib import Path
from typing import Optional

_SERVICE_NAME = "llm_memory_forensics"
_CONFIG_FILE = Path.home() / ".vmf_config.json"

try:
    import keyring
    _HAS_KEYRING = True
except Exception:
    _HAS_KEYRING = False


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
    """Get a secret by name. Uses keyring if available, otherwise stored in file under the secrets key (encoded)."""
    if _HAS_KEYRING:
        try:
            return keyring.get_password(_SERVICE_NAME, name)
        except Exception:
            return None
    # fallback to file
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    return secrets.get(name)


def set_secret(name: str, value: str):
    if _HAS_KEYRING:
        try:
            keyring.set_password(_SERVICE_NAME, name, value)
            return
        except Exception:
            pass
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    secrets[name] = value
    data["_secrets"] = secrets
    _write_file_config(data)


def set_secret_force_file(name: str, value: str):
    """Force saving the secret into the fallback file even if keyring is available.
    This is insecure compared to keyring; use only if you want on-disk persistence.
    """
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    secrets[name] = value
    data["_secrets"] = secrets
    _write_file_config(data)


def delete_secret(name: str):
    if _HAS_KEYRING:
        try:
            keyring.delete_password(_SERVICE_NAME, name)
            return
        except Exception:
            pass
    data = _read_file_config()
    secrets = data.get("_secrets", {})
    if name in secrets:
        del secrets[name]
        data["_secrets"] = secrets
        _write_file_config(data)


def list_nonsecrets() -> dict:
    return _read_file_config()
