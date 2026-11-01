"""Basit .env yukleyici (harici bagimlilik yok, python-dotenv'siz)."""

from __future__ import annotations

import os
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


def load_env() -> None:
    """.env dosyasini okur, KEY=VALUE satirlarini os.environ'a yukler.

    Zaten os.environ'da tanimli olan degiskenlerin ustune yazmaz.
    """
    if not _ENV_FILE.exists():
        return
    for line in _ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def get_urlhaus_auth_key() -> str | None:
    load_env()
    return os.environ.get("URLHAUS_AUTH_KEY") or None
