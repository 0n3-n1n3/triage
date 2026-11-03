"""Validated JSON configuration. PHISH_TRIAGE_CONFIG selects an explicit directory.

Return independent objects; never let one action mutate a cached configuration.
The cache key includes the resolved path and file metadata, not just its name.
"""
from __future__ import annotations
import copy
import json
import os
from functools import lru_cache
from pathlib import Path

from core.validation import validate_config

DEFAULT_DIR = Path(__file__).resolve().parent.parent / 'config'
NAMES = frozenset({'scoring', 'brands', 'internal', 'allowlist', 'simulation', 'security'})


def config_dir() -> Path:
    return Path(os.environ.get('PHISH_TRIAGE_CONFIG', DEFAULT_DIR)).expanduser().resolve()


@lru_cache(maxsize=32)
def _read(path: str, mtime_ns: int, size: int) -> dict:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def load(name: str, directory: str | Path | None = None) -> dict:
    if name not in NAMES:
        raise ValueError(f'Unknown configuration name: {name}')
    path = ((Path(directory) if directory is not None else config_dir()) / f'{name}.json').resolve()
    try:
        st = path.stat()
        value = _read(str(path), st.st_mtime_ns, st.st_size)
        return copy.deepcopy(validate_config(name, value))
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f'Invalid configuration {path}: {exc}') from exc


def clear_cache() -> None:
    _read.cache_clear()
