"""Wordlist resolution and loading.

Lets the configured wordlists point at any directory on disk (e.g. a SecLists
checkout) while tiers stay simple names. A tier reference is resolved in order:

1. absolute path (with ``~`` support)                     -> used as-is
2. relative path joined onto ``base_dir``                 -> used as-is
3. bare filename searched beneath ``base_dir`` (best-effort,
   depth-capped, prefers paths containing ``Web-Content``)

Loading strips blank lines and ``#``/``//``/``;`` comments.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("hunterx.wordlists")

MAX_SEARCH_DEPTH = 8

DEFAULT_WORDS = [
    "admin", "api", "backup", "config", "swagger", "login",
    "robots.txt", "sitemap.xml", "health", "status",
]


def resolve(base_dir: Path | None, ref: str | Path | None) -> Path | None:
    if not ref:
        return None
    raw = Path(str(ref)).expanduser()

    if raw.is_absolute() and raw.exists():
        return raw

    if base_dir:
        direct = base_dir.joinpath(str(raw)).resolve()
        if direct.exists():
            return direct

    if base_dir and base_dir.is_dir():
        found = _find_basename(base_dir, raw.name)
        if found:
            return found

    log.debug("wordlist %r not found under %s", ref, base_dir)
    return None


def _find_basename(base_dir: Path, name: str) -> Path | None:
    """Best-effort search for a file called *name* somewhere under *base_dir*."""
    if not name or name in (".", ".."):
        return None
    best: Path | None = None
    for dirpath, dirnames, filenames in os.walk(base_dir):
        rel = os.path.relpath(dirpath, base_dir)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        dirnames[:] = [d for d in dirnames if d not in (".git", ".svn", "__pycache__")]
        if depth > MAX_SEARCH_DEPTH:
            dirnames.clear()
            continue
        if name in filenames:
            full = Path(dirpath) / name
            if "Web-Content" in str(full.relative_to(base_dir)):
                return full
            if best is None:
                best = full
    return best


def load(path: Path | None, *, default: list[str] | None = None) -> list[str]:
    fallback = list(default) if default is not None else list(DEFAULT_WORDS)
    if not path or not path.is_file():
        return fallback
    words: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("wordlist %s unreadable: %s", path, exc)
        return fallback
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        words.append(line)
    return words if words else fallback