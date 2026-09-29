"""Global emergency stop.

Workers poll :func:`check` between requests; ``hunterx stop`` sets a
marker file; a running/future scan removes it on startup. This gives a
cooperative, cross-process kill switch without terminating processes
mid-request.
"""

from __future__ import annotations

from pathlib import Path


class StopRequested(Exception):
    """Raised inside workers when a graceful stop has been requested."""


def marker_path(data_dir: str | Path) -> Path:
    return Path(data_dir) / ".stop"

# Keep the current marker path for cross-module polling.
_current: Path | None = None


def arm(data_dir: str | Path) -> None:
    """Called by ``scan`` at startup: remove any stale stop marker."""
    global _current
    _current = marker_path(data_dir)
    _current.unlink(missing_ok=True)


def armed(data_dir: str | Path) -> bool:
    global _current
    _current = _current or marker_path(data_dir)
    return _current


def stop(data_dir: str | Path) -> Path:
    path = marker_path(data_dir)
    path.touch()
    return path


def check_stop() -> None:
    """Raise :class:`StopRequested` if a stop was requested since arming."""
    if _current is not None and _current.exists():
        raise StopRequested("graceful stop requested via 'hunterx stop'")