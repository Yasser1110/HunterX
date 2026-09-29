"""External tool discovery and execution.

Every external binary is invoked with a parameter list (never ``shell=True``),
validated arguments, a hard timeout, and output captured to a log file. Runs
are recorded in ``tool_runs`` for observability and reproducibility.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .logger import get_logger

log = get_logger("hunterx.tools")

# Characters that make a tool argument useless for us.
_FORBIDDEN = ("\x00",)


@dataclass
class ToolResult:
    name: str
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int = 0
    output_file: str | None = None
    ok: bool = False
    skipped: bool = False
    reason: str = ""

    @property
    def timed_out(self) -> bool:
        return self.exit_code == -9


class Tools:
    """Resolution + caching of installed binaries."""

    def __init__(self, cfg: Config | None = None) -> None:
        self._names: set[str] = set()
        self._cache: dict[str, str | None] = {}
        if cfg:
            extra = str(cfg.tools_cfg().get("install_dir", "~/hunterx-tools"))
            self.search_dirs = [Path(extra).expanduser()] if extra else []
        else:
            self.search_dirs = []

    def find(self, name: str) -> str | None:
        key = name
        if key in self._cache:
            return self._cache[key]
        found = shutil.which(name)
        if not found:
            for d in self.search_dirs:
                candidate = d / name
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    found = str(candidate)
                    break
        self._cache[key] = found
        return found

    def available(self, name: str) -> bool:
        return self.find(name) is not None

    def available_many(self, names: list[str]) -> dict[str, bool]:
        return {n: self.available(n) for n in names}


def _strings(args: list[Any]) -> list[str]:
    out: list[str] = []
    for a in args:
        s = str(a)
        if any(f in s for f in _FORBIDDEN):
            raise ValueError("argument contains forbidden character")
        out.append(s)
    return out


async def run_tool(
    name: str,
    args: list[Any],
    *,
    tools: Tools,
    timeout: int = 120,
    output_dir: str | Path | None = None,
    run_id: str | None = None,
    target: str | None = None,
    db=None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> ToolResult:
    """Execute *name* with *args* (no shell). Returns a record + log file."""
    path = tools.find(name)
    result = ToolResult(name=name)
    if path is None:
        result.skipped = True
        result.reason = f"{name} not installed"
        log.info("tool skipped: %s (%s)", name, result.reason)
        if db:
            tool_run = db.record_tool_run(run_id or "", name, command=f"{name} {' '.join(map(str,args))}" if args else name, target=target)
            db.finish_tool_run(tool_run, exit_code=0, status="skipped")
        return result

    try:
        cmd = [str(path), *_strings(args)]
    except ValueError as exc:
        result.reason = f"invalid arguments: {exc}"
        return result

    out_dir = Path(output_dir) if output_dir else Path("data/tool-outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = out_dir / f"{name}-{stamp}-{os.getpid()}.log"

    full_env = dict(os.environ)
    if env:
        full_env.update(env)
        full_env.setdefault("PYTHONUNBUFFERED", "1")

    log.info("tool: %s", " ".join(cmd), extra={"run_id": run_id, "target": target})
    if db:
        tool_run = db.record_tool_run(
            run_id or "", name,
            command=" ".join(cmd), target=target,
        )

    started = time.monotonic()
    try:
        out_fh = open(output_file, "w", encoding="utf-8", errors="replace")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=out_fh,
            stderr=subprocess.STDOUT,
            cwd=str(cwd) if cwd else None,
            env=full_env,
        )
        try:
            exit_code = await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                proc.kill()
                await proc.wait()
            exit_code = -9
        finally:
            out_fh.close()
    except (OSError, subprocess.SubprocessError) as exc:
        result.reason = f"failed to start: {exc}"
        result.exit_code = -1
        return result

    result.command = cmd
    result.exit_code = int(exit_code)
    result.duration_ms = int((time.monotonic() - started) * 1000)
    result.output_file = str(output_file)
    result.ok = exit_code == 0
    if exit_code == -9:
        result.reason = f"timed out after {timeout}s"

    if db:
        db.finish_tool_run(
            tool_run,
            exit_code=result.exit_code,
            output_file=result.output_file,
            duration_ms=result.duration_ms,
            status="ok" if result.ok else ("timed_out" if result.timed_out else "failed"),
        )
    return result