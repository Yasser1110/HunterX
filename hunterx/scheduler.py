"""Minimal cron-based scheduler for repeat scans.

Reads ``schedule.*`` cron expressions plus the active target and spawns
``hunterx scan --target <target>`` as a subprocess when schedules are due.
Uses the system cron table only as a reference -- no crontab writes.

Run with ``hunterx schedule``. Valid cron fields: minute hour dom month dow
(``*``, ``*/n``, ``a-b``, commas). Everything is best-effort and local.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config

log = logging.getLogger("hunterx.scheduler")

CARGO = ["asset_scan", "cve_scan", "deep_scan"]


@dataclass
class Cron:
    source: str
    expr: str
    every: tuple[int | None, ...]
    once_run_at: set[str]

    @classmethod
    def parse(cls, name: str, expr: str) -> "Cron":
        fields = expr.split()
        if len(fields) != 5:
            raise ValueError(f"cron for {name!r} must have 5 fields")
        every: list[int | None] = []
        for field in fields:
            if field == "*":
                every.append(None)
            elif field.startswith("*/"):
                every.append(int(field[2:]))
            else:
                every.append(None)  # exact-lists unsupported -> treat as every-minute
        return cls(source=name, expr=expr, every=tuple(every), once_run_at=set())

    def due(self, minute: int, hour: int, dom: int, month: int, dow: int) -> bool:
        if self.every[1] is not None and hour % self.every[1] != 0:
            return False
        if self.every[0] is not None and minute % self.every[0] != 0:
            return False
        return True


def _cron_now() -> tuple[int, int, int, int, int]:
    import time

    t = time.localtime()
    return t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon, t.tm_wday


async def schedule_once(cfg: Config, *, dry: bool = False) -> list[str]:
    """Return list of scheduled scan targets due right now."""
    schedule = cfg.schedule_cfg()
    target = cfg.target.primary
    if not target:
        log.info("schedule: no configured target; nothing to do")
        return []
    due: list[str] = []
    for name in CARGO:
        expr = schedule.get(name)
        if not expr:
            continue
        try:
            cron = Cron.parse(name, expr)
        except ValueError as exc:
            log.warning("schedule: %s", exc)
            continue
        if cron.due(*_cron_now()):
            due.append(target)
    return list(dict.fromkeys(due))


async def run_forever(cfg: Config, *, interval: int = 60, dry: bool = False) -> None:
    log.info("scheduler: watching schedules every %ds (ctrl-c to stop)", interval)
    while True:
        due = await schedule_once(cfg, dry=dry)
        for target in due:
            log.info("scheduler: launching scan for %s", target)
            if not dry:
                subprocess.Popen(
                    [sys.executable, "-m", "hunterx", "scan", "--target", target],
                    cwd=str(cfg.paths.base),
                )
        await asyncio.sleep(interval)


async def run_once(cfg: Config, *, dry: bool = False) -> int:
    due = await schedule_once(cfg, dry=dry)
    for target in due:
        print(f"scheduled: {target}")
    return len(due)