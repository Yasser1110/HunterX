"""Environment / dependency health checks for ``hunterx doctor``.

Checks are non-destructive and never assume a security tool is present:
missing optional tools are warnings, not failures. The pipeline must run
with whatever subset is installed.
"""

from __future__ import annotations

import importlib
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.table import Table

from . import __version__
from .config import Config
from .config import ConfigError
from .database import Database, DatabaseError
from .scope import Scope, ScopeError

OK = "ok"
WARN = "warn"
MISSING = "missing"
FAIL = "fail"

STATUS_STYLE: dict[str, str] = {
    OK: "green", WARN: "yellow", MISSING: "yellow", FAIL: "red",
}
STATUS_GLYPH: dict[str, str] = {
    OK: "[green][✓][/]", WARN: "[yellow][!][/]", MISSING: "[yellow][!][/]", FAIL: "[red][✗][/]",
}

CORE_TOOLS = ["curl", "git", "openssl", "dig"]
PYTHON_PACKAGES = ["yaml", "rich"]


@dataclass
class Check:
    name: str
    category: str
    status: str = OK
    detail: str = ""
    required: bool = False

    @property
    def passed(self) -> bool:
        return self.status == OK


@dataclass
class DoctorReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, check: Check) -> None:
        self.checks.append(check)

    @property
    def summary(self) -> tuple[int, int, int]:
        ok = sum(1 for c in self.checks if c.status == OK)
        warn = sum(1 for c in self.checks if c.status in (WARN, MISSING))
        fail = sum(1 for c in self.checks if c.status == FAIL)
        return ok, warn, fail

    def table(self) -> Table:
        table = Table(title="HunterX Doctor", show_header=True, header_style="bold")
        table.add_column("", width=3)
        table.add_column("Check", style="cyan")
        table.add_column("Category", style="dim")
        table.add_column("Status")
        table.add_column("Detail")
        for c in self.checks:
            table.add_row(
                STATUS_GLYPH[c.status],
                c.name,
                c.category,
                f"[{STATUS_STYLE[c.status]}]{c.status}[/]",
                c.detail,
            )
        return table


def _which(name: str) -> str | None:
    return shutil.which(name)


def run_doctor(config: Config | None = None, db_path: str | Path | None = None,
               config_file: str | Path | None = None) -> DoctorReport:
    report = DoctorReport()

    # Python runtime -------------------------------------------------
    version = sys.version_info
    py_ok = version >= (3, 12)
    report.add(Check(
        "Python", "runtime", OK if py_ok else FAIL,
        f"{sys.version.split()[0]} (need >=3.12)", required=True,
    ))
    report.add(Check("HunterX package", "runtime", OK, f"v{__version__}"))

    # Python dependencies --------------------------------------------
    for pkg in PYTHON_PACKAGES:
        try:
            importlib.import_module(pkg)
            report.add(Check(pkg, "python", OK, "importable"))
        except ImportError:
            report.add(Check(pkg, "python", MISSING, "not installed", required=True))

    # Core OS tools ---------------------------------------------------
    for tool in CORE_TOOLS:
        path = _which(tool)
        report.add(Check(tool, "core tool", OK if path else MISSING,
                         path or "install it (e.g. dnsutils)", required=tool in ("curl", "git")))

    # Security tools (optional) --------------------------------------
    tools_cfg = config.tools_cfg() if config else {}
    security_tools = tools_cfg.get("optional", [])
    for tool in security_tools:
        path = _which(tool)
        report.add(Check(tool, "security tool", OK if path else MISSING,
                         path or f"optional; pipeline will skip it"))

    # Configuration & scope -------------------------------------------
    if config:
        report.add(Check("config.yaml", "config", OK, "loaded"))
        try:
            scope_cfg = config.scope_cfg()
            scope = Scope.from_config(scope_cfg, config.target)
            count = len(scope.allowed_patterns)
            report.add(Check("scope engine", "scope", OK,
                             f"{count} include pattern(s) compiled"))
        except ScopeError as exc:
            report.add(Check("scope engine", "scope", FAIL, str(exc), required=True))
    else:
        try:
            Config.load(config_file=config_file)
            report.add(Check("config.yaml", "config", OK, "loads + validates"))
        except ConfigError as exc:
            report.add(Check("config.yaml", "config", FAIL, str(exc), required=True))

    # Database ---------------------------------------------------------
    try:
        path = Path(db_path) if db_path else (config.paths.data / "hunterx.db" if config else Path("data/hunterx.db"))
        db = Database(path)
        report.add(Check("database", "storage", OK,
                         f"sqlite schema v{db.schema_version} at {path}"))
        db.close()
    except DatabaseError as exc:
        report.add(Check("database", "storage", FAIL, str(exc), required=True))

    # Directories ------------------------------------------------------
    if config:
        try:
            config.paths.ensure()
            report.add(Check("data/reports/log dirs", "storage", OK, "writable"))
        except OSError as exc:
            report.add(Check("data/reports/log dirs", "storage", FAIL, str(exc), required=True))

    # Wordlists ---------------------------------------------------------
    if config:
        from .wordlists import resolve as resolve_wordlist

        base_cfg = config.wordlists_cfg()
        base = base_cfg.get("base_dir", "wordlists")
        tiers = base_cfg.get("tiers", {})
        missing_tiers = [name for name, ref in tiers.items()
                         if ref and resolve_wordlist(config.paths.wordlists, ref) is None]
        if missing_tiers:
            report.add(Check("wordlists", "wordlists", WARN,
                             f"missing: {', '.join(missing_tiers)} (base_dir: {base})"))
        else:
            report.add(Check("wordlists", "wordlists", OK,
                             f"{len(tiers)} tier(s) resolved under {base}"))

    return report


def report_json(report: DoctorReport) -> dict[str, Any]:
    return {
        "checks": [{"name": c.name, "category": c.category, "status": c.status,
                     "detail": c.detail, "required": c.required} for c in report.checks],
        "summary": dict(zip(("ok", "warnings", "failures"), report.summary)),
    }