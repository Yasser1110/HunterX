"""HunterX command-line interface.

Commands:
  * ``init``, ``doctor``, ``test``            - setup / diagnostics
  * ``scan``, ``resume``, ``stop``            - full resumable pipeline
  * ``discover``, ``probe``, ``crawl``,
    ``fuzz``, ``nuclei``                     - one-shot single-phase runs
  * ``intel`` (update/diff)                   - CVE/KEV intelligence
  * ``report``, ``dashboard``                 - output artifacts
  * ``schedule``                              - cron-based repeat scans
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Config, ConfigError, normalize_wildcard_target, validate_hostname
from .database import PHASES
from .database import Database, DatabaseError
from .doctor import DoctorReport, run_doctor, report_json
from .logger import get_logger, setup_logging
from .scope import Scope, ScopeError
from .stop import arm as _arm_stop
from .stop import stop as _emit_stop
from .ui import banner, console

log = get_logger("hunterx.cli")

PHASE_LABELS = {
    "scope": "Scope validation (Phase 0)",
    "discovery": "Passive subdomain discovery",
    "dns": "DNS enumeration",
    "http": "HTTP probing",
    "ports": "Port/service discovery",
    "fingerprinting": "Technology fingerprinting",
    "urls": "URL discovery",
    "javascript": "JS analysis",
    "parameters": "Parameter discovery",
    "fuzzing": "Content discovery",
    "scanners": "Nuclei + safe checks",
    "cve": "CVE correlation",
    "dedup": "Deduplication",
    "evidence": "Evidence collection",
    "prioritization": "Risk prioritization",
    "ai": "AI-assisted triage",
    "reporting": "Reporting",
    "notification": "Notification",
}


def _resolve_config(args: argparse.Namespace) -> Config:
    return Config.load(config_file=getattr(args, "config", None))


def _resolve_db(cfg: Config) -> Database:
    return Database(cfg.paths.data / "hunterx.db")


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    cfg = Config.load(config_file=getattr(args, "config", None))
    cfg.paths.ensure()
    created: list[Path] = []

    templates = {
        cfg.paths.config_dir / "config.yaml": _yaml_template("config"),
        cfg.paths.config_dir / "scope.yaml": _yaml_template("scope"),
        cfg.paths.config_dir / "wordlists.yaml": _yaml_template("wordlists"),
    }
    for target, content in templates.items():
        if target.exists() and not args.force:
            console.print(f"[dim]exists, skipping:[/] {target.relative_to(cfg.paths.base)}")
            continue
        target.write_text(content, encoding="utf-8")
        created.append(target)

    for rel in ("wordlists/common.txt", "wordlists/parameters.txt", "wordlists/extensions.txt"):
        path = cfg.paths.base / rel
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_starter_wordlist(rel), encoding="utf-8")
            created.append(path)

    if created:
        console.print("[green]created:[/]")
        for p in created:
            console.print(f"  [bright_cyan]{p.relative_to(cfg.paths.base)}[/]")
    else:
        console.print("[yellow]nothing to create (all files present)[/]")

    console.print("\nEdit [bold]config/config.yaml[/] -> set [bold]target.domain[/] to your")
    console.print("AUTHORIZED scope, then run [bold]hunterx doctor[/] and [bold]hunterx scan[/].")
    return 0


def _yaml_template(kind: str) -> str:
    from .config import DEFAULT_CONFIG_YAML, DEFAULT_SCOPE_YAML, DEFAULT_WORDLISTS_YAML
    return {"config": DEFAULT_CONFIG_YAML, "scope": DEFAULT_SCOPE_YAML, "wordlists": DEFAULT_WORDLISTS_YAML}[kind]


def _starter_wordlist(rel: str) -> str:
    entries = {
        "wordlists/common.txt": "admin\napi\nbackup\nconfig\nlogin\nrobots.txt\nsitemap.xml\nswagger\n",
        "wordlists/parameters.txt": "id\nuser\nuser_id\nuuid\ntoken\nfile\nurl\nredirect\npage\nq\n",
        "wordlists/extensions.txt": "php\nasp\naspx\njsp\njson\nxml\nbak\nold\nzip\n",
    }
    return entries.get(rel, "")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

def cmd_doctor(args: argparse.Namespace) -> int:
    if not args.json:
        banner()
    try:
        cfg = _resolve_config(args)
    except ConfigError as exc:
        cfg = None
        console.print(f"[yellow]config error (continuing with defaults): {exc}[/]")

    report: DoctorReport = run_doctor(config=cfg)
    if args.json:
        print(json.dumps(report_json(report), indent=2, sort_keys=True))
        return 0

    console.print(report.table())
    ok, warn, failed = report.summary
    console.print(f"summary: [green]{ok} ok[/] | [yellow]{warn} warnings[/] | [red]{failed} blockers[/]")
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def _target_from_args(cfg: Config, args: argparse.Namespace) -> tuple[str, str | None]:
    domain, wildcard = cfg.target.domain, cfg.target.wildcard
    if args.target:
        domain, wildcard = normalize_wildcard_target(args.target)
        cfg.set_target(domain, wildcard)
    if not domain and not wildcard:
        console.print("[red]no target configured[/]")
        console.print("set target.domain in config/config.yaml or pass --target")
        raise SystemExit(2)
    chosen = wildcard or domain or ""
    if not validate_hostname(domain or ""):
        raise ConfigError(f"invalid target hostname '{chosen}'")
    return chosen, wildcard


def _scope_table(scope: Scope) -> Table:
    table = Table(title="Scope engine", show_header=False, box=None)
    for line in scope.describe():
        table.add_row(line)
    return table


def _resolve_run(args: argparse.Namespace, cfg: Config, db: Database, chosen: str) -> str:
    profile = args.profile or cfg.scan.mode
    if args.resume:
        if args.resume is True:
            candidates = [r for r in db.list_runs(incomplete_only=True) if r["target"] == chosen]
            if not candidates:
                console.print("[red]no incomplete run to resume for that target[/]")
                raise SystemExit(1)
            run_id = candidates[0]["id"]
        else:
            run_id = str(args.resume)
        run = db.get_run(run_id)
        if not run:
            console.print(f"[red]run {run_id} not found[/]")
            raise SystemExit(1)
        console.print(f"[dim]resuming existing run {run_id}[/]")
        return run_id

    run_id = db.create_scan_run(chosen, profile)
    console.print(f"[bold green]RUN[/] [bold]{run_id}[/]  target=[bright_cyan]{chosen}[/] profile=[cyan]{profile}[/]")
    return run_id


def cmd_scan(args: argparse.Namespace) -> int:
    banner()
    cfg = _resolve_config(args)
    chosen, wildcard = _target_from_args(cfg, args)
    cfg.paths.ensure()
    db = _resolve_db(cfg)
    run_id = _resolve_run(args, cfg, db, chosen)

    scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
    if not scope.allowed_patterns:
        console.print("[red]scope has no include patterns; refusing to run[/]")
        db.finish_run(run_id, "failed")
        return 2
    console.print(_scope_table(scope))
    if not scope.is_allowed_host(chosen):
        console.print(f"[red]target {chosen} is NOT inside configured scope[/]")
        db.finish_run(run_id, "failed")
        return 2
    console.print("[green]✓ target is inside scope[/]")
    db.mark_phase(run_id, "scope", "done")
    db.close()

    from .scan import execute_scan

    only = args.phase.split(",")[0] if args.phase else None
    phases = [args.phase] if args.phase else None
    summary = asyncio.run(
        execute_scan(
            cfg,
            run_id=run_id, target=chosen, profile=args.profile or cfg.scan.mode,
            wildcard=wildcard,
            phases=phases,
            start_phase=only,
            resume=bool(args.resume),
        )
    )

    _print_scan_summary(summary)
    return 2 if summary.get("status") == "failed" else (1 if summary.get("stopped") else 0)


def cmd_interactive(args: argparse.Namespace) -> int:
    from .interactive import run_interactive

    cfg = _resolve_config(args)
    if getattr(args, "wordlist", None):
        cfg.override_wordlist = args.wordlist
    return run_interactive(cfg)


def _print_scan_summary(summary: dict) -> None:
    table = Table(title=f"Pipeline summary — {summary['run_id']}", show_header=True)
    table.add_column("Phase", style="cyan")
    table.add_column("State", justify="center")
    table.add_column("Items", justify="right")
    for name, value in summary.get("phases", {}).items():
        if isinstance(value, str):
            state, count = value, 0
        else:
            state, count = value.get("state", "?"), value.get("count", 0)
        glyph = {"done": "[green]✓[/]", "running": "[yellow]●[/]", "failed": "[red]✗[/]",
                 "stopped": "[magenta]■[/]", "interrupted": "[yellow]⏹[/]"}.get(state, "[dim]·[/]")
        table.add_row(PHASE_LABELS.get(name, name), glyph, str(count))
    console.print(table)
    status = summary.get("status", "?")
    color = "green" if status == "finished" else ("red" if status == "failed" else "yellow")
    console.print(Panel(f"scan status: [{color}]{status}[/]", title="Result"))


def _one_shot_phase(args: argparse.Namespace, phase: str) -> int:
    cfg = _resolve_config(args)
    chosen, wildcard = _target_from_args(cfg, args)
    cfg.paths.ensure()
    db = _resolve_db(cfg)
    scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
    if not scope.allowed_patterns or not scope.is_allowed_host(chosen):
        console.print("[red]target not inside configured scope; refusing[/]")
        return 2

    run_id = db.create_scan_run(chosen, args.profile or cfg.scan.mode)
    db.mark_phase(run_id, "scope", "done")
    db.close()

    if phase == "fuzzing" and getattr(args, "wordlist", None):
        cfg.override_wordlist = args.wordlist

    from .scan import execute_scan

    summary = asyncio.run(
        execute_scan(
            cfg,
            run_id=run_id, target=chosen, profile=args.profile or cfg.scan.mode,
            wildcard=wildcard, phases=[phase],
        )
    )
    _print_scan_summary(summary)
    return 0 if summary.get("status") == "finished" else 1


# ---------------------------------------------------------------------------
# resume / stop / clean / test
# ---------------------------------------------------------------------------

def cmd_resume(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    db = _resolve_db(cfg)
    run = db.get_run(args.run_id)
    if not run:
        console.print(f"[red]run {args.run_id!r} not found[/]")
        recent = db.list_runs(limit=5)
        if recent:
            console.print("recent runs:")
            for r in recent:
                console.print(f"  [cyan]{r['id']}[/] {r['target']} [{r['status']}]")
        return 1
    table = Table(title=f"Run {run['id']}", show_header=True)
    table.add_column("Phase", style="cyan")
    table.add_column("State", justify="center")
    for phase in PHASES:
        state = run["phases"].get(phase, "pending")
        glyph = {"done": "[green]✓[/]", "failed": "[red]✗[/]", "running": "[yellow]●[/]",
                 "skipped": "[dim]–[/]"} .get(state, "[dim]·[/]")
        table.add_row(f"{phase}  {PHASE_LABELS.get(phase, '')}", glyph)
    console.print(table)
    console.print(f"target: [bright_cyan]{run['target']}[/] profile: [cyan]{run['profile']}[/] status: [yellow]{run['status']}[/]")
    console.print("resume the scan with: [bold]hunterx scan --target <target> --resume " + run["id"] + "[/]")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    cfg.paths.ensure()
    marker = _emit_stop(cfg.paths.data)
    console.print(f"[red]stop requested[/] — marker written to {marker}")
    console.print("active scan workers will stop between requests.")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    targets = []
    if args.assets:
        targets.append(("data", cfg.paths.data))
        targets.append((".stop marker", cfg.paths.data / ".stop"))
    if args.reports:
        targets.append(("reports", cfg.paths.reports))
    if args.all:
        targets = [("data", cfg.paths.data), ("reports", cfg.paths.reports), ("log", cfg.paths.log_dir)]

    if not targets:
        console.print("nothing selected; use --assets, --reports, or --all")
        return 0
    if args.yes:
        for name, path in targets:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
                console.print(f"[green]removed[/] {name} ({path})")
            elif path.is_file():
                path.unlink(missing_ok=True)
    else:
        console.print("[yellow]this is destructive; pass --yes to confirm[/]")
        return 1
    cfg.paths.ensure()
    console.print("[dim]structure recreated; database will be regenerated on next run[/]")
    if args.assets:
        console.print("[yellow]note: hosting DB lives under data/ and was removed[/]")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    import pytest

    base = Path(__file__).resolve().parent.parent
    result = pytest.main(["-q", str(base / "tests")] + (["-x"] if args.failfast else []))
    return int(result)


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    db = _resolve_db(cfg)
    runs = db.list_runs(limit=20)
    run = next((r for r in runs if args.run and r["id"] == args.run), None)
    if not run and args.run:
        console.print(f"[red]run {args.run!r} not found[/]")
        return 1
    if not run:
        run = next((r for r in runs if r["status"] == "finished"), None)
    if not run:
        run = runs[0] if runs else None
    if not run:
        console.print("[red]no runs to report yet[/]")
        return 1
    db.close()

    target = run["target"]
    cfg.set_target(target, None)
    summary = asyncio.run(render_into(cfg, run))
    for path in summary.get("outputs", []):
        console.print(f"  [bright_cyan]{path}[/]")
    return 0


async def render_into(cfg: Config, run: dict) -> dict:
    from .context import ScanContext
    from .database import Database, utcnow
    from .reporting.run import run as render
    from .scope import Scope
    from .store import Store
    from .tools import Tools

    db = Database(cfg.paths.data / "hunterx.db")
    try:
        scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
        ctx = ScanContext(
            cfg=cfg, scope=scope, db=db, store=Store(db),
            run_id=run["id"], target=run["target"], profile_name=run.get("profile") or "balanced",
            profile=cfg.profile_cfg(run.get("profile") or "balanced"),
            session=None, tools=Tools(cfg),
        )
        paths = await render(ctx)
        return {"run_id": run["id"], "outputs": [str(p) for p in paths]}
    finally:
        db.close()


def cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    from .reporting.dashboard import build_dashboard
    from .context import ScanContext
    from .database import Database
    from .scope import Scope
    from .store import Store

    db = Database(cfg.paths.data / "hunterx.db")
    try:
        ctx = ScanContext(cfg=cfg, scope=Scope.from_config(cfg.scope_cfg(), cfg.target),
                          db=db, store=Store(db), run_id="dashboard", target=cfg.target.primary or "")
        path = build_dashboard(ctx)
    finally:
        db.close()
    console.print(f"dashboard written: [bright_cyan]{path}[/]")
    return 0


# ---------------------------------------------------------------------------
# intel
# ---------------------------------------------------------------------------

def cmd_intel(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    from .context import ScanContext
    from .database import Database
    from .scope import Scope
    from .store import Store
    from .tools import Tools

    db = Database(cfg.paths.data / "hunterx.db")
    try:
        scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
        run_id = db.create_scan_run(cfg.target.primary or "intel", "balanced")
        ctx = ScanContext(cfg=cfg, scope=scope, db=db, store=Store(db), run_id=run_id,
                          target=(cfg.target.primary or "intel"), profile_name="balanced",
                          profile=cfg.profile_cfg("balanced"), session=None, tools=Tools(cfg))

        if args.action == "update":
            from .intelligence.advisories import refresh
            from .intelligence.nuclei_templates import update_nuclei_templates
            new = asyncio.run(refresh(ctx))
            updated = asyncio.run(update_nuclei_templates(ctx))
            console.print(f"[green]intel: {new} new KEV/CVE records ({updated or 'no template update'})[/]")
        else:  # diff
            from .analysis.delta import run as delta_run
            results = asyncio.run(delta_run(ctx))
            console.print("intel diff (since previous run):")
            for scope_name, diff in results.items():
                console.print(f"  [cyan]{scope_name}[/]  +{diff['added']} −{diff['removed']} ~{diff['changed']}")
        db.finish_run(run_id, "finished")
        return 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------

def cmd_schedule(args: argparse.Namespace) -> int:
    cfg = _resolve_config(args)
    from .scheduler import run_forever, run_once

    loop = asyncio.new_event_loop()
    if args.once:
        loop.run_until_complete(run_once(cfg, dry=args.dry))
        return 0
    loop.run_until_complete(run_forever(cfg, dry=args.dry))
    return 0


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunterx",
        description="Authorized bug-hunting / attack-surface monitoring framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"hunterx {__version__}")
    parser.add_argument("--config", help="path to an alternative config.yaml")
    parser.add_argument("--loglevel", default="INFO", help="INFO, DEBUG, WARNING, ERROR")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="create default config, directories, wordlists").add_argument(
        "--force", action="store_true", help="overwrite existing templates")

    run_p = sub.add_parser("run", help="interactive wizard: it asks for the target "
                                       "and which scans to run")
    run_p.add_argument("--wordlist", "-w", metavar="FILE",
                       help="content-discovery wordlist override for this run")

    d = sub.add_parser("doctor", help="check runtime, tools, config, database")
    d.add_argument("--json", action="store_true", help="machine-readable output")

    s = sub.add_parser("scan", help="run the full resumable scanner pipeline")
    s.add_argument("--target", help="override target, e.g. example.com or *.example.com")
    s.add_argument("--profile", choices=["passive", "safe", "balanced", "deep"])
    s.add_argument("--phase", help="run a single phase only, e.g. discovery or dns")
    s.add_argument("--resume", nargs="?", const=True, metavar="RUN_ID",
                   help="resume an unfinished scan; optional RUN_ID")

    r = sub.add_parser("resume", help="inspect a run's phase status")
    r.add_argument("run_id")

    sub.add_parser("stop", help="request a graceful stop of active scans")

    c = sub.add_parser("clean", help="remove scan artifacts (data/reports/logs)")
    c.add_argument("--assets", action="store_true", help="remove data/ (assets DB, evidence)")
    c.add_argument("--reports", action="store_true", help="remove reports/")
    c.add_argument("--all", action="store_true", help="remove data/, reports/ and log/")
    c.add_argument("--yes", action="store_true", help="confirm deletion")

    t = sub.add_parser("test", help="run the unit/integration test suite")
    t.add_argument("--failfast", action="store_true")

    sub.add_parser("discover", help="one-shot: subdomain discovery").add_argument("--target")
    sub.add_parser("probe", help="one-shot: HTTP probing").add_argument("--target")
    sub.add_parser("crawl", help="one-shot: crawl").add_argument("--target")
    fuzz_p = sub.add_parser("fuzz", help="one-shot: content discovery")
    fuzz_p.add_argument("--target")
    fuzz_p.add_argument("--wordlist", "-w", metavar="FILE",
                        help="wordlist file or name (path, relative to base_dir, or any filename under it)")
    sub.add_parser("nuclei", help="one-shot: nuclei scan of stored URLs").add_argument("--target")

    intel = sub.add_parser("intel", help="CVE/KEV intelligence (update or diff)")
    intel.add_argument("action", choices=["update", "diff"])

    rep = sub.add_parser("report", help="render the latest (or --run) report")
    rep.add_argument("--run")

    sub.add_parser("dashboard", help="write reports/dashboard.html")

    sch = sub.add_parser("schedule", help="run scheduled scans (cron expressions in config)")
    sch.add_argument("--once", action="store_true", help="evaluate now and exit")
    sch.add_argument("--dry", action="store_true", help="don't spawn scans")

    for one in ("discover", "probe", "crawl", "fuzz", "nuclei"):
        sub._name_parser_map[one].add_argument("--profile", choices=["passive", "safe", "balanced", "deep"])
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    log_dir = None
    try:
        preliminary = Config.load(config_file=getattr(args, "config", None))
        log_dir = preliminary.paths.log_dir
    except ConfigError:
        pass
    try:
        setup_logging(log_dir=log_dir, level=args.loglevel.upper())
    except Exception:
        pass

    dispatch = {
        "run": cmd_interactive,
        "interactive": cmd_interactive,
        "init": cmd_init,
        "doctor": cmd_doctor,
        "scan": cmd_scan,
        "resume": cmd_resume,
        "stop": cmd_stop,
        "clean": cmd_clean,
        "test": cmd_test,
        "discover": lambda a: _one_shot_phase(a, "discovery"),
        "probe": lambda a: _one_shot_phase(a, "http"),
        "crawl": lambda a: _one_shot_phase(a, "urls"),
        "fuzz": lambda a: _one_shot_phase(a, "fuzzing"),
        "nuclei": lambda a: _one_shot_phase(a, "scanners"),
        "intel": cmd_intel,
        "report": cmd_report,
        "dashboard": cmd_dashboard,
        "schedule": cmd_schedule,
    }
    try:
        return dispatch[args.command or "run"](args)
    except ConfigError as exc:
        console.print(f"[red]config error:[/] {exc}")
        return 2
    except ScopeError as exc:
        console.print(f"[red]scope error:[/] {exc}")
        return 2
    except DatabaseError as exc:
        console.print(f"[red]database error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted by user[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
