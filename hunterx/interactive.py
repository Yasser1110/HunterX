"""Interactive wizard: ``hunterx run`` (or no command) asks for the target and
lets you pick which recon/attack scans to launch, instead of editing config or
memorizing CLI flags."""

from __future__ import annotations

import asyncio
from typing import Any

from rich.prompt import Confirm, Prompt

from .config import Config, normalize_wildcard_target
from .database import PHASES
from .scope import Scope
from .ui import banner, console

# High-level scan options -> concrete pipeline phases. Decision logic lives in
# `plan_scan` so it is unit-testable without driving the prompts.
SCAN_OPTIONS = [
    ("Passive recon (subdomains, DNS enumeration)", ["discovery", "dns"]),
    ("Probe live services (HTTP, ports, fingerprint)", ["http", "ports", "fingerprinting"]),
    ("URL discovery + crawl + JS analysis + params", ["urls", "javascript", "parameters"]),
    ("Content discovery (fuzzing against wordlists)", ["fuzzing"]),
    ("Vulnerability scans (nuclei + safe checks)", ["scanners"]),
    ("CVE correlation & risk scoring", ["cve", "dedup", "evidence", "prioritization"]),
    ("AI-assisted triage", ["ai"]),
]

PROFILE_DESC = {
    "passive": "no packets to the target, API/SQLite sources only",
    "safe": "light, non-aggressive checks against live assets",
    "balanced": "moderate concurrency (default)",
    "deep": "high concurrency, more checks",
}

TIER_LABELS = {
    "1": "small tier (common.txt)",
    "2": "medium tier (raft-medium-directories.txt)",
    "3": "large tier (raft-large-directories.txt)",
}


def tier_for_choice(choice: str) -> str | None:
    """Map the helper's wordlist choice to an override the pipeline understands.
    Tier names ('small'/'medium'/'large') and '' mean "use that tier";
    anything else is a concrete file to resolve under wordlists.base_dir."""
    if choice in ("small", "medium", "large"):
        return choice
    return choice or None


def plan_scan(
    *,
    target: str,
    profile: str,
    selection: list[int],
    wordlist: str | None,
    notify: bool,
) -> dict[str, Any]:
    """Turn interactive answers into a phase list (pure, testable)."""
    phases: list[str] = []
    for idx in selection:
        if 1 <= idx <= len(SCAN_OPTIONS):
            for phase in SCAN_OPTIONS[idx - 1][1]:
                if phase not in phases:
                    phases.append(phase)
    # reporting is always part of the pipeline; notification is optional.
    if "reporting" not in phases:
        phases.append("reporting")
    if notify and "notification" not in phases:
        phases.append("notification")
    ordered = [p for p in PHASES if p in phases]
    return {
        "target": target,
        "profile": profile,
        "phases": ordered,
        "wordlist": wordlist,
    }


def _ask_target(cfg: Config) -> tuple[str, str | None]:
    default = cfg.target.domain or None
    while True:
        answer = Prompt.ask(
            "Target (domain or wildcard, e.g. crypto.com / *.crypto.com)",
            default=default or "",
            show_default=default is not None,
        ).strip()
        if not answer and default:
            answer = default
        if not answer:
            console.print("[yellow]target is required[/]")
            continue
        try:
            return normalize_wildcard_target(answer)
        except ValueError as exc:
            console.print(f"[yellow]{exc}; try again[/]")


def _ask_profile() -> str:
    options = list(PROFILE_DESC)
    console.print("\n[bold]Scan profile[/]")
    for i, name in enumerate(options, 1):
        console.print(f"  [cyan]{i}[/] {name:<9} {PROFILE_DESC[name]}")
    while True:
        answer = Prompt.ask(
            "Profile", choices=[str(i) for i in range(1, len(options) + 1)], default="3")
        return options[int(answer) - 1]


def _ask_selection(default_all: bool = True) -> list[int]:
    console.print("\n[bold]Which scans should I run?[/] (comma-separated numbers)")
    for i, (label, _) in enumerate(SCAN_OPTIONS, 1):
        console.print(f"  [cyan]{i}[/] {label}")
    hint = "1-7" if default_all else "e.g. 1,2,5"
    while True:
        answer = Prompt.ask(f"Scans [dim]({hint})[/]", default="all").strip().lower()
        if answer in ("all", "a", "*"):
            return list(range(1, len(SCAN_OPTIONS) + 1))
        nums: list[int] = []
        for chunk in answer.replace(";", ",").split(","):
            chunk = chunk.strip()
            if "-" in chunk and chunk.count("-") == 1:
                lo, hi = chunk.split("-", 1)
                if lo.strip().isdigit() and hi.strip().isdigit():
                    lo, hi = int(lo), int(hi)
                    if lo <= hi and hi <= len(SCAN_OPTIONS):
                        nums.extend(range(lo, hi + 1))
                        continue
            if chunk.isdigit():
                nums.append(int(chunk))
        if nums and all(1 <= n <= len(SCAN_OPTIONS) for n in nums):
            return sorted(set(nums))
        console.print("[yellow]invalid selection; use numbers like 1,2,5 or 'all'[/]")


def _ask_wordlist() -> str | None:
    console.print("[bold]Content-discovery wordlist[/]")
    for num, label in TIER_LABELS.items():
        console.print(f"  [cyan]{num}[/] {label}")
    console.print("  [cyan]4[/] specific file (path or filename under wordlists.base_dir)")
    while True:
        answer = Prompt.ask("Wordlist", default="1")
        if answer in TIER_LABELS:
            return {"1": None, "2": "medium", "3": "large"}[answer]
        if answer == "4":
            return Prompt.ask("Path or file name").strip()
        console.print("[yellow]choose 1-4[/]")


def _wants_phase(selection: list[int], phase: str) -> bool:
    return any(phase in SCAN_OPTIONS[i - 1][1] for i in selection if 1 <= i <= len(SCAN_OPTIONS))


def _confirm(target: str, profile: str, phases: list[str], wordlist: str | None) -> bool:
    console.print("\n[bold]Plan[/]")
    console.print(f"  target:  [bright_cyan]{target}[/]")
    console.print(f"  profile: [cyan]{profile}[/]")
    console.print(f"  phases:  {', '.join(phases)}")
    if wordlist:
        console.print(f"  wordlist: [yellow]{wordlist}[/]")
    return Confirm.ask("Start scan?", default=True)


def run_interactive(cfg: Config) -> int:
    from .cli import _print_scan_summary, _resolve_db, cmd_report

    banner()
    console.print("Interactive scan — you'll be asked for the target and the scans to run.\n")

    target, wildcard = _ask_target(cfg)
    profile = _ask_profile()
    selection = _ask_selection()

    wordlist = cfg.override_wordlist
    if _wants_phase(selection, "fuzzing") and not wordlist:
        wordlist = _ask_wordlist()
        if wordlist:
            cfg.override_wordlist = wordlist

    notify = Confirm.ask("Send notifications (webhook/discord) after the scan?", default=False)

    plan = plan_scan(target=target, profile=profile, selection=selection,
                     wordlist=wordlist, notify=notify)
    if not _confirm(plan["target"], plan["profile"], plan["phases"], plan["wordlist"]):
        console.print("[yellow]aborted[/]")
        return 1

    cfg.paths.ensure()
    db = _resolve_db(cfg)
    scope = Scope.from_config(cfg.scope_cfg(), cfg.target)
    if not scope.allowed_patterns:
        console.print("[red]config scope has no include patterns; refusing to run[/]")
        db.close()
        return 2
    if not scope.is_allowed_host(plan["target"]):
        console.print(f"[red]target {plan['target']} is NOT inside configured scope; refusing[/]")
        db.close()
        return 2

    run_id = db.create_scan_run(plan["target"], plan["profile"])
    db.mark_phase(run_id, "scope", "done")
    db.close()
    console.print(
        f"[bold green]RUN[/] [bold]{run_id}[/]  "
        f"target=[bright_cyan]{plan['target']}[/] profile=[cyan]{plan['profile']}[/]\n")

    from .scan import execute_scan

    summary = asyncio.run(
        execute_scan(
            cfg,
            run_id=run_id,
            target=plan["target"],
            profile=plan["profile"],
            wildcard=wildcard,
            phases=plan["phases"],
        )
    )
    _print_scan_summary(summary)
    if summary.get("status") == "finished" and Confirm.ask("Open the report?", default=True):
        return cmd_report(_Namespace(run=None, config=None))
    return 0 if summary.get("status") == "finished" else 1


class _Namespace:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)