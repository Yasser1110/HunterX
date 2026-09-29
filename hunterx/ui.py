"""Small terminal UI helpers (banner + tables) built on Rich."""

from __future__ import annotations

from rich.console import Console

from . import __appname__, __version__

console = Console()


def banner() -> None:
    console.print()
    console.rule(f"[bold cyan]{__appname__}[/] [dim]v{__version__}[/]")
    console.print("[dim]Authorized attack-surface monitoring & bug-hunting framework[/]")
    console.print()


def print_box(text: str, style: str = "bold cyan") -> None:
    console.print(f"[{style}]{text}[/]")