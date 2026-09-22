"""Shared scan execution context passed to every pipeline phase."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .database import Database
from .httpclient import ScanSession
from .scope import Scope
from .store import Store
from .tools import Tools


@dataclass
class ScanContext:
    cfg: Config
    scope: Scope
    db: Database
    store: Store
    run_id: str
    target: str
    wildcard: str | None = None
    profile_name: str = "balanced"
    profile: dict[str, Any] = field(default_factory=dict)
    session: ScanSession | None = None
    tools: Tools = field(default_factory=Tools)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("hunterx.scan"))
    stats: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def tool(self, name: str, args: list[Any], *, timeout: int = 120) -> Any:
        from .tools import run_tool
        return run_tool(
            name, args, tools=self.tools, timeout=timeout,
            output_dir=self.cfg.paths.data / "tool-outputs",
            run_id=self.run_id, target=self.target, db=self.db,
        )

    async def atool(self, name: str, args: list[Any], *, timeout: int = 120) -> Any:
        return await self.tool(name, args, timeout=timeout)

    def session_now(self) -> ScanSession:
        if self.session is None:
            self.session = ScanSession(self.cfg, self.scope, self.db, self.run_id)
        return self.session

    async def close(self) -> None:
        if self.session is not None:
            await self.session.close()

    def bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    # -- config shorthands ---------------------------------------------
    @property
    def http_cfg(self) -> dict[str, Any]:
        return self.cfg.http_cfg()

    @property
    def scan_cfg(self) -> dict[str, Any]:
        return self.cfg.scan_cfg()

    @property
    def ports_cfg(self) -> dict[str, Any]:
        return self.cfg.ports_cfg()

    @property
    def intel_cfg(self) -> dict[str, Any]:
        return self.cfg.intel_cfg()

    @property
    def ai_cfg(self) -> dict[str, Any]:
        return self.cfg.ai_cfg()

    @property
    def nuclei_cfg(self) -> dict[str, Any]:
        return self.cfg.nuclei_cfg()

    @property
    def wordlists_cfg(self) -> dict[str, Any]:
        return self.cfg.wordlists_cfg()