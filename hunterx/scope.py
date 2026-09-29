"""Strict scope engine.

Every asset (host, URL, IP) that reaches an active module MUST pass
:meth:`Scope.is_allowed_*` first. Semantics:

  * ``*.example.com`` matches ``example.com`` (apex, when
    ``allow_apex`` is on) and ANY label depth below it
    (``www.``, ``a.b.``, ...) but NOT ``example.com.evil.com`` or
    ``evil-example.com``.
  * Excludes ALWAYS win over includes (``never_bypass_exclusions``).
  * Path and IP-range exclusions are honored for URLs / assets.

Scope checks are intentionally conservative: when in doubt, deny.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable


class ScopeError(Exception):
    pass


def normalize_host(host: str) -> str:
    """Lowercase, strip trailing dot, reject junk outright."""
    if not host or not isinstance(host, str):
        return ""
    h = host.strip().lower().rstrip(".")
    if not h or h in {".", "*"} or " " in h:
        return ""
    return h


def _compile_pattern(pattern: str, include_apex: bool = True) -> re.Pattern[str]:
    """Compile a scope pattern into an anchored regex.

    * ``*`` as a full label matches exactly one label (``[^.]+``).
    * A leading ``*.`` additionally matches the apex (when allowed).
    """
    p = pattern.strip().lower().rstrip(".")
    if not p:
        raise ScopeError(f"empty scope pattern {pattern!r}")

    if p.startswith("*."):
        base = p[2:]
        if not base:
            raise ScopeError(f"invalid scope pattern {pattern!r}")
        suffix = "\\.".join(re.escape(part) for part in base.split(".") if part)
        if include_apex:
            return re.compile(rf"^([^.]+\.)*{suffix}$")
        return re.compile(rf"^[^.]+\.{suffix}$")

    labels = p.split(".")
    escaped = "[^.]+" if "*" in p else None
    parts = [re.escape(part) if part != "*" else escaped for part in labels]
    return re.compile("^" + "\\.".join(str(x) for x in parts) + "$")


def _compile_exact(pattern: str, include_apex: bool = True) -> re.Pattern[str]:
    return _compile_pattern(pattern, include_apex)


def _parse_cidrs(entries: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for entry in entries or []:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise ScopeError(f"invalid IP range '{entry}': {exc}") from exc
    return networks


@dataclass
class Scope:
    """Merged include/exclude scope with path and IP filters."""

    allowed_patterns: list[str] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)
    allow_apex: bool = True
    allow_subdomains: bool = True

    _allowed_re: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _excluded_re: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _excluded_networks: list = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        for entry in list(self.allowed_patterns) or []:
            if entry:
                self._allowed_re.append(_compile_exact(entry, self.allow_apex))
        for entry in list(self.excluded_patterns) or []:
            if entry:
                self._excluded_re.append(_compile_exact(entry, include_apex=True))
        self.excluded_paths = [p.strip().rstrip("/") or "/" for p in (self.excluded_paths or []) if p and p.strip()]
        self._excluded_networks = _parse_cidrs(self.excluded_ips)

    # -- construction -------------------------------------------------
    @classmethod
    def build(cls, *, allowed: Iterable[str] = (), excluded: Iterable[str] = (),
              excluded_paths: Iterable[str] = (), excluded_ips: Iterable[str] = (),
              allow_apex: bool = True, allow_subdomains: bool = True) -> "Scope":
        return cls(
            allowed_patterns=list(allowed),
            excluded_patterns=list(excluded),
            excluded_paths=list(excluded_paths),
            excluded_ips=list(excluded_ips),
            allow_apex=allow_apex,
            allow_subdomains=allow_subdomains,
        )

    @classmethod
    def from_config(cls, scope_cfg: dict, target=None) -> "Scope":
        """Build from a config `scope:` dict.

        The *anchor* (target domain or wildcard) is added to includes once:
        it is the explicit, human-granted authorization anchor. Discovered
        assets are never auto-scoped; they must match an include pattern
        on their own for active modules to touch them.
        """
        includes = [str(x) for x in scope_cfg.get("include", []) if x]
        excludes = [str(x) for x in scope_cfg.get("exclude", []) if x]

        if target is not None:
            anchor = getattr(target, "wildcard", None) or getattr(target, "domain", None)
            if anchor and anchor not in includes and anchor not in excludes:
                includes.append(anchor)

        return cls(
            allowed_patterns=includes,
            excluded_patterns=excludes,
            excluded_paths=scope_cfg.get("excluded_paths", []),
            excluded_ips=scope_cfg.get("excluded_ips", []),
            allow_apex=bool(scope_cfg.get("allow_apex", True)),
            allow_subdomains=bool(scope_cfg.get("allow_subdomains", True)),
        )

    # -- checks -------------------------------------------------------
    def is_allowed_host(self, host: str) -> bool:
        h = normalize_host(host)
        if not h:
            return False
        # Exclusions always win.
        for pattern in self._excluded_re:
            if pattern.fullmatch(h):
                return False
        if not self.allowed_patterns:
            return False
        return any(p.fullmatch(h) for p in self._allowed_re)

    def is_allowed_url(self, url: str) -> bool:
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname or ""
        if not host or not self.is_allowed_host(host):
            return False
        path = parsed.path or "/"
        if self._path_excluded(path):
            return False
        return True

    def is_allowed_ip(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return False
        if not self._excluded_networks:
            return True
        return not any(address in net for net in self._excluded_networks)

    def is_allowed(self, *, host: str | None = None, url: str | None = None, ip: str | None = None) -> bool:
        """Combined gate. When multiple fields are given, ALL must pass."""
        if host is not None and not self.is_allowed_host(host):
            return False
        if url is not None and not self.is_allowed_url(url):
            return False
        if ip is not None and not self.is_allowed_ip(ip):
            return False
        return True

    def _path_excluded(self, path: str) -> bool:
        for excluded in self.excluded_paths:
            if excluded == "/":
                continue
            if path == excluded or path.startswith(excluded.rstrip("/") + "/"):
                return True
        return False

    def describe(self) -> list[str]:
        """Human-readable summary used by ``hunterx scan`` Phase 0."""
        lines = [f"allowed patterns: {', '.join(self.allowed_patterns) or '(none)'}",
                 f"excluded patterns: {', '.join(self.excluded_patterns) or '(none)'}",
                 f"excluded paths: {', '.join(self.excluded_paths) or '(none)'}",
                 f"excluded IPs: {', '.join(self.excluded_ips) or '(none)'}",
                 f"allow subdomains: {self.allow_subdomains}, allow apex: {self.allow_apex}"]
        return lines