"""Configuration loading, merging and validation.

Design:
  * Built-in defaults (code) are deep-merged with the user ``config.yaml``
    and, if present, ``config/scope.yaml`` (scope overlay only).
  * Scan *profiles* (passive/safe/balanced/deep) override a few knobs on
    top of the generic ``scan`` section. ``balanced`` is the default.
  * Wildcard targets (``*.example.com``) are normalized to a base domain
    plus an explicit wildcard pattern.

Nothing here reads from the network. External tools are signed by
``hunterx doctor``, never assumed.
"""

from __future__ import annotations

import os
import re
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*)?\.?$"
)

DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "passive": {
        "concurrency": {"dns": 10, "http": 5, "fuzzing": 0, "nuclei": 0, "workers": 5},
        "rate_limit": {"requests_per_second": 3},
        "retries": 1,
    },
    "safe": {
        "concurrency": {"dns": 15, "http": 10, "fuzzing": 5, "nuclei": 5, "workers": 8},
        "rate_limit": {"requests_per_second": 5},
        "retries": 2,
    },
    "balanced": {
        "concurrency": {"dns": 30, "http": 20, "fuzzing": 10, "nuclei": 10, "workers": 10},
        "rate_limit": {"requests_per_second": 5},
        "retries": 2,
    },
    "deep": {
        "concurrency": {"dns": 50, "http": 30, "fuzzing": 20, "nuclei": 15, "workers": 20},
        "rate_limit": {"requests_per_second": 8},
        "timeout": {"connect": 8, "read": 15},
        "retries": 3,
    },
}

DEFAULTS: dict[str, Any] = {
    "project": {
        "name": "hunterx",
        "data_dir": "data",
        "reports_dir": "reports",
        "log_dir": "log",
    },
    "target": {"domain": None, "wildcard": None},
    "scope": {
        "include": [],
        "exclude": [],
        "excluded_paths": [],
        "excluded_ips": [],
        "allow_subdomains": True,
        "allow_apex": True,
        "allow_related_domains": False,
        "allow_external_redirects": False,
        "never_bypass_exclusions": True,
    },
    "scan": {
        "mode": "balanced",
        "profiles": DEFAULT_PROFILES,
        "concurrency": {"dns": 30, "http": 20, "fuzzing": 10, "nuclei": 10, "workers": 10},
        "rate_limit": {"requests_per_second": 5},
        "timeout": {"connect": 5, "read": 10},
        "retries": 2,
        "extra_ports": [8000, 8080, 8443, 3000, 5000],
        "user_agent": "HunterX/0.2 (+authorized-security-testing)",
    },
    "http": {
        "ports": [80, 443],
        "max_redirects": 5,
        "probe_https": True,
        "crawl": {"enabled": True, "max_pages": 200, "max_depth": 3},
        "url_limit": 20000,
    },
    "ports": {
        "enabled": True,
        "nmap": {"enabled": False, "top_ports": 200},
        "naabu": {"enabled": True},
        "common": [22, 21, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521,
                   3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017],
    },
    "intel": {
        "enabled": True,
        "fetch_kev": True,
        "fetch_nvd": False,
        "nvd_api_key": None,
        "update_nuclei_templates": True,
    },
    "ai": {
        "enabled": False,
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
    },
    "nuclei": {
        "enabled": True,
        "update_templates": True,
        "severities": ["info", "low", "medium", "high", "critical"],
        "tags": ["exposure", "misconfig", "cve"],
        "aggressive": False,
    },
    "schedule": {
        "asset_scan": "0 0 * * *",
        "cve_scan": "0 */6 * * *",
        "deep_scan": "0 3 * * 0",
    },
    "notifications": {
        "enabled": False,
        "discord_webhook": None,
        "webhook_url": None,
        "email": {"smtp_host": None, "from": None, "to": []},
        "cooldown_hours": 6,
        "channels": {
            "webhook": {"enabled": False, "url": None, "cooldown_seconds": 3600, "headers": {}},
            "discord": {"enabled": False, "webhook_url": None, "cooldown_seconds": 3600},
        },
    },
    "reporting": {
        "directory": "reports/latest",
        "formats": ["html", "md", "json", "csv"],
        "include_evidence": True,
    },
    "tools": {
        "install_dir": "~/hunterx-tools",
        "required": ["curl", "git"],
        "optional": [
            "subfinder", "amass", "assetfinder", "dnsx",
            "httpx", "naabu", "nmap", "katana", "gau",
            "waybackurls", "ffuf", "feroxbuster", "gobuster", "nuclei",
        ],
    },
    "wordlists": {
        "base_dir": "wordlists",
        "tiers": {
            "small": "common.txt",
            "medium": "raft-medium-directories.txt",
            "large": "raft-large-directories.txt",
        },
        "extensions": ["php", "asp", "aspx", "jsp", "json", "xml", "bak", "old", "zip"],
    },
}


def _resolve_path(base: Path, raw: str) -> Path:
    """Resolve a configured path/glob key. Absolute and ``~`` paths are used
    as-is; relative paths are joined onto the project base."""
    p = Path(raw)
    if p.is_absolute() or str(p).startswith("~"):
        return p.expanduser().resolve()
    return (base / p).resolve()


def deep_merge(base: dict[str, Any], override: dict[str, Any] | None) -> dict[str, Any]:
    """Recursively merge *override* into *base* (base is not mutated)."""
    if not override:
        return deepcopy(base)
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def normalize_wildcard_target(value: str) -> tuple[str, str | None]:
    """Normalize ``*.example.com`` -> ``(example.com, '*.example.com')``.

    Plain ``example.com`` -> ``(example.com, None)``. Also strips a
    surrounding scheme if the user pasted a URL.
    """
    v = (value or "").strip().lower().rstrip(".")
    if "://" in v:
        v = v.split("://", 1)[1].split("/", 1)[0]
        v = v.lower().rstrip(".")
    if v.startswith("*."):
        return v[2:], v
    return v, None


def validate_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return bool(VALID_HOSTNAME.match(host))


def _base_dir() -> Path:
    return Path(os.environ.get("HUNTERX_BASE", ".")).resolve()


@dataclass
class Target:
    domain: str | None = None
    wildcard: str | None = None

    @property
    def primary(self) -> str | None:
        return self.domain or self.wildcard


@dataclass
class ScanSettings:
    mode: str
    concurrency: dict[str, int] = field(default_factory=dict)
    rate_limit: dict[str, float] = field(default_factory=dict)
    timeout: dict[str, int] = field(default_factory=dict)
    retries: int = 2


@dataclass
class ProjectPaths:
    base: Path
    data: Path
    reports: Path
    log_dir: Path
    config_dir: Path
    wordlists: Path

    def ensure(self) -> "ProjectPaths":
        for p in (self.data, self.reports, self.log_dir, self.config_dir, self.wordlists):
            p.mkdir(parents=True, exist_ok=True)
        return self


class Config:
    """Merged, immutable-ish configuration facade."""

    def __init__(self, raw: dict[str, Any], paths: ProjectPaths) -> None:
        self._raw = raw
        self.paths = paths
        self.override_wordlist: str | None = None
        self.target = Target(**{k: raw["target"][k] for k in ("domain", "wildcard")})
        self.scan = ScanSettings(
            mode=raw["scan"]["mode"],
            concurrency=deepcopy(raw["scan"]["concurrency"]),
            rate_limit={str(k): float(v) for k, v in raw["scan"]["rate_limit"].items()},
            timeout={str(k): int(v) for k, v in raw["scan"]["timeout"].items()},
            retries=int(raw["scan"]["retries"]),
        )

    # -- accessors ----------------------------------------------------
    def scope_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["scope"])

    def scan_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["scan"])

    def nuclei_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["nuclei"])

    def schedule_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["schedule"])

    def notifications_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["notifications"])

    def reporting_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["reporting"])

    def tools_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["tools"])

    def wordlists_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["wordlists"])

    def profile_cfg(self, name: str | None = None) -> dict[str, Any]:
        name = (name or self.scan.mode or "balanced").lower()
        profiles = self._raw["scan"].get("profiles", DEFAULT_PROFILES)
        if name not in profiles:
            raise ConfigError(
                f"unknown scan profile '{name}' (use one of {list(DEFAULT_PROFILES)})"
            )
        profile = deepcopy(profiles[name])
        # Resolve fallbacks: profile wins, else generic scan block.
        merged = deep_merge(self._raw["scan"], profile)
        merged.pop("profiles", None)
        merged["mode"] = name
        return merged

    def http_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["http"])

    def ports_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["ports"])

    def intel_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["intel"])

    def ai_cfg(self) -> dict[str, Any]:
        return deepcopy(self._raw["ai"])

    def set_target(self, domain: str | None, wildcard: str | None) -> None:
        self._raw["target"] = {"domain": domain, "wildcard": wildcard}
        self.target = Target(domain=domain, wildcard=wildcard)

    # -- loading ------------------------------------------------------
    @classmethod
    def load(cls, config_file: str | Path | None = None, base_dir: str | Path | None = None) -> "Config":
        base = Path(base_dir) if base_dir else _base_dir()
        raw = deepcopy(DEFAULTS)

        candidates = [Path(config_file)] if config_file else [
            base / "config" / "config.yaml",
            base / "config" / "config.yml",
        ]
        for candidate in candidates:
            if candidate and candidate.is_file():
                try:
                    loaded = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
                except yaml.YAMLError as exc:
                    raise ConfigError(f"invalid YAML in {candidate}: {exc}") from exc
                raw = deep_merge(raw, loaded)
                break

        # Optional scope overlay from a dedicated file.
        scope_file = base / "config" / "scope.yaml"
        if scope_file.is_file():
            try:
                overlay = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"invalid YAML in {scope_file}: {exc}") from exc
            if isinstance(overlay.get("scope"), dict):
                raw["scope"] = deep_merge(raw["scope"], overlay["scope"])

        paths = ProjectPaths(
            base=base,
            data=(base / str(raw["project"]["data_dir"])).resolve(),
            reports=(base / str(raw["project"]["reports_dir"])).resolve(),
            log_dir=(base / str(raw["project"]["log_dir"])).resolve(),
            config_dir=base / "config",
            wordlists=_resolve_path(base, str(raw["wordlists"]["base_dir"])),
        )
        cfg = cls(raw, paths)
        cfg._validate()
        return cfg

    def _validate(self) -> None:
        mode = self.scan.mode
        if mode not in DEFAULT_PROFILES:
            raise ConfigError(f"unknown scan mode '{mode}' (use one of {list(DEFAULT_PROFILES)})")
        if self.scan.rate_limit.get("requests_per_second", 0) <= 0:
            raise ConfigError("rate_limit.requests_per_second must be > 0")
        if self.scan.concurrency.get("workers", 0) <= 0:
            raise ConfigError("concurrency.workers must be > 0")
        if self.scan.retries < 0:
            raise ConfigError("scan.retries must be >= 0")
        if self.target.domain and not validate_hostname(self.target.domain):
            raise ConfigError(f"target domain '{self.target.domain}' is not a valid hostname")


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------------------
# Bootstrap templates written by ``hunterx init``.
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_YAML = """\
# HunterX configuration
# Change `target.domain` to your authorized scope and run `hunterx scan`.

target:
  domain: example.com
  wildcard: "*.example.com"

scope:
  include:
    - "*.example.com"
    - "api.example.com"

  exclude:
    - "admin.example.com"
    - "staging.example.com"

  excluded_paths:
    - "/logout"
    - "/delete"

  excluded_ips: []

  allow_subdomains: true
  allow_apex: true
  allow_related_domains: false
  allow_external_redirects: false
  never_bypass_exclusions: true

scan:
  mode: balanced      # passive | safe | balanced | deep

  concurrency:
    dns: 30
    http: 20
    fuzzing: 10
    nuclei: 10
    workers: 10

  rate_limit:
    requests_per_second: 5

  timeout:
    connect: 5
    read: 10

  retries: 2

  extra_ports: [8000, 8080, 8443, 3000, 5000]
  user_agent: "HunterX/0.2 (+authorized-security-testing)"

http:
  ports: [80, 443]
  max_redirects: 5
  probe_https: true
  crawl:
    enabled: true
    max_pages: 200
    max_depth: 3
  url_limit: 20000

ports:
  enabled: true
  nmap:
    enabled: false
    top_ports: 200
  naabu:
    enabled: true
  common: [22, 21, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017]

intel:
  enabled: true
  fetch_kev: true
  fetch_nvd: false
  nvd_api_key: null

ai:
  enabled: false
  base_url: "https://api.openai.com/v1"
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY

nuclei:
  enabled: true
  update_templates: true
  severities: [info, low, medium, high, critical]
  tags: [exposure, misconfig, cve]
  aggressive: false   # keep false unless you explicitly authorize deeper checks

schedule:
  asset_scan: "0 0 * * *"
  cve_scan: "0 */6 * * *"
  deep_scan: "0 3 * * 0"

notifications:
  enabled: false
  discord_webhook: null
  webhook_url: null
  email:
    smtp_host: null
    from: null
    to: []
  cooldown_hours: 6
  channels:
    webhook:
      enabled: false
      url: null
      cooldown_seconds: 3600
      headers: {}
    discord:
      enabled: false
      webhook_url: null
      cooldown_seconds: 3600

reporting:
  directory: reports/latest
  formats: [html, md, json, csv]
  include_evidence: true

tools:
  install_dir: ~/hunterx-tools
  required: [curl, git]
  optional: [subfinder, amass, assetfinder, dnsx, dig, httpx, naabu, nmap, katana, gau, waybackurls, ffuf, feroxbuster, gobuster, nuclei]

wordlists:
  # Point this at your OWN wordlist collection (any directory). Each tier can
  # be a relative path (joined onto base_dir) or a bare filename: if the bare
  # name does not exist directly under base_dir, the tool looks for it up to
  # a few levels deep, so you can use anything inside SecLists by name.
  # Examples for a SecLists checkout:
  #   base_dir: ~/Documents/SecLists
  #   tiers:
  #     small: Discovery/Web-Content/common.txt
  #     medium: Discovery/Web-Content/raft-medium-directories.txt
  #     large: Discovery/Web-Content/raft-large-directories.txt
  base_dir: ~/Documents/SecLists
  tiers:
    small: common.txt
    medium: raft-medium-directories.txt
    large: raft-large-directories.txt
  extensions: [php, asp, aspx, jsp, json, xml, bak, old, zip]
"""

DEFAULT_SCOPE_YAML = """\
# Optional scope overlay. Merged on top of the `scope:` section in config.yaml.
# Exclusions always win over inclusions.

scope:
  include:
    - "*.example.com"

  exclude:
    - "admin.example.com"
    - "staging.example.com"

  excluded_paths:
    - "/logout"
    - "/delete"

  excluded_ips:
    - "192.0.2.0/24"
"""

DEFAULT_WORDLISTS_YAML = """\
# Wordlist registry. Tiers are used by content discovery (small/medium/large
# map to scan profiles passive+safe / balanced / deep). Paths are resolved
# relative to wordlists.base_dir in config.yaml, and bare filenames are
# located anywhere under that directory (so a SecLists checkout works).

tiers:
  small: common.txt
  medium: raft-medium-directories.txt
  large: raft-large-directories.txt

payloads:
  api: wordlists/api.txt
  graphql: wordlists/graphql.txt
  backup: wordlists/backup.txt
  sensitive: wordlists/sensitive.txt

parameters: wordlists/parameters.txt
extensions: [php, asp, aspx, jsp, json, xml, bak, old, zip]
"""