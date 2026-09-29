# HunterX

**Authorized attack-surface monitoring & bug-hunting research platform.**

HunterX turns a single wildcard target (e.g. `*.example.com`) into a continuous,
scope-enforced reconnaissance and vulnerability-monitoring pipeline. It is a
*platform*, not a shell script: everything is phase-based, persisted to SQLite,
resumable, deduplicated and reported.

> **Authorization required.** Use this tool ONLY against assets you are
> explicitly allowed to test: bug-bounty programs, your own infrastructure, or
> targets covered by written permission. HunterX enforces a strict scope engine
> before *every* active action, but the scope you configure is your
> responsibility.

---

## Quick start

```bash
git clone <repository>
cd hunterx

python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

hunterx init            # creates config/, data/, reports/, wordlists/
hunterx doctor          # verifies runtime, tools, config, database
hunterx scan --target "*.example.com"   # full pipeline: discovery → … → reports
hunterx scan --target example.com --profile safe --resume RUN-2026-09-21-001
hunterx resume RUN-2026-09-21-001      # inspect per-phase progress
hunterx report --run RUN-2026-09-21-001  # render json/md/csv/html findings
hunterx stop            # graceful global kill switch
hunterx test            # unit/integration test suite
```

Only **one** place needs editing for a new engagement: `config/config.yaml` →
`target.domain`. Wildcards are normalized automatically.

---

## Status by development phase

| Phase | Area | Status |
|-------|------|--------|
| 1 | Skeleton, CLI, config, scope engine, SQLite, logging, doctor, stop | **done** |
| 2 | Subdomain discovery, DNS enumeration, HTTP probing | **done** |
| 3 | Port/service discovery, technology fingerprinting | **done** |
| 4 | Crawler, URL discovery, JS analysis | **done** |
| 5 | Fuzzing, parameter discovery | **done** |
| 6 | Nuclei integration, custom scanners | **done** |
| 7 | CVE intelligence engine | **done** |
| 8 | Correlation, deduplication, prioritization | **done** |
| 9 | HTML/JSON/MD/CSV reports, dashboard, notifications | **done** |
| 10 | Docker, GitHub Actions, scheduled monitoring, `install.sh` | **done** |
| 11 | AI-assisted analysis | **done** |

---

## Architecture

```
Wildcard target
      │
      ▼
 Scope engine  ──►  every active module passes scope.is_allowed() first
      │
      ▼
 phases: discovery → dns → http → ports → fingerprinting → urls → javascript
         → parameters → fuzzing → scanners(+nuclei) → cve → dedup → evidence
         → prioritization → ai → reporting → notification
      │
      ▼
         SQLite (hunterx.db)  ──►  reports/ (json/md/html/csv) + notifications
```

- **Phase pipeline.** Each phase writes to the DB and marks itself
  `done|failed|pending|skipped` on the run record, so scans are resumable and the
  daily attack-surface delta is computable.
- **Scope engine** (`hunterx/scope.py`). Boundary-aware wildcard matching:
  `*.example.com` allows `example.com`, `www.`, `a.b.` … and rejects
  `example.com.evil.com` and `evil-example.com`; exclusions always win; paths and
  IP CIDRs can be excluded.
- **External tools are plugins.** `hunterx doctor` detects what is installed;
  missing tools are skipped, never fatal. Nothing is executed through a shell
  (`shell=True` is avoided) and every command is timeout- and rate-bounded.

---

## CLI

```
hunterx init            create default config, directories, wordlists
hunterx run             INTERACTIVE: asks for target + which scans to run
hunterx doctor          runtime/tool/config/database health
hunterx scan            run pipeline (--target, --profile, --resume, --phase)
hunterx resume RUN_ID   per-phase state of a run
hunterx stop            graceful emergency stop
hunterx clean           remove data/reports/logs (--assets/--reports/--all --yes)
hunterx test            run the automated test suite
hunterx intel update|diff   CVE/KEV intelligence
hunterx schedule            run scheduled scans (--once/--dry, or long-running)
hunterx discover|probe|crawl|fuzz|nuclei   one-shot phase helpers
hunterx report|dashboard    render reports / dashboard.html
```

### Interactive wizard

Running `hunterx run` (or just `hunterx` with no command) starts a guided
session instead of flags: it asks for the **target**, the **profile**, which
of 7 scan bundles to run (passive recon / live probing / URLs+crawl+JS /
content discovery / vulnerability scans / CVE+scoring / AI triage), the
**wordlist**, and whether to send notifications — then prints the plan for
confirmation and runs it. Answers can also be pre-set with normal flags
(e.g. `hunterx run --wordlist raft-medium-directories.txt`).

### Scan profiles

`passive` (nothing touches targets), `safe` (light checks), `balanced`
(default), `deep` (higher concurrence). Override per-knob in
`config/config.yaml` → `scan`.

### Wordlists

`config.yaml` → `wordlists` says where discovery wordlists come from, and the
default template is already pointed at **your own SecLists checkout**
(`~/Documents/SecLists`). Tiers (`small`/`medium`/`large`) may be relative
paths (joined onto `base_dir`) or bare filenames: if a name is not directly
under `base_dir`, the tool searches a few levels deep for a file with that
name (e.g. `Discovery/Web-Content/common.txt`). Whatever isn't found is a
`hunterx doctor` warning, never fatal. One-shot:

```
hunterx fuzz --target example.com --wordlist Discovery/Web-Content/raft-medium-directories.txt
hunterx fuzz --target example.com --wordlist raft-medium-directories.txt   # name lookup works too
```

---

## Containerized & automated operation

- **Venv + optional recon tools** — `./install.sh` creates `.venv`, installs
  the package and (`--tools`) downloads subfinder/httpx/naabu/nuclei/…
  binaries from their official GitHub releases into `~/hunterx-tools`.
- **Docker / Compose** — `docker compose build`, then
  `docker compose run --rm hunterx doctor|init` for one-offs,
  `HUNTERX_TARGET="*.example.com" docker compose up scan` for a single run,
  or `docker compose up -d scheduler` for the long-running cron loop
  (`schedule.asset_scan` / `cve_scan` / `deep_scan` in config).
- **GitHub Actions** — `.github/workflows/hunterx.yml` runs the scanner on a
  cron + manual dispatch, uploads `reports/` as an artifact, writes a
  severity/delta summary to the job page, and optionally POSTs to
  `secrets.HUNTERX_WEBHOOK`. `.github/workflows/ci.yml` runs lint + `pytest`.
  Set the authorized scope in repo **variables** (`HUNTERX_TARGET`) and
  profile in `HUNTERX_PROFILE`.

---

## AI-assisted triage (Phase 11)

Optional, strictly advisory. When `ai.enabled: true` and
`OPENAI_API_KEY` is present, the `ai` phase calls an OpenAI-compatible
chat-completions endpoint to attach a short risk assessment + next step to
each finding (`findings.ai_note`, shown in reports). It never creates,
destroys or escalates findings, and any failure (no key, timeout, bad
response) is a graceful no-op — the pipeline always completes.

---

## Configuration

`config/config.yaml` (created by `hunterx init`) contains the full surface:
target, scope (include/exclude/paths/IPs), scan profile & rate limits, nuclei
categories, schedules, notifications and tool lists. `config/scope.yaml` is an
optional scope-only overlay. Example:

```yaml
target:
  domain: example.com
  wildcard: "*.example.com"

scope:
  include: ["*.example.com"]
  exclude: ["admin.example.com"]
  excluded_paths: ["/logout"]
  excluded_ips: ["192.0.2.0/24"]
  allow_apex: true
```

---

## Safety model

- Every host/URL/IP is validated against scope before an active module runs.
- Destructive checks are disabled by default; aggressive nuclei tags require an
  explicit opt-in (`nuclei.aggressive: true`).
- Logs are JSON on disk with automatic **secret redaction** (tokens, keys, JWTs,
  private keys, authorization headers).
- Findings are labeled `DETECTED / POTENTIAL / INFORMATIONAL /
  NEEDS_MANUAL_VERIFICATION`; automation never claims confirmed exploitation.
- Global **emergency stop** via `hunterx stop` (cooperative, cross-process).

---

## Development

```bash
make dev        # create .venv and install with dev extras
make test       # pytest
make lint       # ruff (if installed)
make doctor     # hunterx doctor
make run TARGET=--target=example.com
```

Requires Python ≥ 3.12. Core runtime deps: `PyYAML`, `rich`. No hard dependency
on any external security tool.

## License & ethics

MIT. Designed for authorized security research only. You are responsible for
ensuring every configured target is within your legal authorization.