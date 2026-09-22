"""Persistence layer (SQLite now, Postgres-ready later).

Versioned migrations live in :data:`MIGRATIONS` and are applied in order;
a ``schema_migrations`` table tracks the applied version. All repository
methods are plain methods on :class:`Database` so the backend can later be
swapped behind the same surface.

Concurrency model: one connection per thread (``threading.local``), WAL
journal for concurrent readers/writers, foreign keys enforced.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PHASES = [
    "scope",
    "discovery",
    "dns",
    "http",
    "ports",
    "fingerprinting",
    "urls",
    "javascript",
    "parameters",
    "fuzzing",
    "scanners",
    "cve",
    "dedup",
    "evidence",
    "prioritization",
    "ai",
    "reporting",
    "notification",
]

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    wildcard    TEXT,
    program     TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn        TEXT NOT NULL UNIQUE,
    ip          TEXT,
    source      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    metadata    TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_fqdn ON assets(fqdn);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    UNIQUE(asset_id, type, value)
);

CREATE TABLE IF NOT EXISTS ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT,
    service     TEXT,
    version     TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS technologies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    technology  TEXT NOT NULL,
    version     TEXT,
    confidence  TEXT DEFAULT 'low',
    first_seen  TEXT NOT NULL,
    UNIQUE(host, technology)
);

CREATE TABLE IF NOT EXISTS urls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL UNIQUE,
    host        TEXT NOT NULL,
    scheme      TEXT,
    path        TEXT,
    method      TEXT DEFAULT 'GET',
    status_code INTEGER,
    source      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);

CREATE TABLE IF NOT EXISTS parameters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint    TEXT NOT NULL,
    parameter   TEXT NOT NULL,
    method      TEXT DEFAULT 'GET',
    source      TEXT,
    first_seen  TEXT NOT NULL,
    UNIQUE(endpoint, parameter, method, source)
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    fingerprint TEXT,
    asset       TEXT,
    url         TEXT,
    type        TEXT,
    severity    TEXT,
    confidence  TEXT,
    status      TEXT NOT NULL DEFAULT 'new',
    source      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    evidence    TEXT,
    cve         TEXT,
    priority    REAL DEFAULT 0,
    ai_note     TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS cves (
    id              TEXT PRIMARY KEY,
    description     TEXT,
    severity        TEXT,
    cvss            REAL,
    cisa_kev        INTEGER DEFAULT 0,
    affected        TEXT,
    remediation     TEXT,
    first_seen      TEXT NOT NULL,
    source          TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    profile     TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    phases      TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT REFERENCES scan_runs(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    command     TEXT,
    target      TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    exit_code   INTEGER,
    status      TEXT DEFAULT 'running',
    output_file TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT,
    channel     TEXT,
    kind        TEXT,
    payload     TEXT,
    sent_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deltas (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    scope       TEXT NOT NULL,
    added       INTEGER NOT NULL DEFAULT 0,
    removed     INTEGER NOT NULL DEFAULT 0,
    changed     INTEGER NOT NULL DEFAULT 0,
    detail      TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    run_id      TEXT NOT NULL,
    scope       TEXT NOT NULL,
    ids         TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY(run_id, scope)
);
"""


def _migrate_v2(conn: sqlite3.Connection) -> None:
    """Idempotent column/table additions for databases already at v1."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(cves)")]
    if "source" not in cols:
        conn.execute("ALTER TABLE cves ADD COLUMN source TEXT")
    fcols = [r[1] for r in conn.execute("PRAGMA table_info(findings)")]
    if "priority" not in fcols:
        conn.execute("ALTER TABLE findings ADD COLUMN priority REAL DEFAULT 0")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS deltas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id      TEXT NOT NULL,
            scope       TEXT NOT NULL,
            added       INTEGER NOT NULL DEFAULT 0,
            removed     INTEGER NOT NULL DEFAULT 0,
            changed     INTEGER NOT NULL DEFAULT 0,
            detail      TEXT,
            created_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            run_id      TEXT NOT NULL,
            scope       TEXT NOT NULL,
            ids         TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            PRIMARY KEY(run_id, scope)
        );
        """
    )


def _migrate_v3(conn: sqlite3.Connection) -> None:
    """Idempotent column additions for databases already at v2 (AI phase)."""
    fcols = [r[1] for r in conn.execute("PRAGMA table_info(findings)")]
    if "ai_note" not in fcols:
        conn.execute("ALTER TABLE findings ADD COLUMN ai_note TEXT")


MIGRATIONS: dict[int, object] = {
    1: SCHEMA_V1,
    2: _migrate_v2,
    3: _migrate_v3,
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DatabaseError(Exception):
    pass


class Database:
    """SQLite-backed repository. One connection per thread."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._migrate()

    # -- connections ---------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        try:
            cur = self._conn().execute(sql, tuple(params))
            self._conn().commit()
            return cur
        except sqlite3.Error as exc:
            raise DatabaseError(f"{exc} (sql: {sql[:80]}...)") from exc

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        try:
            cur = self._conn().execute(sql, tuple(params))
            return cur.fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def scalar(self, sql: str, params: Iterable[Any] = (), default: Any = None) -> Any:
        row = self.query(sql, params)
        return row[0][0] if row else default

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- migrations ----------------------------------------------------
    def _migrate(self) -> None:
        with self._write_lock:
            conn = self._conn()
            try:
                conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
                current = conn.execute("SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0]
                for version in sorted(MIGRATIONS):
                    if version > current:
                        entry = MIGRATIONS[version]
                        if isinstance(entry, str):
                            conn.executescript(entry)
                        else:
                            entry(conn)
                        conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)", (version, utcnow()))
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                raise DatabaseError(f"migration failed: {exc}") from exc

    @property
    def schema_version(self) -> int:
        return int(self.scalar("SELECT COALESCE(MAX(version),0) FROM schema_migrations", default=0))

    # -- scan runs -----------------------------------------------------
    def create_scan_run(self, target: str, profile: str) -> str:
        """Create a run, assign ``RUN-YYYY-MM-DD-NNN``, reset phase states."""
        today = date.today().isoformat()
        with self._write_lock:
            seq = int(self.scalar(
                "SELECT COUNT(*) FROM scan_runs WHERE id LIKE ?", (f"RUN-{today}-%",), default=0
            )) + 1
            run_id = f"RUN-{today}-{seq:03d}"
            phases = {name: "pending" for name in PHASES}
            phases["scope"] = "dry"  # set to 'done' once Phase 0 passes
            self.execute(
                "INSERT INTO scan_runs(id, target, profile, status, phases, started_at) VALUES(?,?,?,?,?,?)",
                (run_id, target, profile, "running", json.dumps(phases), utcnow()),
            )
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM scan_runs WHERE id=?", (run_id,))
        return self._run_row(rows[0]) if rows else None

    def list_runs(self, incomplete_only: bool = False, limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM scan_runs"
        if incomplete_only:
            sql += " WHERE status IN ('running','interrupted')"
        sql += " ORDER BY started_at DESC LIMIT ?"
        return [self._run_row(r) for r in self.query(sql, (limit,))]

    def finish_run(self, run_id: str, status: str = "finished", finished_at: str | None = None) -> None:
        if status not in {"finished", "failed", "interrupted", "stopped"}:
            raise DatabaseError(f"invalid run status {status!r}")
        self.execute(
            "UPDATE scan_runs SET status=?, finished_at=? WHERE id=?",
            (status, finished_at or utcnow(), run_id),
        )

    def run_phases(self, run_id: str) -> dict[str, str]:
        run = self.get_run(run_id)
        if not run:
            raise DatabaseError(f"no such run {run_id!r}")
        return run["phases"]

    def mark_phase(self, run_id: str, phase: str, state: str = "done") -> None:
        if phase not in PHASES:
            raise DatabaseError(f"unknown phase {phase!r}")
        states = {"done", "failed", "pending", "skipped", "running"}
        if state not in states:
            raise DatabaseError(f"invalid phase state {state!r}")
        phases = self.run_phases(run_id)
        phases[phase] = state
        self.execute("UPDATE scan_runs SET phases=? WHERE id=?", (json.dumps(phases), run_id))

    # -- tool runs -----------------------------------------------------
    def record_tool_run(self, run_id: str, tool: str, *, command: str | None = None,
                        target: str | None = None) -> int:
        cur = self.execute(
            "INSERT INTO tool_runs(run_id, tool, command, target, started_at, status) VALUES(?,?,?,?,?,?)",
            (run_id, tool, command, target, utcnow(), "running"),
        )
        return int(cur.lastrowid)

    def finish_tool_run(self, tool_run_id: int, *, exit_code: int | None = None,
                        output_file: str | None = None, duration_ms: int | None = None,
                        status: str | None = None) -> None:
        if status is None:
            status = "ok" if exit_code == 0 else "failed"
        self.execute(
            "UPDATE tool_runs SET exit_code=?, output_file=?, duration_ms=?, finished_at=?, status=? WHERE id=?",
            (exit_code, output_file, duration_ms, utcnow(), status, tool_run_id),
        )

    # -- assets --------------------------------------------------------
    def upsert_asset(self, fqdn: str, *, ip: str | None = None, source: str | None = None) -> int:
        now = utcnow()
        existing = self.query("SELECT id FROM assets WHERE fqdn=?", (fqdn,))
        if existing:
            asset_id = existing[0]["id"]
            self.execute(
                "UPDATE assets SET last_seen=?, ip=COALESCE(?,ip), status=CASE WHEN status='new' THEN status ELSE 'seen' END WHERE id=?",
                (now, ip, asset_id),
            )
            return int(asset_id)
        cur = self.execute(
            "INSERT INTO assets(fqdn, ip, source, first_seen, last_seen, status) VALUES(?,?,?,?,?,?)",
            (fqdn, ip, source, now, now, "new"),
        )
        return int(cur.lastrowid)

    def assets(self, *, status: str | None = None, limit: int | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM assets"
        params: list[Any] = []
        if status:
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY last_seen DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return self.query(sql, params)

    def asset_count(self) -> int:
        return int(self.scalar("SELECT COUNT(*) FROM assets", default=0))

    # -- helpers -------------------------------------------------------
    @staticmethod
    def _run_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        try:
            data["phases"] = json.loads(data.get("phases") or "{}")
        except (TypeError, json.JSONDecodeError):
            data["phases"] = {}
        return data