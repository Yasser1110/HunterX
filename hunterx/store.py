"""High-level repository helpers over the SQLite Database.

Keeps :mod:`hunterx.database` low-level and puts the domain operations
(URLs, ports, technologies, findings, CVEs, deltas) here so the backend
can be swapped later without touching callers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from .database import Database, utcnow


def fingerprint(*parts: str) -> str:
    """Deterministic finding id derived from asset + vuln + endpoint + context."""
    joined = "|".join("" if p is None else str(p).strip().lower() for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


class Store:
    def __init__(self, db: Database) -> None:
        self.db = db

    # -- assets ---------------------------------------------------------
    def _asset_id(self, host: str) -> int:
        """Resolve (creating if needed) the asset row id for a host."""
        return int(self.db.upsert_asset(host))

    # -- URLs ---------------------------------------------------------
    def upsert_url(self, url: str, *, host: str | None = None, scheme: str | None = None,
                   path: str | None = None, method: str = "GET", status_code: int | None = None,
                   source: str | None = None) -> int:
        now = utcnow()
        existing = self.db.query("SELECT id, host FROM urls WHERE url=?", (url,))
        if existing:
            url_id = existing[0]["id"]
            self.db.execute(
                "UPDATE urls SET last_seen=?, status_code=COALESCE(?,status_code) WHERE id=?",
                (now, status_code, url_id),
            )
            return int(url_id)
        cur = self.db.execute(
            "INSERT INTO urls(url,host,scheme,path,method,status_code,source,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (url, host or "", scheme, path, method, status_code, source, now, now),
        )
        return int(cur.lastrowid)

    def urls(self, host: str | None = None, *, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM urls"
        params: list[Any] = []
        if host:
            sql += " WHERE host=?"
            params.append(host)
        sql += " ORDER BY last_seen DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [dict(r) for r in self.db.query(sql, params)]

    def url_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM urls", default=0))

    # -- ports --------------------------------------------------------
    def upsert_port(self, host: str, port: int, *, protocol: str | None = None,
                    service: str | None = None, version: str | None = None) -> int:
        now = utcnow()
        existing = self.db.query("SELECT id FROM ports WHERE host=? AND port=?", (host, port))
        if existing:
            self.db.execute("UPDATE ports SET last_seen=? WHERE id=?", (now, existing[0]["id"]))
            return int(existing[0]["id"])
        cur = self.db.execute(
            "INSERT INTO ports(host,port,protocol,service,version,asset_id,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (host, port, protocol, service, version, self._asset_id(host), now, now),
        )
        return int(cur.lastrowid)

    def ports(self, host: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM ports"
        params: list[Any] = []
        if host:
            sql += " WHERE host=?"
            params.append(host)
        sql += " ORDER BY port"
        return [dict(r) for r in self.db.query(sql, params)]

    def port_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM ports", default=0))

    # -- technologies -------------------------------------------------
    def upsert_technology(self, host: str, technology: str, *, version: str | None = None,
                          confidence: str = "low") -> int:
        now = utcnow()
        existing = self.db.query("SELECT id FROM technologies WHERE host=? AND technology=?",
                                 (host, technology))
        if existing:
            self.db.execute("UPDATE technologies SET version=COALESCE(?,version), confidence=? WHERE id=?",
                            (version, confidence, existing[0]["id"]))
            return int(existing[0]["id"])
        cur = self.db.execute(
            "INSERT INTO technologies(host,technology,version,confidence,asset_id,first_seen)"
            " VALUES(?,?,?,?,?,?)",
            (host, technology, version, confidence, self._asset_id(host), now),
        )
        return int(cur.lastrowid)

    def technologies(self, host: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM technologies"
        params: list[Any] = []
        if host:
            sql += " WHERE host=?"
            params.append(host)
        sql += " ORDER BY technology"
        return [dict(r) for r in self.db.query(sql, params)]

    def technology_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM technologies", default=0))

    # -- parameters ---------------------------------------------------
    def upsert_parameter(self, endpoint: str, parameter: str, *, method: str = "GET",
                         source: str = "crawler") -> int:
        now = utcnow()
        existing = self.db.query(
            "SELECT id FROM parameters WHERE endpoint=? AND parameter=? AND method=? AND source=?",
            (endpoint, parameter, method, source),
        )
        if existing:
            return int(existing[0]["id"])
        cur = self.db.execute(
            "INSERT INTO parameters(endpoint,parameter,method,source,first_seen) VALUES(?,?,?,?,?)",
            (endpoint, parameter, method, source, now),
        )
        return int(cur.lastrowid)

    def parameters(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM parameters ORDER BY endpoint")]

    def parameter_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM parameters", default=0))

    # -- findings -----------------------------------------------------
    def upsert_finding(self, *, asset: str, url: str | None = None, type_: str,
                       severity: str = "info", confidence: str = "low", source: str = "hunterx",
                       status: str = "needs_manual_verification", evidence: dict | None = None,
                       parameter: str | None = None, template: str | None = None,
                       cve: str | None = None, method: str = "GET") -> tuple[str, bool]:
        """Insert or update a finding keyed by fingerprint. Returns (id, is_new)."""
        fid = fingerprint(asset, type_, url or "", parameter or "", template or "", cve or "")
        now = utcnow()
        existing = self.db.query("SELECT id FROM findings WHERE id=?", (fid,))
        if existing:
            # If the finding matures (e.g. duplicate -> detected), raise confidence.
            self.db.execute(
                "UPDATE findings SET last_seen=?, confidence=CASE WHEN ?>confidence THEN ? ELSE confidence END "
                "WHERE id=?",
                (now, confidence, confidence, fid),
            )
            return fid, False
        self.db.execute(
            "INSERT INTO findings(id,fingerprint,asset,url,type,severity,confidence,status,source,"
            "first_seen,last_seen,evidence,cve) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, fid, asset, url, type_, severity, confidence, status, source, now, now,
             json.dumps(evidence or {}), cve),
        )
        return fid, True

    def upsert_finding_raw(self, finding_id: str, **cols: Any) -> None:
        existing = self.db.query("SELECT id FROM findings WHERE id=?", (finding_id,))
        if existing:
            self.db.execute(
                "UPDATE findings SET last_seen=?, status=COALESCE(?,status) WHERE id=?",
                (utcnow(), cols.get("status"), finding_id),
            )
            return
        now = utcnow()
        self.db.execute(
            "INSERT INTO findings(id,fingerprint,asset,url,type,severity,confidence,status,source,"
            "first_seen,last_seen,evidence,cve) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding_id, finding_id, cols.get("asset", ""), cols.get("url"), cols.get("type"),
             cols.get("severity", "info"), cols.get("confidence", "low"),
             cols.get("status", "needs_manual_verification"), cols.get("source", "hunterx"),
             now, now, json.dumps(cols.get("evidence", {}) or {}), cols.get("cve")),
        )

    def findings(self, *, status: str | None = None, severity: str | None = None,
                 limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings"
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY last_seen DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        rows = []
        for r in self.db.query(sql, params):
            d = dict(r)
            try:
                d["evidence"] = json.loads(d.get("evidence") or "{}")
            except (TypeError, json.JSONDecodeError):
                d["evidence"] = {}
            rows.append(d)
        return rows

    def findings_meta(self) -> tuple[str, dict[str, int]]:
        """(total, {severity: count}) across open findings."""
        rows = self.db.query(
            "SELECT severity, COUNT(*) AS n FROM findings "
            "WHERE status NOT IN ('false_positive','resolved') GROUP BY severity"
        )
        total = 0
        by_sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in rows:
            sev = str(r["severity"] or "info").lower()
            count = int(r["n"])
            by_sev[sev] = by_sev.get(sev, 0) + count
            total += count
        return total, by_sev

    def finding_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM findings", default=0))

    # -- CVEs ---------------------------------------------------------
    def upsert_cve(self, cve_id: str, *, description: str | None = None, severity: str | None = None,
                   cvss: float | None = None, cisa_kev: bool = False, affected: str | None = None,
                   remediation: str | None = None, source: str | None = None) -> int:
        existing = self.db.query("SELECT id FROM cves WHERE id=?", (cve_id,))
        if existing:
            self.db.execute(
                "UPDATE cves SET description=COALESCE(?,description), severity=COALESCE(?,severity),"
                " cvss=COALESCE(?,cvss), cisa_kev=?, affected=COALESCE(?,affected), remediation=COALESCE(?,remediation)"
                " WHERE id=?",
                (description, severity, cvss, 1 if cisa_kev else 0, affected, remediation, cve_id),
            )
            return int(existing[0]["id"])
        cur = self.db.execute(
            "INSERT INTO cves(id,description,severity,cvss,cisa_kev,affected,remediation,first_seen,source)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (cve_id, description, severity, cvss, 1 if cisa_kev else 0, affected, remediation,
             utcnow(), source or "intel"),
        )
        return int(cur.lastrowid)

    def cves(self, *, limit: int | None = None, kev_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cves"
        params: list[Any] = []
        if kev_only:
            sql += " WHERE cisa_kev=1"
        sql += " ORDER BY first_seen DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [dict(r) for r in self.db.query(sql, params)]

    def cve_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM cves", default=0))

    # -- AI triage notes ------------------------------------------------
    def set_ai_note(self, finding_id: str, note: str) -> None:
        self.db.execute("UPDATE findings SET ai_note=? WHERE id=?", (str(note)[:600], finding_id))

    # -- delta support -------------------------------------------------
    def seen_before(self, table: str, column: str, value: str) -> bool:
        safe = table if table in {"assets", "urls", "ports", "technologies", "findings"} else "assets"
        safe_col = column if column in {"fqdn", "url", "host", "technology", "id"} else "id"
        return bool(self.db.scalar(f"SELECT 1 FROM {safe} WHERE {safe_col}=? LIMIT 1", (value,), default=0))

    def counts(self) -> dict[str, int]:
        return {
            "assets": int(self.db.scalar("SELECT COUNT(*) FROM assets", default=0)),
            "urls": self.url_count(),
            "ports": self.port_count(),
            "technologies": self.technology_count(),
            "parameters": self.parameter_count(),
            "findings": self.finding_count(),
            "cves": self.cve_count(),
        }

    def url_hosts(self) -> list[str]:
        rows = self.db.query("SELECT DISTINCT host FROM urls ORDER BY host")
        return [str(r["host"]) for r in rows if r["host"]]

    # -- deltas --------------------------------------------------------
    def upsert_delta(self, run_id: str, scope: str, *, added: int = 0, removed: int = 0,
                     changed: int = 0, detail: dict | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO deltas(run_id, scope, added, removed, changed, detail, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (run_id, scope, added, removed, changed, json.dumps(detail or {}), utcnow()),
        )
        return int(cur.lastrowid)

    def deltas(self, run_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM deltas"
        params: list[Any] = []
        if run_id:
            sql += " WHERE run_id=?"
            params.append(run_id)
        sql += " ORDER BY id"
        return [dict(r) for r in self.db.query(sql, params)]