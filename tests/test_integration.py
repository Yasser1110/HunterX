"""End-to-end lab integration test.

Spins a tiny local HTTP server (stdlib only) on an ephemeral port and runs
the real pipeline phases (http -> urls -> scanners) against it through
``hunterx.scan.execute_scan``. Verifies probing, crawling, parameter
harvesting and scanner findings all persist correctly.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hunterx.config import Config, DEFAULTS, ProjectPaths, deep_merge
from hunterx.database import Database
from hunterx.scan import execute_scan
from hunterx.scope import Scope


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence request logging
        pass

    def _dispatch(self):
        if self.path.startswith("/app.js"):
            body = b'const t = "ghp_TESTTOKEN_123456789012345678"; //# sourceMappingURL=app.js.map'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/about":
            body = b'<html><body><h1>About</h1><form method="POST"><input name="comment"></form></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path in ("/", "/index.html"):
            body = b'<html><head><title>Lab Server</title></head><body><a href="/about">about</a><script src="/app.js"></script></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()


class _LabServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _make_lab_cfg(tmp_path, port: int) -> Config:
    base = tmp_path / "lab-project"
    raw = deep_merge(DEFAULTS, {
        "target": {"domain": "127.0.0.1", "wildcard": None},
        "http": {"ports": [port], "crawl": {"enabled": True, "max_pages": 10, "max_depth": 2}},
        "scan": {"mode": "balanced", "rate_limit": {"requests_per_second": 25}},
    })
    paths = ProjectPaths(base=base, data=base / "data", reports=base / "reports",
                         log_dir=base / "log", config_dir=base / "config",
                         wordlists=base / "wordlists")
    cfg = Config(raw, paths)
    cfg.set_target("127.0.0.1", None)
    assert Scope.from_config(cfg.scope_cfg(), cfg.target).is_allowed_host("127.0.0.1")
    return cfg


def test_full_lab_scan(tmp_path):
    with _LabServer() as lab:
        cfg = _make_lab_cfg(tmp_path, lab.port)

        # seed an asset + run record on the real DB path
        db = Database(cfg.paths.data / "hunterx.db")
        db.upsert_asset("127.0.0.1", source="test")
        run_id = db.create_scan_run("127.0.0.1", "balanced")
        db.mark_phase(run_id, "scope", "done")
        db.close()

        summary = asyncio.run(
            execute_scan(
                cfg,
                run_id=run_id, target="127.0.0.1", profile="balanced",
                phases=["http", "urls", "scanners"],
            )
        )

        assert summary["status"] == "finished"
        for phase in ("http", "urls", "scanners"):
            assert summary["phases"][phase]["state"] == "done"

        db = Database(cfg.paths.data / "hunterx.db")
        try:
            urls = db.query("SELECT * FROM urls")
            assert any(str(r["url"]).startswith(f"http://127.0.0.1:{lab.port}/") for r in urls)
            assert any(str(r["url"]).endswith("/about") for r in urls)

            params = db.query("SELECT * FROM parameters")
            assert any(r["parameter"] == "comment" and r["source"] == "crawler" for r in params)

            findings = db.query("SELECT * FROM findings")
            kinds = {r["type"] for r in findings}
            assert "MISSING_SECURITY_HEADER" in kinds

            run = db.get_run(run_id)
            assert run["status"] == "finished"
            assert {p: s for p, s in run["phases"].items() if p in ("http", "urls", "scanners")} \
                == {"http": "done", "urls": "done", "scanners": "done"}
        finally:
            db.close()


def test_resume_skips_done_phases(tmp_path):
    with _LabServer() as lab:
        cfg = _make_lab_cfg(tmp_path, lab.port)
        db = Database(cfg.paths.data / "hunterx.db")
        db.upsert_asset("127.0.0.1", source="test")
        run_id = db.create_scan_run("127.0.0.1", "balanced")
        db.mark_phase(run_id, "scope", "done")
        db.mark_phase(run_id, "http", "done")
        db.close()

        summary = asyncio.run(
            execute_scan(cfg, run_id=run_id, target="127.0.0.1", profile="balanced",
                         phases=["http", "urls"], resume=True)
        )
        # http was already done -> skipped, still marked done
        assert summary["phases"]["http"] == "done"
        assert summary["status"] == "finished"