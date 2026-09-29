"""AI triage phase tests: disabled/offline/mock endpoint behaviour.

Verifies the phase is a graceful no-op when disabled, when no API key is
present, or when the endpoint errors, and that a healthy endpoint attaches
notes back to the right findings (never raising).
"""

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_analysis import make_ctx

from hunterx.analysis import ai


class _AIHandler(BaseHTTPRequestHandler):
    ok = True
    received = None

    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.__class__.received = request
        if not self.__class__.ok:
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = json.loads(request["messages"][1]["content"])
        ids = [f["id"] for f in payload["findings"]]
        notes = {fid: {"assessment": f"Potential risk {i}", "next_step": "Rotate if live"}
                 for i, fid in enumerate(ids)}
        payload = json.dumps({"choices": [{"message": {"content": json.dumps(notes)}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _AIHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _seed(ctx, n=2):
    for i in range(n):
        ctx.store.upsert_finding(asset=f"a{i}.example.com", type_="TRIAGE", severity="medium",
                                 confidence="high", source="t", status="needs_manual_verification")
    return [f["id"] for f in ctx.store.findings()]


def test_ai_disabled_returns_zero(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    try:
        ctx.store.upsert_finding(asset="a.example.com", type_="TRIAGE", severity="low",
                                 confidence="low", source="t", status="needs_manual_verification")
        assert asyncio.run(ai.run(ctx)) == 0
        assert all(not f.get("ai_note") for f in ctx.store.findings())
    finally:
        ctx.db.close()


def test_ai_missing_key_returns_zero(tmp_path):
    _AIHandler.ok = True
    httpd = _server()
    try:
        port = httpd.server_address[1]
        ctx = make_ctx(tmp_path, overrides={"ai": {"enabled": True, "base_url": f"http://127.0.0.1:{port}"}})
        try:
            _seed(ctx)
            assert os.environ.get("OPENAI_API_KEY") is None
            assert asyncio.run(ai.run(ctx)) == 0
        finally:
            ctx.db.close()
    finally:
        httpd.shutdown()


def test_ai_stamps_notes_from_endpoint(tmp_path, monkeypatch):
    _AIHandler.ok = True
    httpd = _server()
    try:
        port = httpd.server_address[1]
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        ctx = make_ctx(tmp_path, overrides={"ai": {"enabled": True, "base_url": f"http://127.0.0.1:{port}"}})
        try:
            ids = _seed(ctx)
            assert asyncio.run(ai.run(ctx)) == 2
            stored = {f["id"]: f for f in ctx.store.findings()}
            for fid in ids:
                assert "Potential risk" in stored[fid]["ai_note"]
            assert _AIHandler.received["model"] != ""
            assert _AIHandler.received["messages"][0]["role"] == "system"
        finally:
            ctx.db.close()
    finally:
        httpd.shutdown()


def test_ai_endpoint_error_is_graceful(tmp_path, monkeypatch):
    _AIHandler.ok = False
    httpd = _server()
    try:
        port = httpd.server_address[1]
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        ctx = make_ctx(tmp_path, overrides={"ai": {"enabled": True, "base_url": f"http://127.0.0.1:{port}"}})
        try:
            ids = _seed(ctx)
            assert asyncio.run(ai.run(ctx)) == 0
            assert all(not f.get("ai_note") for f in ctx.store.findings() if f["id"] in ids)
        finally:
            ctx.db.close()
    finally:
        httpd.shutdown()