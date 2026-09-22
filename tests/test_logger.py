import logging
import re

from hunterx.logger import JsonFormatter, RedactionFilter, redact, setup_logging


def test_redact_aws_key():
    out = redact("key=AKIAIOSFODNN7EXAMPLE hey")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "AKIA" in out


def test_redact_bearer_token():
    out = redact("Authorization: Bearer abcdef1234567890 secret")
    assert "abcdef1234567890" not in out
    assert "Authorization" in out


def test_redact_jwt_and_private_key():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    out = redact(f"token {jwt}")
    assert "eyJhbGci" not in out
    key = "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----"
    out = redact(key)
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert "REDACTED" in out


def test_redact_github_token():
    out = redact("ghp_1234567890abcdefghijklmn")
    assert "ghp_1234567890abcdefghijklmn" not in out
    assert "ghp_" in out


def test_filter_redacts_record():
    record = logging.LogRecord("t", logging.INFO, __file__, 1,
                               "password: hunter2", (), None)
    ok = RedactionFilter().filter(record)
    assert ok
    assert "hunter2" not in record.msg


def test_json_formatter_output():
    handler = logging.StreamHandler()
    record = logging.LogRecord("hunterx", logging.INFO, __file__, 1,
                               "scan started", (), None)
    record.run_id = "RUN-1"
    out = JsonFormatter().format(record)
    assert '"run_id": "RUN-1"' in out
    assert '"level": "INFO"' in out


def test_setup_logging(tmp_path):
    log = setup_logging(tmp_path, level="DEBUG")
    log.info("hello %s", "there")
    logfile = tmp_path / "hunterx.log"
    assert logfile.exists()
    content = logfile.read_text(encoding="utf-8")
    assert "hello there" in content