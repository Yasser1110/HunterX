"""Store/domain-layer tests: fingerprinting, finding dedup, migrations, deltas."""

import pytest
from hunterx.database import Database, utcnow
from hunterx.store import Store, fingerprint


@pytest.fixture
def store(db_path):
    db = Database(db_path)
    yield Store(db)
    db.close()


def test_fingerprint_is_deterministic_and_position_sensitive():
    a = fingerprint("host", "TYPE", "https://h/x")
    assert a == fingerprint("host", "TYPE", "https://h/x")
    assert a != fingerprint("host", "TYPE", "https://h/y")
    assert a != fingerprint("host", "TYPE2", "https://h/x")


def test_upsert_finding_new_then_duplicate(store):
    fid, is_new = store.upsert_finding(
        asset="a.example.com", type_="TEST_FINDING", severity="medium",
        confidence="potential", source="t", status="needs_manual_verification")
    assert is_new is True
    assert len(fid) == 16
    _fid2, is_new2 = store.upsert_finding(
        asset="a.example.com", type_="TEST_FINDING", severity="medium",
        confidence="potential", source="t", status="needs_manual_verification")
    assert is_new2 is False


def test_upsert_url_updates_and_counts(store):
    store.upsert_url("https://a.example.com/x", host="a.example.com", source="probe", status_code=200)
    store.upsert_url("https://a.example.com/x", host="a.example.com", status_code=301)
    assert store.url_count() == 1
    assert store.urls(host="a.example.com")[0]["status_code"] == 301


def test_counts_include_new_tables(store):
    store.upsert_port("a.example.com", 443, service="https")
    store.upsert_technology("a.example.com", "Nginx", version="1.2.3")
    store.upsert_parameter("https://a.example.com/", "id", method="GET", source="crawler")
    counts = store.counts()
    assert counts["ports"] == 1
    assert counts["technologies"] == 1
    assert counts["parameters"] == 1


def test_migrations_add_source_and_priority(db_path):
    db = Database(db_path)
    assert db.schema_version == 3
    cols = [r[1] for r in db.query("PRAGMA table_info(cves)")]
    assert "source" in cols
    fcols = [r[1] for r in db.query("PRAGMA table_info(findings)")]
    assert "priority" in fcols
    db.close()


def test_delta_roundtrip(store):
    store.upsert_delta("RUN-test", "urls", added=3, removed=1, changed=9)
    rows = store.deltas(run_id="RUN-test")
    assert len(rows) == 1
    assert rows[0]["added"] == 3
    assert rows[0]["removed"] == 1
    assert rows[0]["changed"] == 9


def test_upsert_cve_with_source_and_kev(store):
    store.upsert_cve("CVE-2021-23017", description="x", severity="high",
                     cvss=7.7, cisa_kev=True, source="cisa-kev")
    rows = store.cves(kev_only=True)
    assert len(rows) == 1
    assert rows[0]["cisa_kev"] == 1
    assert rows[0]["source"] == "cisa-kev"


def test_findings_meta_groups_by_severity(store):
    store.upsert_finding(asset="x", type_="A", severity="high", confidence="high", source="t")
    store.upsert_finding(asset="x", type_="B", severity="low", confidence="high", source="t")
    total, by_sev = store.findings_meta()
    assert total == 2
    assert by_sev["high"] == 1
    assert by_sev["low"] == 1