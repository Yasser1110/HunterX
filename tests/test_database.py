from hunterx.database import Database, DatabaseError, PHASES


def test_migrate_is_idempotent(db_path):
    db = Database(db_path)
    v1 = db.schema_version
    db2 = Database(db_path)
    assert db2.schema_version == v1 >= 1
    assert db.asset_count() == 0
    db.close()


def test_scan_run_lifecycle(db_path):
    db = Database(db_path)
    run_id = db.create_scan_run("example.com", "balanced")
    assert run_id.startswith("RUN-")
    run = db.get_run(run_id)
    assert run["status"] == "running"
    assert run["profile"] == "balanced"
    assert set(run["phases"]) == set(PHASES)
    db.mark_phase(run_id, "scope", "done")
    db.mark_phase(run_id, "discovery", "failed")
    assert db.run_phases(run_id)["scope"] == "done"
    assert db.run_phases(run_id)["discovery"] == "failed"
    db.finish_run(run_id, "finished")
    assert db.get_run(run_id)["status"] == "finished"
    db.close()


def test_unknown_phase_raises(db_path):
    db = Database(db_path)
    run_id = db.create_scan_run("example.com", "safe")
    try:
        db.mark_phase(run_id, "nonsense", "done")
        assert False, "expected DatabaseError"
    except DatabaseError:
        pass
    db.close()


def test_asset_upsert(db_path):
    db = Database(db_path)
    a1 = db.upsert_asset("api.example.com", ip="1.2.3.4", source="subfinder")
    a1b = db.upsert_asset("api.example.com", source="crtsh")
    assert a1 == a1b  # same row
    assert db.asset_count() == 1
    db.upsert_asset("dev.example.com")
    assert db.asset_count() == 2
    assets = db.assets()
    assert len(assets) == 2
    db.close()


def test_tool_run_tracked(db_path):
    db = Database(db_path)
    run_id = db.create_scan_run("example.com", "balanced")
    tr = db.record_tool_run(run_id, "subfinder", command="subfinder -d example.com", target="example.com")
    db.finish_tool_run(tr, exit_code=2, output_file="/tmp/x.txt", duration_ms=123)
    rows = db.query("SELECT * FROM tool_runs WHERE id=?", (tr,))
    assert rows[0]["status"] == "failed"
    assert rows[0]["exit_code"] == 2
    db.close()


def test_unique_port_and_url(db_path):
    db = Database(db_path)
    db.upsert_asset("example.com")
    # urls are unique
    db.execute("INSERT INTO urls(url, host, first_seen, last_seen) VALUES('https://example.com/a','example.com','t','t')")
    try:
        db.execute("INSERT INTO urls(url, host, first_seen, last_seen) VALUES('https://example.com/a','example.com','t','t')")
        assert False, "expected unique constraint error"
    except DatabaseError:
        pass
    db.close()