import os

import pytest

from hunterx.config import (Config, ConfigError, DEFAULT_CONFIG_YAML,
                            deep_merge, normalize_wildcard_target,
                            validate_hostname)


def test_normalize_wildcard():
    assert normalize_wildcard_target("*.example.com") == ("example.com", "*.example.com")
    assert normalize_wildcard_target("example.com") == ("example.com", None)
    assert normalize_wildcard_target("  HTTPS://API.Example.COM/ ") == ("api.example.com", None)
    assert normalize_wildcard_target("*.sub.example.com") == ("sub.example.com", "*.sub.example.com")


def test_validate_hostname():
    assert validate_hostname("example.com")
    assert validate_hostname("a-b.example.co.uk")
    assert not validate_hostname("bad host.com")
    assert not validate_hostname("")
    assert not validate_hostname("exa mple.com")


def test_deep_merge():
    base = {"a": {"b": 1, "c": 2}}
    merged = deep_merge(base, {"a": {"c": 9, "d": 3}})
    assert merged == {"a": {"b": 1, "c": 9, "d": 3}}
    assert base["a"]["c"] == 2  # original untouched


def test_defaults_loaded(tmp_base, monkeypatch):
    monkeypatch.setenv("HUNTERX_BASE", str(tmp_base))
    cfg = Config.load(base_dir=tmp_base)
    assert cfg.target.domain == "example.com"
    assert cfg.target.wildcard == "*.example.com"
    assert cfg.scan.mode == "balanced"
    assert cfg.scan.concurrency["http"] == 20


def test_profile_merge(tmp_base, monkeypatch):
    monkeypatch.setenv("HUNTERX_BASE", str(tmp_base))
    cfg = Config.load(base_dir=tmp_base)
    deep = cfg.profile_cfg("deep")
    assert deep["concurrency"]["http"] == 30
    assert deep["mode"] == "deep"
    balanced = cfg.profile_cfg("balanced")
    assert balanced["concurrency"]["http"] == 20


def test_invalid_profile_raises(tmp_base, monkeypatch):
    monkeypatch.setenv("HUNTERX_BASE", str(tmp_base))
    cfg = Config.load(base_dir=tmp_base)
    with pytest.raises(ConfigError):
        cfg.profile_cfg("ultra")


def test_config_error_on_unknown_mode(tmp_base):
    (tmp_base / "config" / "config.yaml").write_text(
        "target:\n  domain: example.com\nscan:\n  mode: turbo\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        Config.load(base_dir=tmp_base)


def test_invalid_target_rejected(tmp_base):
    (tmp_base / "config" / "config.yaml").write_text(
        "target:\n  domain: 'not a domain!!'\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        Config.load(base_dir=tmp_base)


def test_set_target_override(cfg):
    cfg.set_target("api.example.org", None)
    assert cfg.target.domain == "api.example.org"
    assert cfg.target.wildcard is None


def test_scope_overlay_file(tmp_base):
    (tmp_base / "config" / "scope.yaml").write_text(
        "scope:\n  exclude:\n    - deathstar.example.com\n", encoding="utf-8"
    )
    cfg = Config.load(base_dir=tmp_base)
    assert "deathstar.example.com" in cfg.scope_cfg()["exclude"]


def test_paths_from_project_section(tmp_base, monkeypatch):
    (tmp_base / "config" / "config.yaml").write_text(
        "project:\n  data_dir: customdata\n", encoding="utf-8"
    )
    monkeypatch.setenv("HUNTERX_BASE", str(tmp_base))
    cfg = Config.load(base_dir=tmp_base)
    assert cfg.paths.data.name == "customdata"