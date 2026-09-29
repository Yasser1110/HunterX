"""Wordlist resolution/loading tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.config import Config, ConfigError
from hunterx.wordlists import DEFAULT_WORDS, load, resolve


def _make_tree(base: Path) -> Path:
    wc = base / "SL" / "Discovery" / "Web-Content"
    other = base / "SL" / "Misc"
    wc.mkdir(parents=True, exist_ok=True)
    other.mkdir(parents=True, exist_ok=True)
    (wc / "common.txt").write_text("# comment\nadmin\napi\n\nrobots.txt\n", encoding="utf-8")
    (wc / "raft-medium-directories.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    (other / "raft-large-directories.txt").write_text("gamma\ndelta\n", encoding="utf-8")
    return base / "SL"


def test_resolve_relative_path(tmp_path):
    base = _make_tree(tmp_path)
    found = resolve(base, "Discovery/Web-Content/common.txt")
    assert found and found.is_file()


def test_resolve_bare_filename_web_content_preferred(tmp_path):
    base = _make_tree(tmp_path)
    found = resolve(base, "common.txt")
    assert found and found.name == "common.txt"


def test_resolve_bare_filename_anywhere_under_base(tmp_path):
    base = _make_tree(tmp_path)
    found = resolve(base, "raft-large-directories.txt")
    assert found and found.parent.name == "Misc"
    assert "Web-Content" not in str(found)


def test_resolve_absolute_path(tmp_path):
    base = _make_tree(tmp_path)
    target = base / "Discovery" / "Web-Content" / "common.txt"
    assert resolve(tmp_path, str(target)) == target


def test_resolve_home_expansion(tmp_path, monkeypatch):
    base = _make_tree(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "fakehome"))
    fake = Path(tmp_path / "fakehome" / "wl.txt")
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("x\n", encoding="utf-8")
    assert resolve(tmp_path, "~/wl.txt") == fake.resolve()


def test_resolve_missing_returns_none(tmp_path):
    assert resolve(_make_tree(tmp_path), "no-such-file.txt") is None
    assert resolve(_make_tree(tmp_path), None) is None
    assert resolve(None, "common.txt") is None


def test_load_strips_comments_and_blanks(tmp_path):
    base = _make_tree(tmp_path)
    words = load(resolve(base, "common.txt"))
    assert words == ["admin", "api", "robots.txt"]
    assert load(Path("/nope/none.txt")) == DEFAULT_WORDS


def test_load_blank_file_falls_back(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("# only a comment\n", encoding="utf-8")
    assert load(path) == DEFAULT_WORDS


def test_doctor_and_config_accept_sec_lists_base(tmp_path):
    base = _make_tree(tmp_path)
    cfgfile = tmp_path / "config.yaml"
    cfgfile.write_text(
        f"target:\n  domain: example.com\n"
        f"wordlists:\n  base_dir: {base}\n"
        f"  tiers:\n    small: common.txt\n"
        f"    medium: raft-medium-directories.txt\n"
        f"    large: raft-large-directories.txt\n",
        encoding="utf-8",
    )
    cfg = Config.load(str(cfgfile))
    assert resolve(cfg.paths.wordlists, cfg.wordlists_cfg()["tiers"]["small"]) is not None
    assert cfg.paths.wordlists == base.resolve()


def test_absolute_base_dir_via_config(tmp_path):
    base = _make_tree(tmp_path)
    cfgfile = tmp_path / "config.yaml"
    cfgfile.write_text(
        f"target:\n  domain: example.com\nwordlists:\n  base_dir: {base / 'Discovery' / 'Web-Content'}\n"
        f"  tiers:\n    small: common.txt\n",
        encoding="utf-8",
    )
    cfg = Config.load(str(cfgfile))
    assert cfg.paths.wordlists == (base / "Discovery" / "Web-Content").resolve()