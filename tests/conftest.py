import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hunterx.config import Config, ProjectPaths, DEFAULT_CONFIG_YAML  # noqa: E402


@pytest.fixture
def tmp_base(tmp_path: Path) -> Path:
    base = tmp_path / "hunterx-home"
    base.mkdir()
    (base / "config").mkdir()
    (base / "config" / "config.yaml").write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
    return base


@pytest.fixture
def cfg(tmp_base: Path) -> Config:
    old = os.environ.copy()
    os.environ["HUNTERX_BASE"] = str(tmp_base)
    try:
        return Config.load(base_dir=tmp_base)
    finally:
        os.environ.pop("HUNTERX_BASE", None)


@pytest.fixture
def db_path(tmp_base: Path) -> Path:
    return tmp_base / "data" / "hunterx.db"