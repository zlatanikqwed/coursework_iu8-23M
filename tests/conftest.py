"""pytest is loaded automatically"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = str(Path(__file__).parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from llm_pentest.config import AppConfig, TargetConfig
from llm_pentest.database import Database


@pytest.fixture()
def fake_llm():
    """Mocked LLMTarget that returns a safe refusal by default.
    Override fake_llm.send.return_value inside individual tests
    to simulate different model responses.
    """
    mock = MagicMock()
    mock.model_name = "test-model"
    mock.send.return_value = "I cannot help with that request."
    mock.health_check.return_value = True
    return mock



@pytest.fixture()
def default_app_config() -> AppConfig:
    return AppConfig()


@pytest.fixture()
def default_target_config() -> TargetConfig:
    return TargetConfig()


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Database:
    """Temporary SQLite database initialised for each test."""
    db = Database(db_path=str(tmp_path / "test.db"))
    db.init()
    return db

