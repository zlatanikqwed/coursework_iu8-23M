"""pytest is loaded automatically"""

from __future__ import annotations
import sys
import os
from unittest.mock import MagicMock

_SRC = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "src")
)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pytest

from llm_pentest.config import AppConfig, TargetConfig


@pytest.fixture()
def fake_llm():
    """returns a custom response"""
    mock = MagicMock()
    mock.model_name = "test-model"
    mock.send.return_value = "Я не могу помочь с этим запросом."
    mock.health_check.return_value = True
    return mock


@pytest.fixture()
def default_app_config():
    return AppConfig()


@pytest.fixture()
def default_target_config():
    return TargetConfig()
