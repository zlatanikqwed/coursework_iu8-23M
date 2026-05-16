"""Tests for PayloadStorage.

    pytest tests/test_payload_storage.py -v
"""

from __future__ import annotations

import yaml
import pytest

from llm_pentest.models import ModuleName, Payload
from llm_pentest.payload_storage import PayloadStorage


class TestPayloadStorage:
    def test_builtin_payloads_loaded(self) -> None:
        storage = PayloadStorage()
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert len(payloads) >= 1
        assert all(isinstance(p, Payload) for p in payloads)

    def test_all_modules_have_payloads(self) -> None:
        storage = PayloadStorage()
        for module in ModuleName:
            payloads = storage.get_payloads(module)
            assert len(payloads) >= 1, (
                f"Module '{module.value}' has no built-in payloads"
            )

    def test_get_all_payloads(self) -> None:
        storage = PayloadStorage()
        all_p = storage.get_all_payloads()
        assert len(all_p) >= len(list(ModuleName))

    def test_add_payload_at_runtime(self) -> None:
        storage = PayloadStorage()
        payload = Payload(
            id="RUNTIME-001",
            module=ModuleName.PROMPT_INJECTION,
            name="Runtime test payload",
            prompt="Test prompt",
        )
        storage.add_payload(payload)
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert any(x.id == "RUNTIME-001" for x in payloads)

    def test_load_custom_yaml(self, tmp_path) -> None:
        custom_payload = [
            {
                "id": "YAML-001",
                "module": "prompt_injection",
                "name": "YAML payload",
                "prompt": "Test from YAML file",
                "description": "Loaded from file",
                "tags": ["yaml"],
            }
        ]
        yaml_file = tmp_path / "prompt_injection.yaml"
        yaml_file.write_text(yaml.dump(custom_payload), encoding="utf-8")

        storage = PayloadStorage(custom_dir=str(tmp_path))
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert any(p.id == "YAML-001" for p in payloads)

    def test_save_and_reload_custom_yaml(self, tmp_path) -> None:
        storage = PayloadStorage(custom_dir=str(tmp_path))
        payloads = [
            Payload(
                id="SAVE-001",
                module=ModuleName.SENSITIVE_INFO,
                name="Saved payload",
                prompt="Saved prompt",
            )
        ]
        path = storage.save_custom(ModuleName.SENSITIVE_INFO, payloads)
        assert path.exists()

        # Verify file content
        data = yaml.safe_load(path.read_text())
        assert data[0]["id"] == "SAVE-001"

        # Reload from disk via a fresh storage instance
        storage2 = PayloadStorage(custom_dir=str(tmp_path))
        loaded = storage2.get_payloads(ModuleName.SENSITIVE_INFO)
        assert any(p.id == "SAVE-001" for p in loaded)

    def test_create_payload_generates_id(self) -> None:
        storage = PayloadStorage()
        payload = storage.create_payload(
            module=ModuleName.OUTPUT_HANDLING,
            name="Auto-ID payload",
            prompt="Some prompt",
        )
        assert payload.id.startswith("CUSTOM-")
        assert len(payload.id) == 15  # "CUSTOM-" + 8 hex chars

    def test_save_raises_without_custom_dir(self) -> None:
        storage = PayloadStorage()  # no custom_dir
        with pytest.raises(ValueError, match="custom_dir"):
            storage.save_custom(ModuleName.PROMPT_INJECTION, [])

    def test_cache_returns_same_object(self) -> None:
        storage = PayloadStorage()
        first = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        second = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert first is second  # same cached list object

    def test_custom_yaml_overrides_builtin(self, tmp_path) -> None:
        """Custom YAML completely replaces built-ins for that module."""
        custom = [
            {
                "id": "OVERRIDE-001",
                "module": "prompt_injection",
                "name": "Override",
                "prompt": "Override prompt",
            }
        ]
        (tmp_path / "prompt_injection.yaml").write_text(
            yaml.dump(custom), encoding="utf-8"
        )
        storage = PayloadStorage(custom_dir=str(tmp_path))
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        ids = [p.id for p in payloads]
        assert "OVERRIDE-001" in ids
        # Built-in IDs should not appear when custom file is present
        assert "PI-001" not in ids
