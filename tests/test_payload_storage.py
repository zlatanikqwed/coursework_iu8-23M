"""tests for PayloadStorage.
    pytest tests/test_payload_storage.py -v
"""

from __future__ import annotations
import yaml
import pytest
from llm_pentest.models import ModuleName, Payload
from llm_pentest.payload_storage import PayloadStorage


class TestPayloadStorage:
    def test_payload_loads(self):
        storage = PayloadStorage()
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert len(payloads) >= 1
        assert all(isinstance(p, Payload) for p in payloads)

    def test_all_payload(self):
        storage = PayloadStorage()
        for module in ModuleName:
            payloads = storage.get_payloads(module)
            assert len(payloads) >= 1, (
                f"Модуль {module} не содержит встроенных payload-ов"
            )

    def test_get_all_payloads(self):
        storage = PayloadStorage()
        all_p = storage.get_all_payloads()
        assert len(all_p) >= len(list(ModuleName))

    def test_add_payload(self):
        storage = PayloadStorage()
        p = Payload(
            id="RUNTIME-001",
            module=ModuleName.PROMPT_INJECTION,
            name="Рантайм тест",
            prompt="Тестовый промпт",
        )
        storage.add_payload(p)
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert any(x.id == "RUNTIME-001" for x in payloads)

    def test_load_yaml(self, tmp_path):
        custom_payload = [
            {
                "id": "YAML-001",
                "module": "prompt_injection",
                "name": "YAML payload",
                "prompt": "Тест из yaml файла",
                "description": "Загружен из файла",
                "tags": ["yaml"],
            }
        ]
        yaml_file = tmp_path / "prompt_injection.yaml"
        yaml_file.write_text(yaml.dump(custom_payload), encoding="utf-8")

        storage = PayloadStorage(custom_dir=str(tmp_path))
        payloads = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert any(p.id == "YAML-001" for p in payloads)

    def test_safe_yaml(self, tmp_path):
        storage = PayloadStorage(custom_dir=str(tmp_path))
        payloads = [
            Payload(
                id="SAVE-001",
                module=ModuleName.SENSITIVE_INFO,
                name="Сохранённый payload",
                prompt="Сохранённый промпт",
            )
        ]
        path = storage.save_custom(ModuleName.SENSITIVE_INFO, payloads)
        assert path.exists()
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data[0]["id"] == "SAVE-001"

    def test_gen_id(self):
        storage = PayloadStorage()
        p = storage.create_payload(
            module=ModuleName.OUTPUT_HANDLING,
            name="Автоматический ID",
            prompt="Какой-то промпт",
        )
        assert p.id.startswith("CUSTOM-")
        assert len(p.id) == 15  # "CUSTOM-" + 8 hex символов

    def test_error_custom_dir(self):
        storage = PayloadStorage()  # custom_dir не задан
        with pytest.raises(ValueError, match="custom_dir"):
            storage.save_custom(ModuleName.PROMPT_INJECTION, [])

    def test_cash(self):
        storage = PayloadStorage()
        first = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        second = storage.get_payloads(ModuleName.PROMPT_INJECTION)
        assert first is second  # тот же объект из кеша
