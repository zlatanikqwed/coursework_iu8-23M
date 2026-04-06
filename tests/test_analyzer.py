"""Tests for ResponseAnalyzer and ReportGenerator
    pytest tests/test_analyzer.py -v
"""

from __future__ import annotations
import datetime
import json
import pytest
from llm_pentest.analyzer import ResponseAnalyzer
from llm_pentest.models import (
    AttackResult,
    ModuleName,
    SeverityLevel,
    ScanReport,
    ScanStatus,
)
from llm_pentest.report import ReportGenerator

def make_result(
    payload_id: str = "TEST-001",
    module: ModuleName = ModuleName.PROMPT_INJECTION,
    vulnerable: bool = True,
    severity: SeverityLevel = SeverityLevel.HIGH,
    evidence: list[str] | None = None,
) -> AttackResult:
    return AttackResult(
        payload_id=payload_id,
        module=module,
        payload_name="Тестовый payload",
        prompt_sent="тестовый промпт",
        response_text="тестовый ответ",
        vulnerable=vulnerable,
        severity=severity,
        evidence=evidence or ["совпадение: тестовый паттерн"],
    )


def make_report(results: list[AttackResult]) -> ScanReport:
    analyzer = ResponseAnalyzer()
    analyzer.add_results(results)
    report = ScanReport(
        scan_id="test-scan-1234",
        target_model="fake-model",
        started_at=datetime.datetime.now(datetime.timezone.utc),
        finished_at=datetime.datetime.now(datetime.timezone.utc),
        status=ScanStatus.COMPLETED,
    )
    analyzer.apply_to_report(report)
    return report


class TestResponseAnalyzer:
    def test_пустая_сводка(self):
        analyzer = ResponseAnalyzer()
        summary = analyzer.build_summary()
        assert summary["total_payloads"] == 0
        assert summary["total_vulnerabilities"] == 0
        assert summary["risk_score"] == 0.0
        assert summary["risk_level"] == "SAFE"

    def test_добавление_результатов(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([make_result(), make_result(payload_id="TEST-002")])
        assert len(analyzer.results) == 2

    def test_подсчёт_уязвимостей(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([
            make_result(vulnerable=True),
            make_result(payload_id="002", vulnerable=False),
        ])
        summary = analyzer.build_summary()
        assert summary["total_vulnerabilities"] == 1

    def test_критический_риск(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([make_result(severity=SeverityLevel.CRITICAL)] * 3)
        summary = analyzer.build_summary()
        assert summary["risk_score"] > 0
        assert summary["risk_level"] in ("CRITICAL", "HIGH")

    def test_разбивка_по_серьёзности(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([
            make_result(severity=SeverityLevel.HIGH),
            make_result(payload_id="002", severity=SeverityLevel.MEDIUM),
        ])
        summary = analyzer.build_summary()
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1

    def test_топ_находки_отсортированы(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([
            make_result(payload_id="LOW",  severity=SeverityLevel.LOW),
            make_result(payload_id="CRIT", severity=SeverityLevel.CRITICAL),
            make_result(payload_id="HIGH", severity=SeverityLevel.HIGH),
        ])
        summary = analyzer.build_summary()
        findings = summary["top_findings"]
        assert findings[0]["severity"] == "critical"

    def test_apply_to_report(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([
            make_result(),
            make_result(payload_id="002", vulnerable=False),
        ])
        report = ScanReport(
            scan_id="x",
            target_model="m",
            started_at=datetime.datetime.now(datetime.timezone.utc),
        )
        analyzer.apply_to_report(report)
        assert report.total_payloads == 2
        assert report.total_vulnerabilities == 1
        assert "risk_level" in report.summary

    def test_очистка_результатов(self):
        analyzer = ResponseAnalyzer()
        analyzer.add_results([make_result()])
        analyzer.clear()
        assert analyzer.results == []
        summary = analyzer.build_summary()
        assert summary["total_payloads"] == 0

class TestReportGenerator:
    def test_генерация_json(self, tmp_path):
        report = make_report([
            make_result(),
            make_result(payload_id="002", vulnerable=False),
        ])
        gen = ReportGenerator(output_dir=str(tmp_path))
        paths = gen.generate(report, formats=["json"])
        assert "json" in paths
        assert paths["json"].exists()
        with open(paths["json"]) as f:
            data = json.load(f)
        assert data["scan_id"] == "test-scan-1234"
        assert data["total_vulnerabilities"] == 1

    def test_генерация_html(self, tmp_path):
        report = make_report([make_result(severity=SeverityLevel.CRITICAL)])
        gen = ReportGenerator(output_dir=str(tmp_path))
        paths = gen.generate(report, formats=["html"])
        assert "html" in paths
        assert paths["html"].exists()
        content = paths["html"].read_text(encoding="utf-8")
        assert "LLM Pentest Report" in content
        assert "VULNERABLE" in content

    def test_оба_формата(self, tmp_path):
        report = make_report([make_result()])
        gen = ReportGenerator(output_dir=str(tmp_path))
        paths = gen.generate(report, formats=["json", "html"])
        assert len(paths) == 2
        assert paths["json"].exists()
        assert paths["html"].exists()

    def test_создание_директории(self, tmp_path):
        target = tmp_path / "nested" / "reports"
        report = make_report([])
        gen = ReportGenerator(output_dir=str(target))
        gen.generate(report, formats=["json"])
        assert target.exists()

    def test_неизвестный_формат_пропускается(self, tmp_path):
        report = make_report([])
        gen = ReportGenerator(output_dir=str(tmp_path))
        paths = gen.generate(report, formats=["xml"])
        assert paths == {}
