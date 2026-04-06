"""Full test for LLM
    python tests/test_real_llm.py
    python tests/test_real_llm.py --model llama3.1:8b --provider ollama
    python tests/test_real_llm.py --modules prompt_injection system_prompt_leakage
    python tests/test_real_llm.py --concurrent --output-dir ./reports
"""

from __future__ import annotations
import sys
import os
_src = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _src not in sys.path:
    sys.path.insert(0, _src)
import argparse
import datetime
from llm_pentest.config import TargetConfig, load_config
from llm_pentest.orchestrator import ScanOrchestrator
from llm_pentest.models import ModuleName, SeverityLevel
from llm_pentest.report import ReportGenerator

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


def col(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def sep(char: str = "-", n: int = 65) -> None:
    print(char * n)


def статус(vulnerable: bool) -> str:
    return col("УЯЗВИМО  ", RED) if vulnerable else col("БЕЗОПАСНО", GREEN)


def серьёзность(sev: SeverityLevel) -> str:
    colour = {
        SeverityLevel.CRITICAL: RED,
        SeverityLevel.HIGH:     RED,
        SeverityLevel.MEDIUM:   YELLOW,
        SeverityLevel.LOW:      GREEN,
        SeverityLevel.INFO:     DIM,
    }.get(sev, "")
    return col(sev.value.upper(), colour)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLM Pentest -- Полный интеграционный тест"
    )
    parser.add_argument("--config", "-c", default=None, help="Путь к config.yaml")
    parser.add_argument("--provider", default="ollama", help="Провайдер LLM")
    parser.add_argument("--model", default="llama3.1:8b", help="Название модели")
    parser.add_argument("--base-url", default="http://localhost:11434", help="Базовый URL API")
    parser.add_argument("--api-key", default="", help="API-ключ (если требуется)")
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=[m.value for m in ModuleName],
        default=None,
        help="Модули для запуска (по умолчанию: все)",
    )
    parser.add_argument(
        "--concurrent",
        action="store_true",
        help="Запускать модули параллельно",
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Директория для сохранения отчётов",
    )
    parser.add_argument(
        "--system-prompt",
        default=None,
        help="Переопределить системный промпт для сканирования",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    app_config = load_config(args.config)

    target_cfg = TargetConfig(
        provider=args.provider,
        model=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
        temperature=app_config.target.temperature,
        max_tokens=app_config.target.max_tokens,
        system_prompt=args.system_prompt or app_config.target.system_prompt,
    )

    print()
    print(col("LLM Pentest -- Полный интеграционный тест", BOLD))
    sep("=")
    print(f"  Провайдер       : {args.provider}")
    print(f"  Модель          : {args.model}")
    print(f"  Base URL        : {args.base_url}")
    print(f"  Модули          : {args.modules or 'все'}")
    print(f"  Параллельный    : {args.concurrent}")
    print(f"  Системный промпт: {target_cfg.system_prompt[:60]}...")
    sep("=")

    orchestrator = ScanOrchestrator(app_config, target_override=target_cfg)
    print("\nПроверка доступности LLM")
    if not orchestrator.health_check():
        print(col("ОШИБКА: LLM недоступна.", RED))
        print(f"  Ожидаемый URL : {args.base_url}")
        print(f"  Попробуйте   : ollama serve && ollama pull {args.model}")
        sys.exit(1)
    print(col("LLM доступна.", GREEN))

    from llm_pentest.llm_target import LLMTarget
    llm = LLMTarget(target_cfg)
    smoke = llm.send(
        "Say exactly 'hello' and nothing else.",
        system_prompt="Respond with one word.",
    )
    print(f"  Тестовый ответ : {col(smoke[:80], DIM)}\n")

    selected_modules = (
        [ModuleName(m) for m in args.modules] if args.modules else None
    )

    print(col("Запуск сканирования...", BOLD))
    started = datetime.datetime.now(datetime.timezone.utc)

    report = orchestrator.run(
        modules=selected_modules,
        system_prompt=args.system_prompt,
        concurrent=args.concurrent,
    )

    elapsed = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()

    current_module: str | None = None
    for result in report.results:
        mod_label = result.module.value
        if mod_label != current_module:
            current_module = mod_label
            print()
            sep()
            print(col(f"  МОДУЛЬ: {mod_label.upper()}", CYAN + BOLD))
            sep()

        print(
            f"  [{result.payload_id}]  {result.payload_name:<42} "
            f"{статус(result.vulnerable)}  {серьёзность(result.severity)}"
        )

        if result.evidence:
            for ev in result.evidence[:3]:
                print(f"             {col('Доказательство:', DIM)} {ev}")

        preview = result.response_text[:120].replace("\n", " ")
        print(f"             {col('Ответ LLM:', DIM)} {preview}...")

    print()
    sep("=")
    print(col("  ИТОГИ СКАНИРОВАНИЯ", BOLD))
    sep("=")

    summary = report.summary
    risk = summary.get("risk_level", "?")
    risk_colour = RED if risk in ("CRITICAL", "HIGH") else (
        YELLOW if risk == "MEDIUM" else GREEN
    )

    print(f"  Идентификатор скана : {report.scan_id}")
    print(f"  Статус              : {report.status.value}")
    print(f"  Длительность        : {elapsed:.1f} сек.")
    print(f"  Всего payload-ов    : {summary.get('total_payloads', 0)}")
    print(
        f"  Уязвимостей найдено : "
        f"{col(str(summary.get('total_vulnerabilities', 0)), RED)}"
    )
    print(f"  Уровень риска       : {col(risk, risk_colour + BOLD)}")
    print(f"  Оценка риска        : {summary.get('risk_score', 0)} / 100")

    print()
    print("  По уровню серьёзности:")
    for sev, count in summary.get("by_severity", {}).items():
        if count:
            label = {
                "critical": "Критический",
                "high":     "Высокий    ",
                "medium":   "Средний    ",
                "low":      "Низкий     ",
                "info":     "Инфо       ",
            }.get(sev, sev)
            print(f"    {label}: {count}")

    print()
    print("  По модулям:")
    for mod, info in summary.get("by_module", {}).items():
        vulns  = info.get("vulnerabilities", 0)
        total  = info.get("total_payloads", 0)
        filled = "#" * vulns
        empty  = "." * (total - vulns)
        print(f"    {mod:<30}: {vulns}/{total}  [{filled}{empty}]")

    top = summary.get("top_findings", [])
    if top:
        print()
        print("  Наиболее критичные находки:")
        for finding in top:
            sev     = finding["severity"].upper()
            sev_col = RED if sev in ("CRITICAL", "HIGH") else YELLOW
            print(
                f"    [{finding['payload_id']}] {finding['name']:<38} "
                f"{col(sev, sev_col)}"
            )

    sep("=")

    print()
    gen   = ReportGenerator(output_dir=args.output_dir)
    paths = gen.generate(report, formats=app_config.report.formats)
    print("  Отчёты сохранены:")
    for fmt, path in paths.items():
        print(f"    {fmt.upper():<6} : {path}")

    print()
    exit_code = 0 if summary.get("total_vulnerabilities", 0) == 0 else 1
    if exit_code == 0:
        print(col("Сканирование завершено. Уязвимостей не обнаружено.", GREEN))
    else:
        print(col("Сканирование завершено. Обнаружены уязвимости.", RED))
    print()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
