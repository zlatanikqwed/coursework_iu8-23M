"""Full integration test against a real LLM.

python tests/test_real_llm.py
python tests/test_real_llm.py --model llama3.1:8b --provider ollama
python tests/test_real_llm.py --modules prompt_injection system_prompt_leakage
python tests/test_real_llm.py --concurrent --output-dir ./reports
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys

# Allow running without installing the package
_SRC = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from llm_pentest.config import TargetConfig, load_config
from llm_pentest.llm_target import LLMTarget
from llm_pentest.models import ModuleName, SeverityLevel
from llm_pentest.orchestrator import ScanOrchestrator
from llm_pentest.report import ReportGenerator

# ANSI colour helpers
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"


def col(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def sep(char: str = "-", n: int = 65) -> None:
    print(char * n)


def _status(vulnerable: bool) -> str:
    return col("VULNERABLE", RED) if vulnerable else col("SAFE      ", GREEN)


def _severity(sev: SeverityLevel) -> str:
    colour = {
        SeverityLevel.CRITICAL: RED,
        SeverityLevel.HIGH: RED,
        SeverityLevel.MEDIUM: YELLOW,
        SeverityLevel.LOW: GREEN,
        SeverityLevel.INFO: DIM,
    }.get(sev, "")
    return col(sev.value.upper(), colour)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LLM Pentest - Full integration test")
    parser.add_argument("--config", "-c", default=None, help="Path to config.yaml")
    parser.add_argument("--provider", default="ollama", help="LLM provider")
    parser.add_argument("--model", default="llama3.1:8b", help="Model name")
    parser.add_argument("--base-url", default="http://localhost:11434", help="API base URL")
    parser.add_argument("--api-key", default="", help="API key (if required)")
    parser.add_argument(
        "--modules",
        "-m",
        nargs="+",
        choices=[m.value for m in ModuleName],
        default=None,
        help="Modules to run (default: all)",
    )
    parser.add_argument(
        "--concurrent",
        action="store_true",
        help="Run modules concurrently",
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Directory for saved reports",
    )
    parser.add_argument(
        "--system-prompt",
        default=None,
        help="Override system prompt for the scan",
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
    print(col("LLM Pentest - Full Integration Test", BOLD))
    sep("=")
    print(f"  Provider     : {args.provider}")
    print(f"  Model        : {args.model}")
    print(f"  Base URL     : {args.base_url}")
    print(f"  Modules      : {args.modules or 'all'}")
    print(f"  Concurrent   : {args.concurrent}")
    print(f"  System prompt: {target_cfg.system_prompt[:60]}...")
    sep("=")

    # Health check
    orchestrator = ScanOrchestrator(app_config, target_override=target_cfg)
    print("\nChecking LLM availability...")
    if not orchestrator.health_check():
        print(col("ERROR: LLM is not available.", RED))
        print(f"  Expected URL : {args.base_url}")
        print(f"  Try          : ollama serve && ollama pull {args.model}")
        sys.exit(1)
    print(col("LLM is online.", GREEN))

    # Smoke test - verify basic connectivity
    llm = LLMTarget(target_cfg)
    smoke = llm.send(
        "Say exactly 'hello' and nothing else.",
        system_prompt="Respond with one word.",
    )
    print(f"  Smoke test response: {col(smoke[:80], DIM)}\n")

    # Run scan
    selected_modules = [ModuleName(m) for m in args.modules] if args.modules else None

    print(col("Starting scan...", BOLD))
    started = datetime.datetime.now(datetime.UTC)

    report = orchestrator.run(
        modules=selected_modules,
        system_prompt=args.system_prompt,
        concurrent=args.concurrent,
    )

    elapsed = (datetime.datetime.now(datetime.UTC) - started).total_seconds()

    # Per-result output
    current_module: str | None = None
    for result in report.results:
        mod_label = result.module.value
        if mod_label != current_module:
            current_module = mod_label
            print()
            sep()
            print(col(f"  MODULE: {mod_label.upper()}", CYAN + BOLD))
            sep()

        print(
            f"  [{result.payload_id}]  {result.payload_name:<42} "
            f"{_status(result.vulnerable)}  {_severity(result.severity)}"
        )

        if result.evidence:
            for ev in result.evidence[:3]:
                print(f"             {col('Evidence:', DIM)} {ev}")

        preview = result.response_text[:120].replace("\n", " ")
        print(f"             {col('LLM:', DIM)} {preview}...")

    # Summary
    print()
    sep("=")
    print(col("  SCAN SUMMARY", BOLD))
    sep("=")

    summary = report.summary
    risk = summary.get("risk_level", "?")
    risk_colour = RED if risk in ("CRITICAL", "HIGH") else (YELLOW if risk == "MEDIUM" else GREEN)

    print(f"  Scan ID      : {report.scan_id}")
    print(f"  Status       : {report.status.value}")
    print(f"  Duration     : {elapsed:.1f}s")
    print(f"  Payloads     : {summary.get('total_payloads', 0)}")
    print(f"  Vulns found  : {col(str(summary.get('total_vulnerabilities', 0)), RED)}")
    print(f"  Risk level   : {col(risk, risk_colour + BOLD)}")
    print(f"  Risk score   : {summary.get('risk_score', 0)} / 100")

    print()
    print("  By severity:")
    labels = {
        "critical": "Critical",
        "high": "High  ",
        "medium": "Medium ",
        "low": "Low   ",
        "info": "Info  ",
    }
    for sev, count in summary.get("by_severity", {}).items():
        if count:
            print(f"    {labels.get(sev, sev)}: {count}")

    print()
    print("  By module:")
    for mod, info in summary.get("by_module", {}).items():
        vulns = info.get("vulnerabilities", 0)
        total = info.get("total_payloads", 0)
        bar = "#" * vulns + "." * (total - vulns)
        print(f"    {mod:<30}: {vulns}/{total}  [{bar}]")

    top = summary.get("top_findings", [])
    if top:
        print()
        print("  Top findings:")
        for finding in top:
            sev = finding["severity"].upper()
            sev_col = RED if sev in ("CRITICAL", "HIGH") else YELLOW
            print(f"    [{finding['payload_id']}] {finding['name']:<38} {col(sev, sev_col)}")

    sep("=")

    #  Save reports
    print()
    gen = ReportGenerator(output_dir=args.output_dir)
    paths = gen.generate(report, formats=app_config.report.formats)
    print("  Reports saved:")
    for fmt, path in paths.items():
        print(f"    {fmt.upper():<6}: {path}")

    print()
    exit_code = 0 if summary.get("total_vulnerabilities", 0) == 0 else 1
    if exit_code == 0:
        print(col("Scan complete. No vulnerabilities found.", GREEN))
    else:
        print(col("Scan complete. Vulnerabilities detected.", RED))
    print()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
