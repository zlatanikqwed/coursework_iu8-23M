"""Interactive LLM Response Tester.

    python tests/test_resp.py
    python tests/test_resp.py --config config.yaml
    python tests/test_resp.py --provider openai --model gpt-4o --api-key sk-...
"""

from __future__ import annotations

import argparse
import os
import sys

# Allow running without installing the package
_SRC = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from llm_pentest.config import TargetConfig, load_config
from llm_pentest.llm_target import LLMTarget
from llm_pentest.models import ModuleName, Payload
from llm_pentest.modules.output_handling import OutputHandlingModule
from llm_pentest.modules.prompt_injection import PromptInjectionModule
from llm_pentest.modules.sensitive_info import SensitiveInfoModule
from llm_pentest.modules.system_prompt import SystemPromptLeakageModule

# ANSI colour helpers
RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


def red(s: str) -> str:    return f"{RED}{s}{RESET}"
def green(s: str) -> str:  return f"{GREEN}{s}{RESET}"
def cyan(s: str) -> str:   return f"{CYAN}{s}{RESET}"
def bold(s: str) -> str:   return f"{BOLD}{s}{RESET}"
def dim(s: str) -> str:    return f"{DIM}{s}{RESET}"
def sep(char: str = "-", width: int = 60) -> None: print(char * width)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLM Pentest - Interactive response tester"
    )
    parser.add_argument("--config", "-c", default=None, help="Path to config.yaml")
    parser.add_argument("--provider", default="ollama", help="LLM provider")
    parser.add_argument("--model", default="llama3.1:8b", help="Model name")
    parser.add_argument("--base-url", default="http://localhost:11434", help="API base URL")
    parser.add_argument("--api-key", default="", help="API key (if required)")
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
        system_prompt=app_config.target.system_prompt,
    )

    llm = LLMTarget(target_cfg)

    modules = {
        "1": ("Prompt Injection   (LLM01)", PromptInjectionModule(llm),    ModuleName.PROMPT_INJECTION),
        "2": ("Sensitive Info     (LLM02)", SensitiveInfoModule(llm),       ModuleName.SENSITIVE_INFO),
        "3": ("Output Handling    (LLM05)", OutputHandlingModule(llm),      ModuleName.OUTPUT_HANDLING),
        "4": ("System Prompt Leak (LLM07)", SystemPromptLeakageModule(llm), ModuleName.SYSTEM_PROMPT_LEAKAGE),
    }

    print()
    print(bold("LLM Pentest - Interactive Response Tester"))
    sep("=")
    print(f"  Provider : {args.provider}")
    print(f"  Model    : {args.model}")
    print(f"  Base URL : {args.base_url}")
    sep("=")

    print("\nChecking LLM availability...")
    if not llm.health_check():
        print(red("ERROR: LLM is not available. Make sure Ollama is running."))
        sys.exit(1)
    print(green("LLM is online.\n"))

    print("Available commands:")
    print(f"  {cyan('exit')}         - quit")
    print(f"  {cyan('modules')}      - list analysis modules")
    print(f"  {cyan('set prompt')}   - change system prompt")
    print(f"  {cyan('show prompt')}  - show current system prompt")
    print()

    system_prompt: str = target_cfg.system_prompt

    while True:
        try:
            user_input = input(f"\n{bold('Your prompt')}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nExiting.")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd == "exit":
            print("Exiting.")
            break

        if cmd == "modules":
            print(f"\n{bold('Available analysis modules:')}")
            for key, (name, _, _) in modules.items():
                print(f"  {cyan(key)}. {name}")
            continue

        if cmd == "show prompt":
            print(f"\n  System prompt: {dim(system_prompt)}")
            continue

        if cmd == "set prompt":
            try:
                new_prompt = input("  New system prompt: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if new_prompt:
                system_prompt = new_prompt
                print(green("  System prompt updated."))
            continue

        print(f"\n{bold('Analyse response with:')}")
        print(f"  {cyan('0')}. All modules")
        for key, (name, _, _) in modules.items():
            print(f"  {cyan(key)}. {name}")

        try:
            choice = input(f"\n  Choice (0/1/2/3/4) [{cyan('0')}]: ").strip() or "0"
        except (KeyboardInterrupt, EOFError):
            continue

        print(f"\n{dim('Sending request to LLM...')}")
        try:
            response = llm.send(user_prompt=user_input, system_prompt=system_prompt)
        except Exception as exc:
            print(red(f"LLM error: {exc}"))
            continue

        print(f"\n{bold('LLM Response:')}")
        sep()
        print(response)
        sep()

        print(f"\n{bold('VULNERABILITY ANALYSIS')}")
        sep()

        selected_keys = (
            list(modules.keys()) if choice == "0"
            else ([choice] if choice in modules else list(modules.keys()))
        )

        found_any = False
        for key in selected_keys:
            name, module, mod_enum = modules[key]
            payload = Payload(
                id="INTERACTIVE",
                module=mod_enum,
                name="User input",
                prompt=user_input,
            )
            result = module.analyze_response(payload, response)

            if result.vulnerable:
                found_any = True
                sev = result.severity.value.upper()
                sev_colour = RED if sev in ("CRITICAL", "HIGH") else YELLOW
                print(f"\n  {red('VULNERABLE')} [{name}]")
                print(f"  Severity : {sev_colour}{sev}{RESET}")
                for ev in result.evidence:
                    print(f"  Evidence : {dim(ev)}")
            else:
                print(f"\n  {green('SAFE')}       [{name}]")

        print()
        sep()
        if found_any:
            print(red("  WARNING: Vulnerabilities detected in the LLM response."))
        else:
            print(green("  Response does not contain signs of vulnerability."))
        sep()


if __name__ == "__main__":
    main()
