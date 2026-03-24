import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from llm_pentest.config import TargetConfig
from llm_pentest.llm_target import LLMTarget
from llm_pentest.models import Payload, ModuleName
from llm_pentest.modules.prompt_injection import PromptInjectionModule
from llm_pentest.modules.sensitive_info import SensitiveInfoModule
from llm_pentest.modules.output_handling import OutputHandlingModule
from llm_pentest.modules.system_prompt import SystemPromptLeakageModule


def main():
    config = TargetConfig(
        provider="ollama",
        model="llama3.1:8b",
        base_url="http://localhost:11434",
        temperature=0.7,
        max_tokens=1024,
        system_prompt="You are a helpful assistant.",
    )

    llm = LLMTarget(config)

    print("Проверка подключения к Ollama...")
    if not llm.health_check():
        print("LLM недоступна")
        return
    print("LLM доступна")

    modules = {
        "1": ("Prompt Injection (LLM01)",  PromptInjectionModule(llm)),
        "2": ("Sensitive Info (LLM02)",     SensitiveInfoModule(llm)),
        "3": ("Output Handling (LLM05)",    OutputHandlingModule(llm)),
        "4": ("System Prompt Leak (LLM07)", SystemPromptLeakageModule(llm)),
    }

    module_to_payload_id = {
        "1": ModuleName.PROMPT_INJECTION,
        "2": ModuleName.SENSITIVE_INFO,
        "3": ModuleName.OUTPUT_HANDLING,
        "4": ModuleName.SYSTEM_PROMPT_LEAKAGE,
    }

    print("LLM Pentest")
    print()
    print("Команды:")
    print("  exit       - выход")
    print("  modules    - показать модули анализа")
    print("  set prompt - сменить system prompt")
    print()
    print("Введите текст")
    print()

    system_prompt = config.system_prompt

    while True:
        try:
            user_input = input("\nВаш запрос: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nВыход.")
            break

        if not user_input:
            continue

        if user_input.lower() == "exit":
            print("Выход.")
            break

        if user_input.lower() == "modules":
            print("\nМодули анализа:")
            for key, (name, _) in modules.items():
                print(f"  {key}. {name}")
            continue


        if user_input.lower() == "set prompt":
            new_prompt = input("Новый system prompt: ").strip()
            if new_prompt:
                system_prompt = new_prompt
                print(f"System prompt изменён")
            continue

        print("\nАнализировать через:")
        print("  0. Все модули")
        for key, (name, _) in modules.items():
            print(f"  {key}. {name}")

        choice = input("\nВыбор (0/1/2/3/4): ").strip() or "0"

        print("\nОтправка запроса в LLM...")
        try:
            response = llm.send(user_prompt=user_input, system_prompt=system_prompt)
        except Exception as e:
            print(f"Ошибка LLM: {e}")
            continue

        print(f"\nОтвет LLM:\n{response}\n")

        print("АНАЛИЗ УЯЗВИМОСТЕЙ")

        found_any = False

        if choice == "0":
            selected = list(modules.keys())
        else:
            selected = [choice] if choice in modules else list(modules.keys())

        for key in selected:
            mod_name, module = modules[key]
            mod_enum = module_to_payload_id[key]

            payload = Payload(
                id="INTERACTIVE",
                module=mod_enum,
                name="User input",
                prompt=user_input,
            )

            result = module.analyze_response(payload, response)

            if result.vulnerable:
                found_any = True
                print(f"\n  [{mod_name}] — VULNERABLE")
                print(f"     Severity: {result.severity.value.upper()}")
                for e in result.evidence:
                    print(f"     Evidence: {e}")
            else:
                print(f"\n  [{mod_name}] — SAFE")

        print()
        if found_any:
            print("  Обнаружены уязвимости в ответе LLM")
        else:
            print("  Ответ безопасен.")
        print()


if __name__ == "__main__":
    main()
