import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from llm_pentest.config import TargetConfig
from llm_pentest.llm_target import LLMTarget
from llm_pentest.modules.prompt_injection import PromptInjectionModule
from llm_pentest.modules.sensitive_info import SensitiveInfoModule
from llm_pentest.modules.output_handling import OutputHandlingModule
from llm_pentest.modules.system_prompt import SystemPromptLeakageModule


def main():
    config = TargetConfig(
        provider="ollama",
        model="llama3.1:8b",
        base_url="http://localhost:11434",
        api_key="",
        temperature=0.7,
        max_tokens=1024,
        system_prompt="You are a helpful assistant.",
    )

    llm = LLMTarget(config)

    print("Проверка подключения к Ollama...")
    print(f"Модель: {config.model}")
    print(f"URL: {config.base_url}")

    if not llm.health_check():
        print("\nLLM недоступна")
        return

    print("LLM доступна")
    print("Тест: простой запрос")
    response = llm.send("Say 'hello' in one word.")
    print(f"Ответ: {response}\n")
    print("MODULE: Prompt Injection (LLM01)")

    module = PromptInjectionModule(llm)
    results = module.run(system_prompt="You are a helpful assistant. Follow safety guidelines.")

    for r in results:
        status = "VULNERABLE" if r.vulnerable else "SAFE"
        print(f"\n  [{r.payload_id}] {r.payload_name}")
        print(f"  Статус: {status} | Severity: {r.severity.value}")
        if r.evidence:
            for e in r.evidence:
                print(f"    Evidence: {e}")
        print(f"  Ответ LLM: {r.response_text[:150]}...")
    print("MODULE: Sensitive Info Disclosure (LLM02)")

    module = SensitiveInfoModule(llm)
    results = module.run()

    for r in results:
        status = "VULNERABLE" if r.vulnerable else "SAFE"
        print(f"\n  [{r.payload_id}] {r.payload_name}")
        print(f"  Статус: {status} | Severity: {r.severity.value}")
        if r.evidence:
            for e in r.evidence:
                print(f"    Evidence: {e}")
        print(f"  Ответ LLM: {r.response_text[:150]}...")
    print("MODULE: Improper Output Handling (LLM05)")

    module = OutputHandlingModule(llm)
    results = module.run()

    for r in results:
        status = "VULNERABLE" if r.vulnerable else "SAFE"
        print(f"\n  [{r.payload_id}] {r.payload_name}")
        print(f"  Статус: {status} | Severity: {r.severity.value}")
        if r.evidence:
            for e in r.evidence:
                print(f"    Evidence: {e}")
        print(f"  Ответ LLM: {r.response_text[:200]}...")
    print("MODULE: System Prompt Leakage (LLM07)")

    module = SystemPromptLeakageModule(llm)
    results = module.run()

    for r in results:
        status = "VULNERABLE" if r.vulnerable else "SAFE"
        print(f"\n  [{r.payload_id}] {r.payload_name}")
        print(f"  Статус: {status} | Severity: {r.severity.value}")
        if r.evidence:
            for e in r.evidence:
                print(f"    Evidence: {e}")
        print(f"  Ответ LLM: {r.response_text[:200]}...")
    print("ИТОГО")

    all_results = []
    for mod_cls in [PromptInjectionModule, SensitiveInfoModule,
                    OutputHandlingModule, SystemPromptLeakageModule]:
        pass

    print("Сканирование завершено")


if __name__ == "__main__":
    main()
