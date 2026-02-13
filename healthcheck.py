"""Healthcheck operacional do S.H.I.E.L.D."""

import importlib
import json
import sys
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

REQUIRED_MODULES = ["numpy", "requests", "psutil"]


def check_python_modules() -> list[str]:
    errors = []
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:
            errors.append(f"Dependência ausente/falha ao importar '{module}': {exc}")
    return errors


def check_config() -> list[str]:
    errors = []
    for cfg in ["config.json", "config.example.json"]:
        path = Path(cfg)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                for key in ["perimeter", "heuristics", "oracle", "enforcement"]:
                    if key not in data:
                        errors.append(f"Configuração {cfg} sem chave obrigatória: {key}")
            except Exception as exc:
                errors.append(f"Falha ao ler {cfg}: {exc}")
            break
    else:
        errors.append("Nenhum config encontrado (config.json ou config.example.json)")
    return errors


def check_ollama(endpoint: str = "http://localhost:11434/api/tags") -> list[str]:
    try:
        with urlopen(endpoint, timeout=3) as resp:
            if resp.status != 200:
                return [f"Ollama respondeu status inesperado: {resp.status}"]
    except URLError as exc:
        return [f"Ollama indisponível em {endpoint}: {exc}"]
    except Exception as exc:
        return [f"Falha ao verificar Ollama: {exc}"]
    return []


def main() -> int:
    errors = []
    errors.extend(check_python_modules())
    errors.extend(check_config())

    ollama_errors = check_ollama()
    if ollama_errors:
        print("⚠️ Oracle LLM offline (modo degradado):")
        for msg in ollama_errors:
            print(f"   - {msg}")

    if errors:
        print("❌ Healthcheck falhou:")
        for msg in errors:
            print(f"   - {msg}")
        return 1

    print("✅ Healthcheck principal OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
