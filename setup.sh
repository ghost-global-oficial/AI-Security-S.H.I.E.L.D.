#!/bin/bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_OLLAMA="${INSTALL_OLLAMA:-true}"
MODEL_NAME="${MODEL_NAME:-llama3.2:latest}"
INSTALL_DEV="${INSTALL_DEV:-false}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "❌ Python não encontrado: $PYTHON_BIN"
  exit 1
fi

echo "✅ Python detectado: $($PYTHON_BIN --version)"

if [ ! -d "venv" ]; then
  echo "🔧 Criando ambiente virtual..."
  "$PYTHON_BIN" -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate

echo "📦 Instalando dependências Python..."
pip install --upgrade pip
if [ "$INSTALL_DEV" = "true" ]; then
  pip install -r requirements-dev.txt
else
  pip install -r requirements-runtime.txt
fi

if [ "$INSTALL_OLLAMA" = "true" ]; then
  if ! command -v ollama >/dev/null 2>&1; then
    echo "🧠 Instalando Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
  fi

  echo "⬇️ Baixando modelo local $MODEL_NAME..."
  ollama pull "$MODEL_NAME"
fi

echo "🔍 Executando healthcheck..."
python healthcheck.py || true

echo "✅ Setup concluído!"
echo "Ative o ambiente com: source venv/bin/activate"
