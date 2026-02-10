#!/bin/bash

# S.H.I.E.L.D. Setup Script
# Instalação automatizada do sistema

set -e

echo "🛡️  S.H.I.E.L.D. - Setup Wizard"
echo "========================================"
echo ""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para verificar comando
check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 encontrado"
        return 0
    else
        echo -e "${RED}✗${NC} $1 não encontrado"
        return 1
    fi
}

# Função para instalar Ollama
install_ollama() {
    echo ""
    echo "📦 Instalando Ollama..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install ollama
    else
        echo -e "${YELLOW}⚠${NC} Sistema operacional não suportado para instalação automática"
        echo "Por favor, instale manualmente: https://ollama.com"
        return 1
    fi
    
    echo -e "${GREEN}✓${NC} Ollama instalado"
}

# 1. Verificar Python
echo "1️⃣  Verificando Python..."
if ! check_command python3; then
    echo -e "${RED}Erro:${NC} Python 3 não encontrado. Por favor, instale Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "   Versão: $PYTHON_VERSION"

# 2. Verificar pip
echo ""
echo "2️⃣  Verificando pip..."
if ! check_command pip3; then
    echo "   Instalando pip..."
    python3 -m ensurepip --upgrade
fi

# 3. Criar ambiente virtual
echo ""
echo "3️⃣  Criando ambiente virtual..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓${NC} Ambiente virtual criado"
else
    echo -e "${YELLOW}⚠${NC} Ambiente virtual já existe"
fi

# 4. Ativar ambiente e instalar dependências
echo ""
echo "4️⃣  Instalando dependências..."
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate

pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}✓${NC} Dependências instaladas"

# 5. Verificar Ollama
echo ""
echo "5️⃣  Verificando Ollama..."
if ! check_command ollama; then
    echo -e "${YELLOW}⚠${NC} Ollama não encontrado"
    read -p "Deseja instalar Ollama agora? (s/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        install_ollama
    else
        echo -e "${YELLOW}⚠${NC} Ollama não instalado. O Layer Oracle não funcionará."
        echo "   Instale depois com: curl -fsSL https://ollama.com/install.sh | sh"
    fi
else
    echo -e "${GREEN}✓${NC} Ollama já instalado"
fi

# 6. Baixar modelo LLM
echo ""
echo "6️⃣  Configurando modelo LLM..."
if check_command ollama; then
    # Verifica se Ollama está rodando
    if ! pgrep -x "ollama" > /dev/null; then
        echo "   Iniciando Ollama..."
        ollama serve &
        sleep 3
    fi
    
    echo "   Baixando modelo llama3.2 (pode demorar alguns minutos)..."
    ollama pull llama3.2:latest
    echo -e "${GREEN}✓${NC} Modelo baixado"
else
    echo -e "${YELLOW}⚠${NC} Ollama não disponível. Pulando download do modelo."
fi

# 7. Testar instalação
echo ""
echo "7️⃣  Testando instalação..."
python3 -c "
import sys
try:
    import numpy
    import requests
    import psutil
    print('${GREEN}✓${NC} Todas as bibliotecas carregadas com sucesso')
except ImportError as e:
    print('${RED}✗${NC} Erro ao importar bibliotecas:', e)
    sys.exit(1)
"

# 8. Finalização
echo ""
echo "========================================"
echo -e "${GREEN}✅ Setup concluído com sucesso!${NC}"
echo "========================================"
echo ""
echo "📝 Próximos passos:"
echo ""
echo "1. Ativar ambiente virtual:"
echo "   source venv/bin/activate"
echo ""
echo "2. Executar demo:"
echo "   python demo_shield.py"
echo ""
echo "3. Ler documentação:"
echo "   cat README.md"
echo ""
echo "🛡️  O S.H.I.E.L.D. está pronto para proteger suas IAs!"
echo ""
