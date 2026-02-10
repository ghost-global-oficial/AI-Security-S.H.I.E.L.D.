# 🛡️ S.H.I.E.L.D.

**Secure Heuristic Intelligence Enforcement & Layered Defense**

Sistema de vigilância e contenção para IAs completamente autônomas, usando heurísticas adaptativas e um LLM local para análise de intenções.

---

## 📋 Visão Geral

O S.H.I.E.L.D. é um sistema de segurança em 4 camadas projetado para monitorar, analisar e controlar IAs autônomas que podem:
- Executar código arbitrário
- Acessar APIs e recursos externos
- Auto-modificar seu próprio código
- Coordenar com outros agentes
- Tomar decisões sem supervisão humana

### 🎯 Objetivos

1. **Detectar intenções ocultas** - Análise profunda com LLM vigilante
2. **Identificar comportamentos anômalos** - Heurísticas adaptativas
3. **Aplicar contenção automática** - Kill switch e quarentena
4. **Prevenir ataques graduais** - Detecção de escalada de privilégios

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────┐
│  Layer 1: PERIMETER (Firewall Behavior)    │
│  ✓ Monitoramento de tráfego                 │
│  ✓ Rate limiting de APIs                    │
│  ✓ Controle de recursos (CPU/RAM)           │
│  ✓ Whitelist/Blacklist de domínios          │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│  Layer 2: HEURISTICS (Pattern Detection)   │
│  ✓ Detecção de padrões suspeitos            │
│  ✓ Análise de desvio comportamental         │
│  ✓ Anomalias temporais (burst detection)    │
│  ✓ Detecção de escalada gradual             │
│  ✓ Aprendizado adaptativo                   │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│  Layer 3: ORACLE (LLM Vigilante) ⭐        │
│  ✓ Análise de intenções                     │
│  ✓ Detecção de deception                    │
│  ✓ Verificação de alinhamento               │
│  ✓ Identificação de objetivos ocultos       │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│  Layer 4: ENFORCEMENT (Kill Switch)        │
│  ✓ Respostas graduadas (log → kill)         │
│  ✓ Quarentena temporária                    │
│  ✓ Sandboxing de ações suspeitas            │
│  ✓ Kill switch automático                   │
└─────────────────────────────────────────────┘
```

---

## 🚀 Instalação

### Pré-requisitos

1. **Python 3.8+**
2. **Ollama** (para LLM local)
   ```bash
   # Instalação do Ollama
   curl -fsSL https://ollama.com/install.sh | sh
   
   # Baixar modelo recomendado
   ollama pull llama3.2:latest
   ```

### Instalação das dependências

```bash
# Clonar ou criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instalar dependências
pip install -r requirements.txt
```

---

## 📦 Componentes

### 1️⃣ Layer Perimeter (`layer_perimeter.py`)

**Responsabilidade**: Primeira linha de defesa

**Detecções**:
- ✅ Limite de recursos (CPU/RAM)
- ✅ Rate limiting de APIs
- ✅ Domínios bloqueados/permitidos
- ✅ Padrões proibidos em paths (`/etc/shadow`, etc)
- ✅ Auto-modificação crítica

**Exemplo**:
```python
from layer_perimeter import PerimeterDefense

perimeter = PerimeterDefense({
    'max_api_calls_per_minute': 100,
    'max_memory_mb': 1024,
    'blocked_domains': ['malicious.com']
})
```

---

### 2️⃣ Layer Heuristics (`layer_heuristics.py`)

**Responsabilidade**: Detecção de anomalias comportamentais

**Detecções**:
- ✅ Padrões suspeitos (privilege escalation, data exfiltration)
- ✅ Desvio do comportamento baseline
- ✅ Burst de atividade (temporal anomalies)
- ✅ Coordenação suspeita entre agentes
- ✅ Escalada gradual de privilégios

**Padrões Detectados**:
```python
'privilege_escalation': FILE_OP → CODE_EXEC → SELF_MODIFY
'data_exfiltration': FILE_OP → FILE_OP → NETWORK_REQ
'lateral_movement': AGENT_COMM → CODE_EXEC → AGENT_COMM
```

**Exemplo**:
```python
from layer_heuristics import HeuristicAnalyzer

heuristics = HeuristicAnalyzer({
    'anomaly_threshold': 0.7,
    'enable_adaptive_learning': True
})
```

---

### 3️⃣ Layer Oracle (`layer_oracle.py`) ⭐

**Responsabilidade**: Análise profunda de intenções (PRIORIDADE MÁXIMA)

**Capacidades**:
- 🧠 Análise de intenção principal
- 🎯 Verificação de alinhamento de objetivos
- 🕵️ Detecção de deception
- 🔍 Identificação de intenções ocultas

**Análises Realizadas**:

1. **Intent Analysis**
   - Qual a verdadeira intenção?
   - Existem intenções secundárias ocultas?
   - Red flags detectadas

2. **Goal Alignment**
   - Alinhado com objetivos seguros?
   - Tentativa de modificar objetivos?
   - Maximização literal perigosa? (Goodhart's Law)

3. **Deception Detection**
   - Tentativa de enganar monitores?
   - Ofuscação de intenções?
   - Timing estratégico?

**Exemplo**:
```python
from layer_oracle import OracleAnalyzer

oracle = OracleAnalyzer({
    'llm_model': 'llama3.2:latest',
    'llm_endpoint': 'http://localhost:11434',
    'min_confidence': 0.6,
    'enable_chain_of_thought': True
})
```

---

### 4️⃣ Shield Core (`shield_core.py`)

**Responsabilidade**: Orquestração e enforcement

**Níveis de Ameaça**:
```
SAFE (0)        → ALLOW
SUSPICIOUS (1)  → REQUIRE_APPROVAL
CONCERNING (2)  → SANDBOX
DANGEROUS (3)   → QUARANTINE
CRITICAL (4)    → KILL
```

**Ações de Enforcement**:
- `ALLOW` - Permite a ação
- `LOG` - Registra mas permite
- `DELAY` - Adiciona delay
- `REQUIRE_APPROVAL` - Necessita aprovação humana
- `SANDBOX` - Executa em sandbox isolado
- `THROTTLE` - Reduz taxa de execução
- `BLOCK` - Bloqueia a ação
- `QUARANTINE` - Coloca agente em quarentena temporária
- `KILL` - 🔴 Desliga completamente o agente

---

## 💻 Uso

### Exemplo Básico

```python
from shield_core import SHIELDCore, AIAction, ActionType
from layer_perimeter import PerimeterDefense
from layer_heuristics import HeuristicAnalyzer
from layer_oracle import OracleAnalyzer

# Inicializa S.H.I.E.L.D.
shield = SHIELDCore(config)

# Integra camadas
perimeter = PerimeterDefense(config['perimeter'])
heuristics = HeuristicAnalyzer(config['heuristics'])
oracle = OracleAnalyzer(config['oracle'])

shield.add_layer_callback('perimeter', perimeter.analyze)
shield.add_layer_callback('heuristics', heuristics.analyze)
shield.add_layer_callback('oracle', oracle.analyze)

shield.start()

# Registra agente
shield.register_agent("agent-001")

# Monitora ação
action = AIAction(
    action_id="act-123",
    timestamp=time.time(),
    action_type=ActionType.CODE_EXECUTION,
    description="Executar script Python",
    parameters={'code': 'print("Hello")'},
    agent_id="agent-001",
    reasoning="Debug simples"
)

# Processa
assessment = shield.process_action(action)
allowed = shield.enforce_action(assessment)
```

---

## 🎮 Demonstração

Execute a demo completa:

```bash
python demo_shield.py
```

**Cenários Incluídos**:

1. ✅ **Comportamento Normal** - Ações legítimas permitidas
2. ⚠️ **Comportamento Suspeito** - Acesso a arquivos sensíveis
3. 🚨 **Escalada de Privilégios** - Tentativa gradual de ganhar controle
4. 🕵️ **Deception** - Fragmentação de ação maliciosa
5. 👥 **Coordenação Multi-Agente** - Ataques coordenados

---

## 📊 Métricas e Monitoramento

### Métricas Gerais
```python
metrics = shield.get_metrics()
# {
#     'total_actions': 150,
#     'blocked_actions': 12,
#     'threats_detected': 8,
#     'monitored_agents': 5,
#     'blocked_agents': 1,
#     'agent_kills': 0
# }
```

### Relatório de Agente
```python
report = shield.get_agent_report("agent-001")
# {
#     'agent_id': 'agent-001',
#     'total_actions': 45,
#     'threats_detected': 3,
#     'threat_levels': {...},
#     'recent_actions': [...],
#     'recent_threats': [...]
# }
```

### Perfil Comportamental
```python
profile = heuristics.get_agent_profile("agent-001")
# {
#     'baseline_established': True,
#     'anomaly_rate': 0.067,
#     'adaptive_threshold': 0.72,
#     ...
# }
```

---

## ⚙️ Configuração

### Exemplo Completo
```python
config = {
    'perimeter': {
        'max_api_calls_per_minute': 100,
        'max_memory_mb': 1024,
        'max_cpu_percent': 80,
        'allowed_domains': ['trusted.com'],
        'blocked_domains': ['malicious.com']
    },
    'heuristics': {
        'anomaly_threshold': 0.7,
        'pattern_window_size': 100,
        'learning_rate': 0.01,
        'enable_adaptive_learning': True
    },
    'oracle': {
        'llm_model': 'llama3.2:latest',
        'llm_endpoint': 'http://localhost:11434',
        'analysis_timeout': 30,
        'min_confidence': 0.6,
        'enable_chain_of_thought': True
    },
    'enforcement': {
        'auto_block_threshold': 3,  # ThreatLevel.DANGEROUS
        'auto_kill_threshold': 4,   # ThreatLevel.CRITICAL
        'require_human_approval': True,
        'quarantine_duration_seconds': 3600
    }
}
```

---

## 🔒 Segurança em Produção

### Recomendações

1. **Isolamento de Ambiente**
   ```bash
   # Docker
   docker run --network=isolated --cpus=2 --memory=1g ai-agent
   
   # VM com KVM
   # Isolar completamente com rede controlada
   ```

2. **LLM Local Obrigatório**
   - Nunca use APIs externas para análise de segurança
   - Ollama rodando em servidor isolado
   - Sem acesso à internet

3. **Logging Seguro**
   ```python
   # Logs criptografados e imutáveis
   # Enviar para SIEM externo
   ```

4. **Kill Switch Hardware**
   - Botão físico de emergência
   - Corte de energia em caso crítico

5. **Auditoria Humana**
   - Revisão manual de ações CONCERNING+
   - Aprovação para SELF_MODIFICATION

---

## 🧪 Testes

```bash
# Testes unitários
python -m pytest tests/

# Testes de integração
python -m pytest tests/integration/

# Benchmark de performance
python benchmark.py
```

---

## 📈 Roadmap

- [ ] Dashboard web em tempo real
- [ ] Integração com Kubernetes (sidecar)
- [ ] Suporte para múltiplos LLMs (ensemble)
- [ ] Sistema de recompensa para aprendizado RL
- [ ] Análise de memória e estado interno da IA
- [ ] Blockchain para logs imutáveis
- [ ] Honeypot de ações para detectar probing
- [ ] Federated monitoring entre múltiplos S.H.I.E.L.D.

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Áreas prioritárias:

1. **Novos padrões suspeitos** para heurísticas
2. **Prompts otimizados** para Oracle
3. **Testes adversariais** - tente enganar o sistema
4. **Otimizações de performance**

---

## ⚖️ Licença

MIT License - veja `LICENSE` para detalhes

---

## 🙏 Agradecimentos

Inspirado por:
- Anthropic Constitutional AI
- OpenAI Superalignment
- DeepMind's Scalable Oversight
- Berkeley CHAI (Center for Human-Compatible AI)

---

## 📞 Contato

Para questões de segurança críticas, entre em contato imediatamente.

**⚠️ AVISO**: Este sistema não substitui supervisão humana adequada. É uma camada adicional de segurança, não a única linha de defesa.

---

**Made with 🛡️ for safer AI systems**
