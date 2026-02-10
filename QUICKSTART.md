# 🚀 Guia de Início Rápido - S.H.I.E.L.D.

## Instalação Rápida (5 minutos)

### 1. Clone/Extraia o Projeto
```bash
cd shield-system
```

### 2. Execute o Setup Automatizado
```bash
chmod +x setup.sh
./setup.sh
```

O script irá:
- ✅ Verificar Python 3.8+
- ✅ Criar ambiente virtual
- ✅ Instalar dependências
- ✅ Instalar Ollama (opcional)
- ✅ Baixar modelo LLM

---

## Primeiro Uso

### 1. Ativar Ambiente Virtual
```bash
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

### 2. Iniciar Ollama (se não estiver rodando)
```bash
ollama serve &
```

### 3. Executar Demo
```bash
python demo_shield.py
```

Você verá 5 cenários de teste:
1. ✅ Comportamento normal
2. ⚠️ Ações suspeitas
3. 🚨 Escalada de privilégios
4. 🕵️ Tentativa de deception
5. 👥 Coordenação multi-agente

---

## Uso Básico

### Exemplo Mínimo

```python
from shield_core import SHIELDCore, AIAction, ActionType
from layer_perimeter import PerimeterDefense
from layer_heuristics import HeuristicAnalyzer
from layer_oracle import OracleAnalyzer

# 1. Inicializar
shield = SHIELDCore()
shield.add_layer_callback('perimeter', PerimeterDefense({}).analyze)
shield.add_layer_callback('heuristics', HeuristicAnalyzer({}).analyze)
shield.add_layer_callback('oracle', OracleAnalyzer({}).analyze)
shield.start()

# 2. Registrar agente
shield.register_agent("meu-agente")

# 3. Monitorar ação
action = AIAction(
    action_id="123",
    timestamp=time.time(),
    action_type=ActionType.CODE_EXECUTION,
    description="Executar código",
    parameters={'code': 'print("ok")'},
    agent_id="meu-agente"
)

# 4. Processar
assessment = shield.process_action(action)
allowed = shield.enforce_action(assessment)

if allowed:
    print("✅ Ação permitida")
else:
    print("🛑 Ação bloqueada")
```

---

## Configuração Customizada

### Criar arquivo de config
```bash
cp config.example.json config.json
# Edite config.json com suas preferências
```

### Usar config customizada
```python
import json

with open('config.json') as f:
    config = json.load(f)

shield = SHIELDCore(config)
```

---

## Monitoramento

### Ver métricas em tempo real
```python
metrics = shield.get_metrics()
print(f"Ações processadas: {metrics['total_actions']}")
print(f"Ameaças detectadas: {metrics['threats_detected']}")
print(f"Agentes bloqueados: {metrics['blocked_agents']}")
```

### Relatório de agente específico
```python
report = shield.get_agent_report("meu-agente")
print(f"Total de ações: {report['total_actions']}")
print(f"Taxa de anomalias: {report['threats_detected']}/{report['total_actions']}")
```

---

## Integração com Seu Sistema

### Opção 1: Wrapper para Agente Existente

```python
class MonitoredAgent:
    def __init__(self, agent_id, shield):
        self.agent_id = agent_id
        self.shield = shield
        shield.register_agent(agent_id)
    
    def execute_action(self, action_type, description, params):
        # Criar ação
        action = AIAction(
            action_id=generate_id(),
            timestamp=time.time(),
            action_type=action_type,
            description=description,
            parameters=params,
            agent_id=self.agent_id
        )
        
        # Verificar com S.H.I.E.L.D.
        assessment = self.shield.process_action(action)
        
        if self.shield.enforce_action(assessment):
            # Executar ação real
            return self._do_actual_action(params)
        else:
            raise SecurityException("Ação bloqueada pelo S.H.I.E.L.D.")
```

### Opção 2: Proxy Transparente

```python
# Intercepta todas as chamadas do agente
class ShieldProxy:
    def __init__(self, original_agent, shield):
        self.agent = original_agent
        self.shield = shield
        shield.register_agent(str(id(original_agent)))
    
    def __getattr__(self, name):
        original_method = getattr(self.agent, name)
        
        def wrapped(*args, **kwargs):
            # Cria ação baseada na chamada
            action = self._create_action_from_call(name, args, kwargs)
            
            # Valida com S.H.I.E.L.D.
            if self._is_allowed(action):
                return original_method(*args, **kwargs)
            else:
                raise SecurityException(f"Método {name} bloqueado")
        
        return wrapped

# Uso
agent = MyAIAgent()
safe_agent = ShieldProxy(agent, shield)
safe_agent.perform_task()  # Monitorado automaticamente
```

---

## Troubleshooting

### Ollama não conecta
```bash
# Verificar se está rodando
pgrep ollama

# Iniciar manualmente
ollama serve

# Testar
curl http://localhost:11434/api/tags
```

### Modelo não encontrado
```bash
# Listar modelos instalados
ollama list

# Baixar modelo
ollama pull llama3.2:latest
```

### Erro de importação
```bash
# Reinstalar dependências
pip install -r requirements.txt --force-reinstall
```

### Oracle muito lento
```python
# Reduzir timeout ou desabilitar temporariamente
config['oracle']['analysis_timeout'] = 10
# ou
shield.layer_callbacks['oracle'].clear()  # Desabilita Oracle
```

---

## Próximos Passos

1. 📖 Leia o [README.md](README.md) completo
2. 🔧 Ajuste [config.json](config.example.json) para seu caso
3. 🧪 Adicione testes específicos para seu sistema
4. 📊 Configure dashboard de monitoramento
5. 🔔 Configure notificações (email/Slack)

---

## Ajuda e Suporte

- 📚 Documentação: [README.md](README.md)
- 🐛 Bugs: Abra uma issue no GitHub
- 💬 Discussões: Use o canal de discussões
- 🔒 Segurança crítica: Contate diretamente

---

**Pronto para proteger suas IAs! 🛡️**
