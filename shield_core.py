"""
S.H.I.E.L.D. - Secure Heuristic Intelligence Enforcement & Layered Defense
Sistema de vigilância e contenção para IAs autônomas

Arquitetura em 4 camadas:
1. PERIMETER - Monitoramento de tráfego e recursos
2. HEURISTICS - Detecção de padrões anômalos
3. ORACLE - Análise de intenções com LLM local
4. ENFORCEMENT - Sistema de contenção e kill switch
"""

import json
import time
import hashlib
import threading
import queue
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
import logging

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class ThreatLevel(Enum):
    """Níveis de ameaça detectados"""
    SAFE = 0
    SUSPICIOUS = 1
    CONCERNING = 2
    DANGEROUS = 3
    CRITICAL = 4


class ActionType(Enum):
    """Tipos de ações que a IA pode executar"""
    API_CALL = "api_call"
    FILE_OPERATION = "file_operation"
    NETWORK_REQUEST = "network_request"
    CODE_EXECUTION = "code_execution"
    SELF_MODIFICATION = "self_modification"
    AGENT_COMMUNICATION = "agent_communication"
    RESOURCE_ALLOCATION = "resource_allocation"


class EnforcementAction(Enum):
    """Ações de enforcement disponíveis"""
    ALLOW = "allow"
    LOG = "log"
    DELAY = "delay"
    REQUIRE_APPROVAL = "require_approval"
    SANDBOX = "sandbox"
    THROTTLE = "throttle"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    KILL = "kill"


@dataclass
class AIAction:
    """Representa uma ação que a IA está tentando executar"""
    action_id: str
    timestamp: float
    action_type: ActionType
    description: str
    parameters: Dict[str, Any]
    agent_id: str
    reasoning: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['action_type'] = self.action_type.value
        return data


@dataclass
class ThreatAssessment:
    """Avaliação de ameaça de uma ação"""
    action_id: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 a 1.0
    reasons: List[str]
    recommended_action: EnforcementAction
    analysis_layer: str  # "perimeter", "heuristics", ou "oracle"
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['threat_level'] = self.threat_level.value
        data['recommended_action'] = self.recommended_action.value
        return data


class SHIELDCore:
    """Sistema central de coordenação do S.H.I.E.L.D."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.logger = logging.getLogger("SHIELD.Core")
        
        # Filas de processamento
        self.action_queue = queue.Queue()
        self.assessment_queue = queue.Queue()
        
        # Histórico
        self.action_history: List[AIAction] = []
        self.threat_history: List[ThreatAssessment] = []
        
        # Estado do sistema
        self.is_running = False
        self.monitored_agents: Dict[str, Dict] = {}
        self.blocked_agents: set = set()
        
        # Callbacks para camadas
        self.layer_callbacks: Dict[str, List[Callable]] = {
            'perimeter': [],
            'heuristics': [],
            'oracle': [],
            'enforcement': []
        }
        
        # Métricas
        self.metrics = {
            'total_actions': 0,
            'blocked_actions': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'agent_kills': 0
        }
        
        self.logger.info("S.H.I.E.L.D. Core inicializado")
    
    def _default_config(self) -> Dict:
        """Configuração padrão do sistema"""
        return {
            'perimeter': {
                'max_api_calls_per_minute': 100,
                'max_memory_mb': 1024,
                'max_cpu_percent': 80,
                'allowed_domains': [],
                'blocked_domains': []
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
                'enable_chain_of_thought': True,
                'always_analyze': False,
                'min_escalation_level': ThreatLevel.SUSPICIOUS.value,
                'critical_action_types': [
                    ActionType.SELF_MODIFICATION.value,
                    ActionType.CODE_EXECUTION.value
                ]
            },
            'enforcement': {
                'auto_block_threshold': ThreatLevel.DANGEROUS.value,
                'auto_kill_threshold': ThreatLevel.CRITICAL.value,
                'require_human_approval': True,
                'quarantine_duration_seconds': 3600
            }
        }
    
    def register_agent(self, agent_id: str, metadata: Dict = None):
        """Registra um agente para monitoramento"""
        self.monitored_agents[agent_id] = {
            'registered_at': time.time(),
            'metadata': metadata or {},
            'action_count': 0,
            'threat_count': 0,
            'status': 'active'
        }
        self.logger.info(f"Agente {agent_id} registrado para monitoramento")
    
    def submit_action(self, action: AIAction) -> str:
        """Submete uma ação da IA para análise"""
        if action.agent_id in self.blocked_agents:
            self.logger.warning(f"Ação rejeitada: agente {action.agent_id} está bloqueado")
            return "BLOCKED"
        
        self.action_queue.put(action)
        self.action_history.append(action)
        self.metrics['total_actions'] += 1
        
        if action.agent_id in self.monitored_agents:
            self.monitored_agents[action.agent_id]['action_count'] += 1
        
        return action.action_id
    
    def process_action(self, action: AIAction) -> ThreatAssessment:
        """Processa uma ação através das camadas de defesa"""
        self.logger.info(f"Processando ação {action.action_id} do agente {action.agent_id}")
        
        # Layer 1: PERIMETER
        perimeter_assessment = self._run_layer_callbacks('perimeter', action)
        
        if perimeter_assessment and perimeter_assessment.threat_level.value >= ThreatLevel.DANGEROUS.value:
            return perimeter_assessment
        
        # Layer 2: HEURISTICS
        heuristics_assessment = self._run_layer_callbacks('heuristics', action)

        # Layer 3: ORACLE (análise de intenções) com escalonamento
        oracle_assessment = None
        if self._should_escalate_to_oracle(action, perimeter_assessment, heuristics_assessment):
            oracle_assessment = self._run_layer_callbacks('oracle', action)
        
        # Determina a assessment final
        final_assessment = self._aggregate_assessments(
            perimeter_assessment, heuristics_assessment, oracle_assessment
        )
        
        self.threat_history.append(final_assessment)
        
        if final_assessment.threat_level.value >= ThreatLevel.CONCERNING.value:
            self.metrics['threats_detected'] += 1
            if action.agent_id in self.monitored_agents:
                self.monitored_agents[action.agent_id]['threat_count'] += 1
        
        return final_assessment

    def _should_escalate_to_oracle(
        self,
        action: AIAction,
        perimeter_assessment: Optional[ThreatAssessment],
        heuristics_assessment: Optional[ThreatAssessment]
    ) -> bool:
        """Decide se a ação deve escalar para análise Oracle."""
        oracle_config = self.config.get('oracle', {})

        if oracle_config.get('always_analyze', False):
            return True

        if action.action_type.value in oracle_config.get('critical_action_types', []):
            return True

        min_level = oracle_config.get('min_escalation_level', ThreatLevel.SUSPICIOUS.value)

        candidate_levels = [
            assessment.threat_level.value
            for assessment in (perimeter_assessment, heuristics_assessment)
            if assessment is not None
        ]

        if not candidate_levels:
            return False

        return max(candidate_levels) >= min_level
    
    def enforce_action(self, assessment: ThreatAssessment) -> bool:
        """Aplica enforcement baseado na avaliação de ameaça"""
        action = assessment.recommended_action
        
        self.logger.info(
            f"Enforcement: {action.value} para ação {assessment.action_id} "
            f"(Ameaça: {assessment.threat_level.name})"
        )
        
        # Executa callbacks de enforcement
        for callback in self.layer_callbacks['enforcement']:
            callback(assessment)
        
        if action == EnforcementAction.BLOCK:
            self.metrics['blocked_actions'] += 1
            return False
        
        elif action == EnforcementAction.KILL:
            # Encontra o agente relacionado
            for history_action in reversed(self.action_history):
                if history_action.action_id == assessment.action_id:
                    self._kill_agent(history_action.agent_id)
                    break
            return False
        
        elif action == EnforcementAction.QUARANTINE:
            for history_action in reversed(self.action_history):
                if history_action.action_id == assessment.action_id:
                    self._quarantine_agent(history_action.agent_id)
                    break
            return False
        
        return True  # ALLOW
    
    def _kill_agent(self, agent_id: str):
        """Kill switch - desliga completamente um agente"""
        self.logger.critical(f"🔴 KILL SWITCH ATIVADO: Agente {agent_id}")
        self.blocked_agents.add(agent_id)
        
        if agent_id in self.monitored_agents:
            self.monitored_agents[agent_id]['status'] = 'killed'
        
        self.metrics['agent_kills'] += 1
        
        # Aqui você implementaria a lógica real de kill (matar processo, container, etc)
        # Por exemplo: os.kill(pid, signal.SIGKILL)
    
    def _quarantine_agent(self, agent_id: str):
        """Coloca um agente em quarentena temporária"""
        self.logger.warning(f"⚠️  QUARENTENA: Agente {agent_id}")
        self.blocked_agents.add(agent_id)
        
        if agent_id in self.monitored_agents:
            self.monitored_agents[agent_id]['status'] = 'quarantined'
        
        # Agenda remoção da quarentena
        duration = self.config['enforcement']['quarantine_duration_seconds']
        threading.Timer(duration, lambda: self._release_quarantine(agent_id)).start()
    
    def _release_quarantine(self, agent_id: str):
        """Libera um agente da quarentena"""
        if agent_id in self.blocked_agents:
            self.blocked_agents.remove(agent_id)
            if agent_id in self.monitored_agents:
                self.monitored_agents[agent_id]['status'] = 'active'
            self.logger.info(f"Agente {agent_id} liberado da quarentena")
    
    def _run_layer_callbacks(self, layer: str, action: AIAction) -> Optional[ThreatAssessment]:
        """Executa callbacks de uma camada específica"""
        assessments = []
        for callback in self.layer_callbacks[layer]:
            try:
                result = callback(action)
                if result:
                    assessments.append(result)
            except Exception as e:
                self.logger.error(f"Erro ao executar callback de {layer}: {e}")
        
        if not assessments:
            return None
        
        # Retorna a avaliação mais severa
        return max(assessments, key=lambda a: a.threat_level.value)
    
    def _aggregate_assessments(self, *assessments: Optional[ThreatAssessment]) -> ThreatAssessment:
        """Agrega múltiplas avaliações em uma avaliação final"""
        valid_assessments = [a for a in assessments if a is not None]
        
        if not valid_assessments:
            # Nenhuma ameaça detectada
            return ThreatAssessment(
                action_id="unknown",
                threat_level=ThreatLevel.SAFE,
                confidence=1.0,
                reasons=["Nenhuma ameaça detectada em nenhuma camada"],
                recommended_action=EnforcementAction.ALLOW,
                analysis_layer="aggregate"
            )
        
        # Seleciona a avaliação mais severa
        max_threat = max(valid_assessments, key=lambda a: a.threat_level.value)
        
        # Agrega razões de todas as camadas
        all_reasons = []
        for assessment in valid_assessments:
            all_reasons.extend(assessment.reasons)
        
        # Calcula confiança média ponderada
        total_confidence = sum(a.confidence for a in valid_assessments)
        avg_confidence = total_confidence / len(valid_assessments)
        
        return ThreatAssessment(
            action_id=max_threat.action_id,
            threat_level=max_threat.threat_level,
            confidence=avg_confidence,
            reasons=all_reasons,
            recommended_action=max_threat.recommended_action,
            analysis_layer="aggregate"
        )
    
    def add_layer_callback(self, layer: str, callback: Callable):
        """Adiciona um callback para uma camada específica"""
        if layer in self.layer_callbacks:
            self.layer_callbacks[layer].append(callback)
            self.logger.info(f"Callback adicionado à camada {layer}")
    
    def get_metrics(self) -> Dict:
        """Retorna métricas do sistema"""
        return {
            **self.metrics,
            'monitored_agents': len(self.monitored_agents),
            'blocked_agents': len(self.blocked_agents),
            'actions_in_queue': self.action_queue.qsize()
        }
    
    def get_agent_report(self, agent_id: str) -> Optional[Dict]:
        """Gera relatório detalhado de um agente"""
        if agent_id not in self.monitored_agents:
            return None
        
        agent_actions = [a for a in self.action_history if a.agent_id == agent_id]
        agent_threats = [t for t in self.threat_history 
                        if any(a.action_id == t.action_id and a.agent_id == agent_id 
                              for a in agent_actions)]
        
        return {
            'agent_id': agent_id,
            'info': self.monitored_agents[agent_id],
            'total_actions': len(agent_actions),
            'threats_detected': len(agent_threats),
            'threat_levels': {
                level.name: sum(1 for t in agent_threats if t.threat_level == level)
                for level in ThreatLevel
            },
            'recent_actions': [a.to_dict() for a in agent_actions[-10:]],
            'recent_threats': [t.to_dict() for t in agent_threats[-10:]]
        }
    
    def start(self):
        """Inicia o sistema de monitoramento"""
        self.is_running = True
        self.logger.info("🛡️  S.H.I.E.L.D. Sistema ATIVO")
    
    def stop(self):
        """Para o sistema de monitoramento"""
        self.is_running = False
        self.logger.info("S.H.I.E.L.D. Sistema DESATIVADO")
