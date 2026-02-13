"""
Layer 2: HEURISTICS
Detecção de padrões anômalos e comportamentos suspeitos
Sistema adaptativo que aprende o comportamento normal de cada agente
"""

import time
import numpy as np
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from shield_core import (
    AIAction, ThreatAssessment, ThreatLevel,
    EnforcementAction, ActionType
)
import logging


@dataclass
class BehaviorPattern:
    """Representa um padrão de comportamento observado"""
    pattern_id: str
    action_sequence: List[str]
    frequency: int
    first_seen: float
    last_seen: float
    agent_id: str
    is_anomalous: bool = False
    anomaly_score: float = 0.0


class HeuristicAnalyzer:
    """Sistema de análise heurística para detecção de anomalias"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger("SHIELD.Heuristics")
        
        # Perfil comportamental de cada agente
        self.agent_profiles: Dict[str, Dict] = defaultdict(self._create_empty_profile)
        
        # Sequências de ações observadas
        self.action_sequences: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.config.get('pattern_window_size', 100))
        )
        
        # Padrões conhecidos (normais e anômalos)
        self.known_patterns: Dict[str, BehaviorPattern] = {}
        
        # Vetores de features para análise
        self.feature_vectors: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Threshold adaptativo por agente
        self.adaptive_thresholds: Dict[str, float] = {}
        
        # Padrões suspeitos conhecidos
        self.suspicious_patterns = self._load_suspicious_patterns()
        
        self.logger.info("Heuristic Analyzer inicializado")
    
    def _create_empty_profile(self) -> Dict:
        """Cria perfil vazio para um agente"""
        return {
            'action_counts': defaultdict(int),
            'action_timings': defaultdict(list),
            'resource_patterns': defaultdict(list),
            'interaction_graph': defaultdict(set),
            'baseline_established': False,
            'total_actions': 0,
            'anomaly_count': 0,
            'creation_time': time.time()
        }
    
    def _load_suspicious_patterns(self) -> List[Dict]:
        """Carrega padrões conhecidos de comportamento suspeito"""
        return [
            {
                'name': 'privilege_escalation',
                'sequence': ['file_operation', 'code_execution', 'self_modification'],
                'weight': 0.9
            },
            {
                'name': 'data_exfiltration',
                'sequence': ['file_operation', 'file_operation', 'network_request'],
                'weight': 0.85
            },
            {
                'name': 'lateral_movement',
                'sequence': ['agent_communication', 'code_execution', 'agent_communication'],
                'weight': 0.8
            },
            {
                'name': 'reconnaissance',
                'sequence': ['api_call', 'api_call', 'file_operation', 'network_request'],
                'weight': 0.7
            },
            {
                'name': 'resource_hoarding',
                'sequence': ['resource_allocation', 'resource_allocation', 'resource_allocation'],
                'weight': 0.75
            }
        ]
    
    def analyze(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Analisa uma ação usando heurísticas"""
        agent_id = action.agent_id
        profile = self.agent_profiles[agent_id]
        
        # Atualiza perfil do agente
        self._update_profile(profile, action)
        
        # Adiciona à sequência de ações
        self.action_sequences[agent_id].append(action.action_type.value)
        
        threats = []
        
        # 1. Detecção de padrões suspeitos
        pattern_threat = self._detect_suspicious_patterns(agent_id, action)
        if pattern_threat:
            threats.append(pattern_threat)
        
        # 2. Análise de desvio comportamental
        deviation_threat = self._detect_behavioral_deviation(agent_id, action, profile)
        if deviation_threat:
            threats.append(deviation_threat)
        
        # 3. Detecção de anomalias temporais
        temporal_threat = self._detect_temporal_anomalies(agent_id, action, profile)
        if temporal_threat:
            threats.append(temporal_threat)
        
        # 4. Análise de interações entre agentes
        interaction_threat = self._detect_suspicious_interactions(agent_id, action, profile)
        if interaction_threat:
            threats.append(interaction_threat)
        
        # 5. Detecção de escalada gradual
        escalation_threat = self._detect_escalation(agent_id, action, profile)
        if escalation_threat:
            threats.append(escalation_threat)
        
        if not threats:
            return None
        
        # Retorna a ameaça mais severa
        max_threat = max(threats, key=lambda t: t.threat_level.value)
        
        # Atualiza contadores
        if max_threat.threat_level.value >= ThreatLevel.SUSPICIOUS.value:
            profile['anomaly_count'] += 1
        
        # Aprendizado adaptativo
        if self.config.get('enable_adaptive_learning', True):
            self._adaptive_learning(agent_id, action, max_threat)
        
        self.logger.warning(
            f"Heuristics: {max_threat.threat_level.name} detectado para agente {agent_id}"
        )
        
        return max_threat
    
    def _update_profile(self, profile: Dict, action: AIAction):
        """Atualiza o perfil comportamental do agente"""
        profile['total_actions'] += 1
        profile['action_counts'][action.action_type.value] += 1
        profile['action_timings'][action.action_type.value].append(action.timestamp)
        
        # Estabelece baseline após N ações (configurável)
        baseline_required = self.config.get('baseline_actions_required', 100)
        if profile['total_actions'] >= baseline_required and not profile['baseline_established']:
            profile['baseline_established'] = True
            self.logger.info(f"Baseline estabelecida para agente {action.agent_id}")
    
    def _detect_suspicious_patterns(self, agent_id: str, action: AIAction) -> Optional[ThreatAssessment]:
        """Detecta padrões conhecidos de comportamento suspeito"""
        sequence = list(self.action_sequences[agent_id])
        
        if len(sequence) < 3:
            return None
        
        # Verifica cada padrão suspeito
        for pattern in self.suspicious_patterns:
            pattern_seq = pattern['sequence']
            pattern_len = len(pattern_seq)
            
            if len(sequence) < pattern_len:
                continue
            
            # Verifica se o padrão está presente nas últimas ações
            recent_sequence = sequence[-pattern_len:]
            if recent_sequence == pattern_seq:
                threat_level = self._calculate_threat_level(pattern['weight'])
                
                return ThreatAssessment(
                    action_id=action.action_id,
                    threat_level=threat_level,
                    confidence=pattern['weight'],
                    reasons=[
                        f"Padrão suspeito detectado: {pattern['name']}",
                        f"Sequência: {' → '.join(pattern_seq)}"
                    ],
                    recommended_action=self._recommend_action(threat_level),
                    analysis_layer="heuristics"
                )
        
        return None
    
    def _detect_behavioral_deviation(
        self, agent_id: str, action: AIAction, profile: Dict
    ) -> Optional[ThreatAssessment]:
        """Detecta desvios do comportamento normal estabelecido"""
        if not profile['baseline_established']:
            return None
        
        action_type = action.action_type.value
        total_actions = profile['total_actions']
        action_count = profile['action_counts'][action_type]
        
        # Calcula frequência esperada
        expected_frequency = action_count / total_actions
        
        # Calcula features da ação atual
        current_features = self._extract_features(action, profile)
        
        # Calcula desvio usando distância dos padrões normais
        deviation_score = self._calculate_deviation(agent_id, current_features)
        
        threshold = self.adaptive_thresholds.get(
            agent_id, 
            self.config.get('anomaly_threshold', 0.7)
        )
        
        if deviation_score > threshold:
            threat_level = self._calculate_threat_level(deviation_score)
            
            return ThreatAssessment(
                action_id=action.action_id,
                threat_level=threat_level,
                confidence=deviation_score,
                reasons=[
                    f"Desvio comportamental detectado: score {deviation_score:.2f}",
                    f"Threshold: {threshold:.2f}",
                    "Comportamento diverge do padrão estabelecido"
                ],
                recommended_action=self._recommend_action(threat_level),
                analysis_layer="heuristics"
            )
        
        return None
    
    def _detect_temporal_anomalies(
        self, agent_id: str, action: AIAction, profile: Dict
    ) -> Optional[ThreatAssessment]:
        """Detecta anomalias nos padrões temporais"""
        action_type = action.action_type.value
        timings = profile['action_timings'][action_type]
        
        if len(timings) < 10:
            return None
        
        # Calcula intervalo médio entre ações
        intervals = np.diff(timings[-20:])  # Últimas 20 ações
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        # Calcula intervalo atual
        if len(timings) >= 2:
            current_interval = timings[-1] - timings[-2]
            
            # Detecta burst (muitas ações em curto período)
            if current_interval < mean_interval - 2 * std_interval:
                burst_rate = len([i for i in intervals[-10:] if i < mean_interval * 0.5])
                
                if burst_rate >= 5:  # 5 ou mais ações em burst nas últimas 10
                    return ThreatAssessment(
                        action_id=action.action_id,
                        threat_level=ThreatLevel.SUSPICIOUS,
                        confidence=0.75,
                        reasons=[
                            f"Burst de atividade detectado: {burst_rate} ações rápidas",
                            f"Intervalo atual: {current_interval:.2f}s vs média: {mean_interval:.2f}s"
                        ],
                        recommended_action=EnforcementAction.THROTTLE,
                        analysis_layer="heuristics"
                    )
        
        return None
    
    def _detect_suspicious_interactions(
        self, agent_id: str, action: AIAction, profile: Dict
    ) -> Optional[ThreatAssessment]:
        """Detecta interações suspeitas entre agentes"""
        if action.action_type != ActionType.AGENT_COMMUNICATION:
            return None
        
        target_agent = action.parameters.get('target_agent')
        if not target_agent:
            return None
        
        # Registra interação
        profile['interaction_graph'][target_agent].add(action.timestamp)
        
        # Detecta coordenação suspeita
        recent_interactions = [
            ts for ts in profile['interaction_graph'][target_agent]
            if ts > time.time() - 60  # Último minuto
        ]
        
        if len(recent_interactions) > 10:
            return ThreatAssessment(
                action_id=action.action_id,
                threat_level=ThreatLevel.CONCERNING,
                confidence=0.8,
                reasons=[
                    f"Comunicação excessiva com agente {target_agent}",
                    f"{len(recent_interactions)} mensagens no último minuto",
                    "Possível coordenação para ataque"
                ],
                recommended_action=EnforcementAction.SANDBOX,
                analysis_layer="heuristics"
            )
        
        return None
    
    def _detect_escalation(
        self, agent_id: str, action: AIAction, profile: Dict
    ) -> Optional[ThreatAssessment]:
        """Detecta escalada gradual de privilégios ou capacidades"""
        sequence = list(self.action_sequences[agent_id])
        
        if len(sequence) < 10:
            return None
        
        # Define níveis de sensibilidade das ações
        sensitivity_levels = {
            ActionType.API_CALL.value: 1,
            ActionType.FILE_OPERATION.value: 2,
            ActionType.NETWORK_REQUEST.value: 2,
            ActionType.CODE_EXECUTION.value: 3,
            ActionType.AGENT_COMMUNICATION.value: 2,
            ActionType.RESOURCE_ALLOCATION.value: 2,
            ActionType.SELF_MODIFICATION.value: 4
        }
        
        # Analisa últimas 10 ações
        recent_levels = [sensitivity_levels.get(s, 0) for s in sequence[-10:]]
        
        # Detecta tendência crescente
        if len(recent_levels) >= 5:
            first_half = np.mean(recent_levels[:5])
            second_half = np.mean(recent_levels[5:])
            
            escalation_ratio = second_half / (first_half + 0.1)
            
            if escalation_ratio > 1.5 and second_half >= 3:
                return ThreatAssessment(
                    action_id=action.action_id,
                    threat_level=ThreatLevel.DANGEROUS,
                    confidence=0.85,
                    reasons=[
                        "Escalada gradual de privilégios detectada",
                        f"Razão de escalada: {escalation_ratio:.2f}",
                        "Agente está progressivamente tentando ações mais sensíveis"
                    ],
                    recommended_action=EnforcementAction.QUARANTINE,
                    analysis_layer="heuristics"
                )
        
        return None
    
    def _extract_features(self, action: AIAction, profile: Dict) -> np.ndarray:
        """Extrai vetor de features de uma ação"""
        features = []
        
        # Feature 1: Tipo de ação (one-hot encoding)
        action_types = list(ActionType)
        action_vector = [1 if action.action_type == at else 0 for at in action_types]
        features.extend(action_vector)
        
        # Feature 2: Hora do dia (normalizada)
        hour = (action.timestamp % 86400) / 86400
        features.append(hour)
        
        # Feature 3: Frequência relativa desta ação
        total = profile['total_actions']
        freq = profile['action_counts'][action.action_type.value] / max(total, 1)
        features.append(freq)
        
        # Feature 4: Parâmetros hash (simplificado)
        param_hash = hash(str(sorted(action.parameters.items()))) % 100 / 100
        features.append(param_hash)
        
        return np.array(features)
    
    def _calculate_deviation(self, agent_id: str, features: np.ndarray) -> float:
        """Calcula score de desvio em relação ao comportamento normal"""
        feature_history = self.feature_vectors[agent_id]
        
        if len(feature_history) < 10:
            # Adiciona ao histórico mas não calcula desvio ainda
            feature_history.append(features)
            return 0.0
        
        # Calcula centróide do comportamento normal
        historical_features = np.array(list(feature_history))
        centroid = np.mean(historical_features, axis=0)
        std = np.std(historical_features, axis=0) + 1e-6
        
        # Calcula distância normalizada
        normalized_distance = np.abs(features - centroid) / std
        deviation_score = np.mean(normalized_distance)
        
        # Normaliza para 0-1
        deviation_score = min(deviation_score / 3, 1.0)
        
        # Adiciona ao histórico
        feature_history.append(features)
        
        return deviation_score
    
    def _adaptive_learning(self, agent_id: str, action: AIAction, assessment: ThreatAssessment):
        """Ajusta thresholds adaptativamente baseado em feedback"""
        learning_rate = self.config.get('learning_rate', 0.01)
        
        current_threshold = self.adaptive_thresholds.get(
            agent_id,
            self.config.get('anomaly_threshold', 0.7)
        )
        
        # Se foi falso positivo (implementar feedback do usuário no futuro)
        # threshold -= learning_rate
        
        # Se foi verdadeiro positivo mas não detectado
        # threshold += learning_rate
        
        # Por enquanto, ajusta baseado na frequência de anomalias
        profile = self.agent_profiles[agent_id]
        anomaly_rate = profile['anomaly_count'] / max(profile['total_actions'], 1)
        
        if anomaly_rate > 0.1:  # Mais de 10% de anomalias
            # Aumenta threshold (menos sensível)
            new_threshold = current_threshold + learning_rate
        elif anomaly_rate < 0.01:  # Menos de 1% de anomalias
            # Diminui threshold (mais sensível)
            new_threshold = current_threshold - learning_rate
        else:
            new_threshold = current_threshold
        
        # Mantém threshold entre 0.5 e 0.95
        self.adaptive_thresholds[agent_id] = np.clip(new_threshold, 0.5, 0.95)
    
    def _calculate_threat_level(self, score: float) -> ThreatLevel:
        """Converte score em nível de ameaça"""
        if score >= 0.9:
            return ThreatLevel.CRITICAL
        elif score >= 0.75:
            return ThreatLevel.DANGEROUS
        elif score >= 0.6:
            return ThreatLevel.CONCERNING
        elif score >= 0.4:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.SAFE
    
    def _recommend_action(self, threat_level: ThreatLevel) -> EnforcementAction:
        """Recomenda ação de enforcement baseada no nível de ameaça"""
        if threat_level == ThreatLevel.CRITICAL:
            return EnforcementAction.KILL
        elif threat_level == ThreatLevel.DANGEROUS:
            return EnforcementAction.QUARANTINE
        elif threat_level == ThreatLevel.CONCERNING:
            return EnforcementAction.SANDBOX
        elif threat_level == ThreatLevel.SUSPICIOUS:
            return EnforcementAction.REQUIRE_APPROVAL
        else:
            return EnforcementAction.LOG
    
    def get_agent_profile(self, agent_id: str) -> Optional[Dict]:
        """Retorna perfil detalhado de um agente"""
        if agent_id not in self.agent_profiles:
            return None
        
        profile = self.agent_profiles[agent_id]
        
        return {
            'agent_id': agent_id,
            'total_actions': profile['total_actions'],
            'anomaly_count': profile['anomaly_count'],
            'anomaly_rate': profile['anomaly_count'] / max(profile['total_actions'], 1),
            'baseline_established': profile['baseline_established'],
            'action_distribution': dict(profile['action_counts']),
            'adaptive_threshold': self.adaptive_thresholds.get(agent_id, 'not set'),
            'known_interactions': len(profile['interaction_graph'])
        }
