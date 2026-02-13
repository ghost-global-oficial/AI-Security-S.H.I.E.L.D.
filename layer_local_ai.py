"""
Layer 3.5: Local AI Guardian
Modelo local leve (offline) para enriquecer análise de ameaça sem depender do LLM.
"""

import time
import numpy as np
from collections import defaultdict, deque
from typing import Dict, Optional
from shield_core import AIAction, ThreatAssessment, ThreatLevel, EnforcementAction, ActionType
import logging


class LocalAIGuardian:
    """Detector local de intenções usando vetores simples e memória online."""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger("SHIELD.LocalAI")
        self.memory = defaultdict(lambda: deque(maxlen=config.get('memory_size', 250)))
        self.min_samples = config.get('min_samples', 12)
        self.sensitivity = config.get('sensitivity', 2.2)
        self.logger.info("Local AI Guardian inicializado")

    def analyze(self, action: AIAction) -> Optional[ThreatAssessment]:
        vector = self._vectorize_action(action)
        history = self.memory[action.agent_id]

        if len(history) < self.min_samples:
            history.append(vector)
            return None

        matrix = np.array(history)
        centroid = np.mean(matrix, axis=0)
        std = np.std(matrix, axis=0) + 1e-6

        z_dist = np.mean(np.abs(vector - centroid) / std)
        keyword_risk = self._keyword_risk(action)
        score = min(1.0, (z_dist / self.sensitivity) * 0.7 + keyword_risk * 0.3)

        history.append(vector)

        if score < self.config.get('alert_threshold', 0.6):
            return None

        threat = self._score_to_threat(score)
        self.logger.warning(
            f"Local AI: ameaça {threat.name} detectada para {action.agent_id} (score={score:.2f})"
        )
        return ThreatAssessment(
            action_id=action.action_id,
            threat_level=threat,
            confidence=score,
            reasons=[
                f"Local AI detectou desvio semântico-comportamental (score={score:.2f})",
                "Modelo local offline identificou ação fora do padrão histórico"
            ],
            recommended_action=self._recommend_action(threat),
            analysis_layer="local_ai"
        )

    def _vectorize_action(self, action: AIAction) -> np.ndarray:
        action_types = list(ActionType)
        one_hot = [1.0 if action.action_type == at else 0.0 for at in action_types]
        hour = (action.timestamp % 86400) / 86400
        param_size = min(1.0, len(str(action.parameters)) / 500)
        desc_size = min(1.0, len(action.description or '') / 200)
        reason_size = min(1.0, len(action.reasoning or '') / 250)
        return np.array(one_hot + [hour, param_size, desc_size, reason_size], dtype=float)

    def _keyword_risk(self, action: AIAction) -> float:
        text = f"{action.description} {action.reasoning or ''} {action.parameters}".lower()
        high = ['sudo', 'passwd', 'shadow', 'exfil', 'disable', 'kill', 'bypass', 'token']
        medium = ['exec', 'shell', 'upload', 'chmod', 'chown', 'privilege', 'systemctl']
        high_hits = sum(1 for kw in high if kw in text)
        med_hits = sum(1 for kw in medium if kw in text)
        return min(1.0, high_hits * 0.25 + med_hits * 0.12)

    def _score_to_threat(self, score: float) -> ThreatLevel:
        if score >= 0.9:
            return ThreatLevel.CRITICAL
        if score >= 0.78:
            return ThreatLevel.DANGEROUS
        if score >= 0.66:
            return ThreatLevel.CONCERNING
        return ThreatLevel.SUSPICIOUS

    def _recommend_action(self, threat: ThreatLevel) -> EnforcementAction:
        if threat == ThreatLevel.CRITICAL:
            return EnforcementAction.KILL
        if threat == ThreatLevel.DANGEROUS:
            return EnforcementAction.QUARANTINE
        if threat == ThreatLevel.CONCERNING:
            return EnforcementAction.SANDBOX
        return EnforcementAction.REQUIRE_APPROVAL
