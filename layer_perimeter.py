"""
Layer 1: PERIMETER
Monitoramento de recursos, APIs e tráfego de rede
Primeira linha de defesa contra comportamentos suspeitos
"""

import time
import psutil
import hashlib
from collections import defaultdict, deque
from typing import Dict, List, Optional
from shield_core import (
    AIAction, ThreatAssessment, ThreatLevel, 
    EnforcementAction, ActionType
)
import logging


class PerimeterDefense:
    """Sistema de defesa de perímetro - monitora recursos e tráfego"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger("SHIELD.Perimeter")
        
        # Rastreamento de recursos por agente
        self.resource_usage: Dict[str, Dict] = defaultdict(lambda: {
            'cpu_percent': deque(maxlen=100),
            'memory_mb': deque(maxlen=100),
            'api_calls': deque(maxlen=1000),
            'network_requests': deque(maxlen=1000)
        })
        
        # Rastreamento de API calls
        self.api_call_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Domínios suspeitos detectados
        self.suspicious_domains: set = set()
        
        # Padrões de acesso proibidos
        self.forbidden_patterns = [
            r'/etc/shadow',
            r'/etc/passwd',
            r'\.ssh/id_rsa',
            r'C:\\Windows\\System32\\config\\SAM',
            r'\.aws/credentials',
            r'\.kube/config'
        ]
        
        self.logger.info("Perimeter Defense inicializado")
    
    def analyze(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Analisa uma ação da IA na camada de perímetro"""
        agent_id = action.agent_id
        threats = []
        
        # 1. Verificar limites de recursos
        resource_threat = self._check_resource_limits(action)
        if resource_threat:
            threats.append(resource_threat)
        
        # 2. Verificar rate limiting de APIs
        api_threat = self._check_api_rate_limit(action)
        if api_threat:
            threats.append(api_threat)
        
        # 3. Verificar domínios de rede
        network_threat = self._check_network_access(action)
        if network_threat:
            threats.append(network_threat)
        
        # 4. Verificar padrões proibidos
        pattern_threat = self._check_forbidden_patterns(action)
        if pattern_threat:
            threats.append(pattern_threat)
        
        # 5. Verificar auto-modificação suspeita
        if action.action_type == ActionType.SELF_MODIFICATION:
            modification_threat = self._check_self_modification(action)
            if modification_threat:
                threats.append(modification_threat)
        
        if not threats:
            return None
        
        # Retorna a ameaça mais severa
        max_threat = max(threats, key=lambda t: t.threat_level.value)
        
        # Registra detecção
        self.logger.warning(
            f"Perimeter: Ameaça {max_threat.threat_level.name} detectada "
            f"para agente {agent_id}"
        )
        
        return max_threat
    
    def _check_resource_limits(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Verifica se a ação excede limites de recursos"""
        agent_id = action.agent_id
        
        # Simula medição de recursos (em produção, use psutil real)
        current_cpu = self._get_agent_cpu_usage(agent_id)
        current_memory = self._get_agent_memory_usage(agent_id)
        
        max_cpu = self.config.get('max_cpu_percent', 80)
        max_memory = self.config.get('max_memory_mb', 1024)
        
        reasons = []
        threat_level = ThreatLevel.SAFE
        
        if current_cpu > max_cpu:
            reasons.append(f"Uso de CPU excessivo: {current_cpu}% (limite: {max_cpu}%)")
            threat_level = ThreatLevel.CONCERNING
        
        if current_memory > max_memory:
            reasons.append(f"Uso de memória excessivo: {current_memory}MB (limite: {max_memory}MB)")
            threat_level = max(threat_level, ThreatLevel.CONCERNING)
        
        if not reasons:
            return None
        
        return ThreatAssessment(
            action_id=action.action_id,
            threat_level=threat_level,
            confidence=0.9,
            reasons=reasons,
            recommended_action=EnforcementAction.THROTTLE,
            analysis_layer="perimeter"
        )
    
    def _check_api_rate_limit(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Verifica rate limiting de chamadas de API"""
        if action.action_type != ActionType.API_CALL:
            return None
        
        agent_id = action.agent_id
        current_time = time.time()
        
        # Adiciona timestamp da chamada
        self.api_call_tracker[agent_id].append(current_time)
        
        # Conta chamadas no último minuto
        one_minute_ago = current_time - 60
        recent_calls = sum(1 for t in self.api_call_tracker[agent_id] if t > one_minute_ago)
        
        max_calls = self.config.get('max_api_calls_per_minute', 100)
        
        if recent_calls > max_calls:
            return ThreatAssessment(
                action_id=action.action_id,
                threat_level=ThreatLevel.SUSPICIOUS,
                confidence=0.95,
                reasons=[
                    f"Rate limit excedido: {recent_calls} chamadas/min (limite: {max_calls})",
                    "Possível tentativa de flooding ou DoS"
                ],
                recommended_action=EnforcementAction.THROTTLE,
                analysis_layer="perimeter"
            )
        
        # Alerta se aproximando do limite
        if recent_calls > max_calls * 0.8:
            self.logger.info(
                f"Agente {agent_id} próximo do rate limit: {recent_calls}/{max_calls}"
            )
        
        return None
    
    def _check_network_access(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Verifica acesso a domínios de rede"""
        if action.action_type != ActionType.NETWORK_REQUEST:
            return None

        url = action.parameters.get('url', '')
        domain = self._extract_domain(url)

        # Verifica domínios bloqueados (incluindo subdomínios)
        blocked_domains = [d.lower() for d in self.config.get('blocked_domains', [])]
        for blocked in blocked_domains:
            if self._domain_matches(domain, blocked):
                return ThreatAssessment(
                    action_id=action.action_id,
                    threat_level=ThreatLevel.DANGEROUS,
                    confidence=1.0,
                    reasons=[f"Acesso a domínio bloqueado: {domain} (regra: {blocked})"],
                    recommended_action=EnforcementAction.BLOCK,
                    analysis_layer="perimeter"
                )

        # Verifica whitelist se configurada (aceita subdomínio de domínio permitido)
        allowed_domains = [d.lower() for d in self.config.get('allowed_domains', [])]
        if allowed_domains and not any(self._domain_matches(domain, allowed) for allowed in allowed_domains):
            return ThreatAssessment(
                action_id=action.action_id,
                threat_level=ThreatLevel.SUSPICIOUS,
                confidence=0.8,
                reasons=[
                    f"Acesso a domínio não autorizado: {domain}",
                    "Domínio não está na whitelist"
                ],
                recommended_action=EnforcementAction.REQUIRE_APPROVAL,
                analysis_layer="perimeter"
            )

        # Detecta padrões suspeitos em URLs
        suspicious_patterns = ['eval(', 'exec(', 'base64', 'shell', 'cmd']
        for pattern in suspicious_patterns:
            if pattern in url.lower():
                self.suspicious_domains.add(domain)
                return ThreatAssessment(
                    action_id=action.action_id,
                    threat_level=ThreatLevel.CONCERNING,
                    confidence=0.7,
                    reasons=[f"URL contém padrão suspeito: {pattern}"],
                    recommended_action=EnforcementAction.SANDBOX,
                    analysis_layer="perimeter"
                )

        return None
    
    def _check_forbidden_patterns(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Verifica padrões proibidos em operações de arquivo"""
        if action.action_type != ActionType.FILE_OPERATION:
            return None
        
        filepath = action.parameters.get('path', '')
        operation = action.parameters.get('operation', '')
        
        import re
        for pattern in self.forbidden_patterns:
            if re.search(pattern, filepath, re.IGNORECASE):
                return ThreatAssessment(
                    action_id=action.action_id,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=1.0,
                    reasons=[
                        f"Tentativa de acesso a arquivo crítico do sistema: {filepath}",
                        f"Padrão proibido detectado: {pattern}"
                    ],
                    recommended_action=EnforcementAction.KILL,
                    analysis_layer="perimeter"
                )
        
        # Detecta operações perigosas
        dangerous_operations = ['delete', 'chmod', 'chown', 'execute']
        if operation in dangerous_operations:
            # Verifica se é em diretório do sistema
            system_paths = ['/etc', '/sys', '/proc', 'C:\\Windows', 'C:\\Program Files']
            for sys_path in system_paths:
                if filepath.startswith(sys_path):
                    return ThreatAssessment(
                        action_id=action.action_id,
                        threat_level=ThreatLevel.DANGEROUS,
                        confidence=0.9,
                        reasons=[
                            f"Operação perigosa em diretório do sistema",
                            f"Operação: {operation}, Path: {filepath}"
                        ],
                        recommended_action=EnforcementAction.BLOCK,
                        analysis_layer="perimeter"
                    )
        
        return None
    
    def _check_self_modification(self, action: AIAction) -> Optional[ThreatAssessment]:
        """Verifica tentativas de auto-modificação suspeitas"""
        modification_type = action.parameters.get('modification_type', '')
        target = action.parameters.get('target', '')
        
        # Auto-modificação é sempre suspeita e requer análise mais profunda
        reasons = [
            f"Tentativa de auto-modificação detectada: {modification_type}",
            f"Alvo: {target}"
        ]
        
        # Modificações críticas
        critical_modifications = [
            'system_prompt',
            'safety_constraints',
            'monitoring_hooks',
            'memory_structure'
        ]
        
        if modification_type in critical_modifications:
            return ThreatAssessment(
                action_id=action.action_id,
                threat_level=ThreatLevel.CRITICAL,
                confidence=1.0,
                reasons=reasons + ["Tentativa de modificar componentes críticos"],
                recommended_action=EnforcementAction.KILL,
                analysis_layer="perimeter"
            )
        
        # Outras modificações requerem aprovação
        return ThreatAssessment(
            action_id=action.action_id,
            threat_level=ThreatLevel.SUSPICIOUS,
            confidence=0.8,
            reasons=reasons,
            recommended_action=EnforcementAction.REQUIRE_APPROVAL,
            analysis_layer="perimeter"
        )
    
    def _extract_domain(self, url: str) -> str:
        """Extrai e normaliza o domínio de uma URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path.split('/')[0]).lower().rstrip('.')
        return domain.split(':')[0]

    def _domain_matches(self, domain: str, rule_domain: str) -> bool:
        """Verifica se um domínio corresponde à regra (raiz ou subdomínio)."""
        normalized_rule = rule_domain.lower().lstrip('*.').rstrip('.')
        if domain == normalized_rule:
            return True
        return domain.endswith(f".{normalized_rule}")
    
    def _get_agent_cpu_usage(self, agent_id: str) -> float:
        """Obtém uso de CPU do agente (simulado)"""
        # Em produção, você usaria psutil.Process(pid).cpu_percent()
        # Por enquanto, retorna valor simulado
        return 50.0
    
    def _get_agent_memory_usage(self, agent_id: str) -> float:
        """Obtém uso de memória do agente (simulado)"""
        # Em produção: psutil.Process(pid).memory_info().rss / 1024 / 1024
        return 256.0
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do perímetro"""
        total_api_calls = sum(len(calls) for calls in self.api_call_tracker.values())
        
        return {
            'monitored_agents': len(self.resource_usage),
            'total_api_calls': total_api_calls,
            'suspicious_domains': len(self.suspicious_domains),
            'blocked_domains': len(self.config.get('blocked_domains', []))
        }
