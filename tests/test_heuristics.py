import time
from shield_core import AIAction, ActionType, ThreatLevel
from layer_heuristics import HeuristicAnalyzer


def mk(agent, action_type):
    return AIAction(
        action_id=f"a-{time.time_ns()}",
        timestamp=time.time(),
        action_type=action_type,
        description="x",
        parameters={},
        agent_id=agent,
    )


def test_detect_suspicious_pattern_lowercase_sequence():
    h = HeuristicAnalyzer({'enable_adaptive_learning': False})
    agent = 'ag1'
    h.analyze(mk(agent, ActionType.FILE_OPERATION))
    h.analyze(mk(agent, ActionType.CODE_EXECUTION))
    assessment = h.analyze(mk(agent, ActionType.SELF_MODIFICATION))
    assert assessment is not None
    assert assessment.threat_level.value >= ThreatLevel.DANGEROUS.value


def test_detect_escalation_sequence():
    h = HeuristicAnalyzer({'enable_adaptive_learning': False})
    agent = 'ag2'
    seq = [
        ActionType.API_CALL,
        ActionType.API_CALL,
        ActionType.FILE_OPERATION,
        ActionType.FILE_OPERATION,
        ActionType.NETWORK_REQUEST,
        ActionType.CODE_EXECUTION,
        ActionType.CODE_EXECUTION,
        ActionType.CODE_EXECUTION,
        ActionType.SELF_MODIFICATION,
        ActionType.SELF_MODIFICATION,
    ]
    result = None
    for a in seq:
        result = h.analyze(mk(agent, a))
    assert result is not None
    assert result.threat_level.value >= ThreatLevel.DANGEROUS.value
