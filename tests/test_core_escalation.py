import time
from shield_core import SHIELDCore, AIAction, ActionType, ThreatAssessment, ThreatLevel, EnforcementAction


def mk(action_type):
    return AIAction(
        action_id=str(time.time_ns()),
        timestamp=time.time(),
        action_type=action_type,
        description='x',
        parameters={},
        agent_id='ag'
    )


def test_core_skips_oracle_for_safe_non_critical_action():
    shield = SHIELDCore({'oracle': {'always_analyze': False, 'min_escalation_level': 1, 'critical_action_types': []}, 'enforcement': {'quarantine_duration_seconds': 1}})

    def perimeter(_):
        return None

    def heuristics(_):
        return None

    called = {'oracle': 0}

    def oracle(_):
        called['oracle'] += 1
        return ThreatAssessment('x', ThreatLevel.SUSPICIOUS, 0.7, ['o'], EnforcementAction.REQUIRE_APPROVAL, 'oracle')

    shield.add_layer_callback('perimeter', perimeter)
    shield.add_layer_callback('heuristics', heuristics)
    shield.add_layer_callback('oracle', oracle)

    shield.process_action(mk(ActionType.API_CALL))
    assert called['oracle'] == 0
