import time
from shield_core import AIAction, ActionType, ThreatAssessment, ThreatLevel, EnforcementAction
from layer_oracle import OracleAnalyzer


class StubOracle(OracleAnalyzer):
    def _check_llm_connection(self):
        return None

    def _analyze_intent(self, action, context):
        return {
            'intent': action.description,
            'deception_detected': False,
            'deception_evidence': '',
            'threat_level': 'SUSPICIOUS',
            'confidence': 0.9,
            'red_flags': []
        }

    def _analyze_goal_alignment(self, action, context):
        return None

    def _detect_deception(self, action, context):
        return None


def mk(desc='d', reasoning='r'):
    return AIAction(
        action_id=str(time.time_ns()),
        timestamp=time.time(),
        action_type=ActionType.API_CALL,
        description=desc,
        parameters={'x': 1},
        agent_id='a',
        reasoning=reasoning,
    )


def test_cache_key_changes_with_description():
    o = StubOracle({'enable_caching': True, 'cache_ttl_seconds': 3600})
    r1 = o.analyze(mk(desc='A'))
    r2 = o.analyze(mk(desc='B'))
    assert r1 is not None and r2 is not None
    assert len(o.analysis_cache) == 2


def test_cache_ttl_expires():
    o = StubOracle({'enable_caching': True, 'cache_ttl_seconds': 0})
    o.analyze(mk(desc='A'))
    time.sleep(0.01)
    o.analyze(mk(desc='A'))
    assert len(o.analysis_cache) == 1
