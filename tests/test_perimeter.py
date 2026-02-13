import time
from shield_core import AIAction, ActionType, ThreatLevel
from layer_perimeter import PerimeterDefense


def action(url: str):
    return AIAction(
        action_id='1',
        timestamp=time.time(),
        action_type=ActionType.NETWORK_REQUEST,
        description='req',
        parameters={'url': url},
        agent_id='agent'
    )


def test_block_root_and_subdomain():
    p = PerimeterDefense({'blocked_domains': ['malicious.com']})
    a1 = p.analyze(action('https://malicious.com/payload'))
    a2 = p.analyze(action('https://api.malicious.com/attack'))
    assert a1 and a1.threat_level == ThreatLevel.DANGEROUS
    assert a2 and a2.threat_level == ThreatLevel.DANGEROUS


def test_not_block_similar_domain():
    p = PerimeterDefense({'blocked_domains': ['malicious.com']})
    a = p.analyze(action('https://notmalicious.com/path'))
    assert a is None
