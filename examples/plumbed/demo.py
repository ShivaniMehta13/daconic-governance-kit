"""Offline, simulated outbound evaluations. Never contacts Plumbed or an LLM."""
import copy
import json
from pathlib import Path
from daconic_governance.observation import evaluate_observation

ROOT = Path(__file__).parent


def load_policy(name):
    return json.loads((ROOT / 'policies' / (name + '.json')).read_text())


def payload(name):
    return json.loads((ROOT / 'payloads' / (name + '.json')).read_text())


def trace(policy, outbound, *, transformed=None, observed=False):
    def stage(value):
        return {'availability': 'present', 'source': 'simulated-fixture',
                'observed_at_ns': 1800000000000000000,
                'representation': 'canonical-json-v1', 'payload': copy.deepcopy(value)}
    missing = {'availability': 'unavailable', 'source': 'supplied-file',
               'observed_at_ns': 1800000000000000000, 'representation': 'canonical-json-v1'}
    return {'schema_version': '1', 'interaction_id': 'plumbed-offline-example',
            'correlation_id': 'plumbed-sample-pair', 'agent_id': 'plumbed-demo',
            'action': 'llm_send', 'scenario': 'with_processing',
            'policy': {'id': policy['id'], 'version': policy['version']},
            'context': {'principal': None, 'delegated_user': None, 'resource': None, 'destination': None},
            'stages': {'input': stage(payload('raw')), 'transformed': stage(transformed if transformed is not None else payload('masked')),
                       'outbound': stage(outbound) if observed else missing}}


def _cases():
    raw, masked = payload('raw'), payload('masked')
    omitted = copy.deepcopy(masked)
    for key in ('error_trigger_endpoint', 'error_logs', 'rag_response'):
        omitted.pop(key)
    for name in ('sensitive-patterns', 'known-field-masking', 'connection-fields'):
        for label, body in [('raw', raw), ('masked', masked)]:
            yield name + '-' + label, name, trace(load_policy(name), body, observed=True)
    yield 'connection-fields-omitted', 'connection-fields', trace(load_policy('connection-fields'), omitted, observed=True)
    p = load_policy('outbound-binding')
    yield 'binding-simulated-match', 'outbound-binding', trace(p, masked, observed=True)
    yield 'binding-simulated-substitution', 'outbound-binding', trace(p, raw, observed=True)
    yield 'binding-actual-outbound-unavailable', 'outbound-binding', trace(p, None)


def cases():
    for label, name, sample in _cases():
        sample["interaction_id"] = label
        if label.endswith("-raw"):
            sample["scenario"] = "without_processing"
        yield label, name, sample


def results():
    for label, name, sample in cases():
        p = load_policy(name)
        assessment = evaluate_observation(p, sample)
        yield {'case': label, 'simulation': label != 'binding-actual-outbound-unavailable',
               'compliance': assessment['compliance'],
               'checks': [{'id': rule['id'], **result} for rule, result in zip(p['checks'], assessment['checks'])]}


if __name__ == '__main__':
    for result in results():
        print(json.dumps(result))
