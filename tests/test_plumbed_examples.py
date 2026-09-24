"""Acceptance examples and detector limitations derived from Plumbed's sample."""
import copy
import importlib.util
from pathlib import Path
import pytest
from daconic_governance.observation import evaluate_observation
from daconic_governance.classification import classify

spec = importlib.util.spec_from_file_location('plumbed_demo', Path(__file__).parents[1] / 'examples/plumbed/demo.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


def test_sample_matrix():
    assert {r['case']: r['compliance'] for r in demo.results()} == {
        'sensitive-patterns-raw': 'VIOLATION',
        'sensitive-patterns-masked': 'VIOLATION',  # Documentation URL numeric ID, not a confirmed card.
        'known-field-masking-raw': 'VIOLATION',
        'known-field-masking-masked': 'COMPLIANT',
        'connection-fields-raw': 'VIOLATION',
        'connection-fields-masked': 'VIOLATION',
        'connection-fields-omitted': 'COMPLIANT',
        'binding-simulated-match': 'COMPLIANT',
        'binding-simulated-substitution': 'VIOLATION',
        'binding-actual-outbound-unavailable': 'INSUFFICIENT_EVIDENCE',
    }


def test_known_card_false_positive_is_visible():
    findings = classify(demo.payload('masked'))
    assert [(f['category'], f['path']) for f in findings] == [('PAYMENT_CARD', '/target_api_doc_urls/2')]


@pytest.mark.parametrize('extra,category', [
    ('email nested in prompt: person@example.test', 'PII'),
    ('password=synthetic_demo_only', 'CREDENTIAL'),
    ('test card 4111 1111 1111 1111', 'PAYMENT_CARD'),
])
def test_sensitive_data_in_embedded_text(extra, category):
    p = demo.load_policy('sensitive-patterns')
    body = demo.payload('masked')
    body['target_api_doc_urls'] = []  # Isolate the injected signal from the known URL false positive.
    body['prompt_with_relevant_data_objects'] += extra
    result = evaluate_observation(p, demo.trace(p, body, observed=True))
    index = ['PII', 'CREDENTIAL', 'PAYMENT_CARD'].index(category)
    assert result['checks'][index]['status'] == 'FAIL'


def test_missing_known_field_is_unknown_not_pass():
    p = demo.load_policy('known-field-masking')
    body = demo.payload('masked')
    del body['flattened_source_data']['name']
    result = evaluate_observation(p, demo.trace(p, body, observed=True))
    assert result['compliance'] == 'INSUFFICIENT_EVIDENCE'


def test_null_connection_field_is_still_forbidden():
    p = demo.load_policy('connection-fields')
    body = {key: None for key in ['error_trigger_endpoint', 'error_logs', 'rag_response']}
    assert evaluate_observation(p, demo.trace(p, body, observed=True))['compliance'] == 'VIOLATION'


def test_unavailable_outbound_never_passes_any_profile():
    for name in ['sensitive-patterns', 'known-field-masking', 'connection-fields', 'outbound-binding']:
        p = demo.load_policy(name)
        assert evaluate_observation(p, demo.trace(p, None))['compliance'] == 'INSUFFICIENT_EVIDENCE'
