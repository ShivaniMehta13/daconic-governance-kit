import json
from pathlib import Path

from daconic_governance import Observer, langflow_trace_to_observation
from daconic_governance.observation import validate_trace


ROOT = Path(__file__).parents[1]


def policy():
    return json.loads((ROOT / "examples/observation_policies/pii.json").read_text())


def langflow_trace(input_value='{"name":"Test User","email":"synthetic@example.test"}'):
    return {
        "id": "trace-contact-001",
        "flowId": "flow-contact-001",
        "flowName": "Synthetic Contact Flow",
        "sessionId": "session-contact-001",
        "startTime": "2026-09-22T05:35:10.246956",
        "status": "ok",
        "input": {"input_value": input_value},
        "output": {"output": {"data": {"value": {"status": "success"}}}},
    }


def test_langflow_trace_maps_and_validates():
    observation = langflow_trace_to_observation(langflow_trace(), policy())
    validate_trace(observation)
    assert observation["interaction_id"] == "trace-contact-001"
    assert observation["correlation_id"] == "session-contact-001"
    assert observation["agent_id"] == "flow-contact-001"
    assert observation["action"] == "flow_execution"
    assert observation["stages"]["input"]["payload"]["email"] == "synthetic@example.test"
    assert observation["stages"]["input"]["observed_at_ns"] == 1790055310246956000


def test_malformed_input_is_preserved_and_unavailable_stages_are_not_inferred():
    observation = langflow_trace_to_observation(langflow_trace("not-json"), policy())
    assert observation["stages"]["input"]["payload"] == "not-json"
    assert observation["stages"]["transformed"]["availability"] == "unavailable"
    assert observation["stages"]["outbound"]["availability"] == "unavailable"


def test_explicit_snapshots_are_mapped_with_configured_metadata():
    observation = langflow_trace_to_observation(
        langflow_trace(),
        policy(),
        principal="synthetic-service",
        destination="synthetic-endpoint",
        transformed_payload={"name": "Test User", "email": "[REMOVED]"},
        outbound_payload={"name": "Test User", "email": "[REMOVED]"},
        transformed_source="langflow-transform-hook",
        outbound_source="synthetic-egress-hook",
        transformed_observed_at_ns=1800000000000000001,
        outbound_observed_at_ns=1800000000000000002,
    )
    assert observation["scenario"] == "with_processing"
    assert observation["context"]["destination"] == "synthetic-endpoint"
    assert observation["stages"]["transformed"]["payload"]["email"] == "[REMOVED]"
    assert observation["stages"]["outbound"]["source"] == "synthetic-egress-hook"
    assert observation["stages"]["outbound"]["observed_at_ns"] == 1800000000000000002


def test_observation_can_be_submitted_to_observer(tmp_path):
    trace = langflow_trace_to_observation(langflow_trace(), policy(), action="llm_send")
    with Observer(tmp_path, [policy()]) as observer:
        result = observer.observe(trace)
    assert result["compliance"] == "INSUFFICIENT_EVIDENCE"