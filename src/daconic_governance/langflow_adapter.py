"""Convert one Langflow monitor trace into a Daconic observation."""
import copy
import json
from datetime import datetime, timezone

from .observation import validate_trace


def _timestamp_ns(value, fallback):
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str):
        try:
            normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
            result = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
            if result > 0:
                return result
        except (TypeError, ValueError, OverflowError):
            pass
    if not isinstance(fallback, int) or fallback < 1:
        raise ValueError("A valid observation timestamp is required")
    return fallback


def _input_payload(trace):
    source = trace.get("input")
    if not isinstance(source, dict) or "input_value" not in source:
        return copy.deepcopy(source), source is not None
    value = source["input_value"]
    if isinstance(value, str):
        try:
            return json.loads(value), True
        except json.JSONDecodeError:
            return value, True
    return copy.deepcopy(value), True


def _output_payload(trace):
    value = trace.get("output")
    for key in ("output", "data", "value"):
        if not isinstance(value, dict) or key not in value:
            return None, False
        value = value[key]
    return copy.deepcopy(value), True


def _stage(source, observed_at_ns, payload=None, available=None):
    stage = {"availability": "unavailable", "source": source,
             "observed_at_ns": observed_at_ns, "representation": "canonical-json-v1"}
    if available is None:
        available = payload is not None
    if available:
        stage["availability"] = "present"
        stage["payload"] = copy.deepcopy(payload)
    return stage


def _policy_reference(policy):
    if not isinstance(policy, dict) or "id" not in policy or "version" not in policy:
        raise ValueError("Policy reference is required")
    return {"id": policy["id"], "version": policy["version"]}


def langflow_trace_to_observation(
    trace,
    policy,
    *,
    action="flow_execution",
    principal=None,
    delegated_user=None,
    resource=None,
    destination=None,
    source="langflow-monitor",
    observed_at_ns=None,
    transformed_payload=None,
    outbound_payload=None,
    transformed_source=None,
    outbound_source=None,
    transformed_observed_at_ns=None,
    outbound_observed_at_ns=None,
    scenario=None,
):
    """Build and validate a Daconic trace from one Langflow monitor record.

    Ottom8's monitor output value is preserved as outbound-stage evidence when
    present. It is monitor-reported output, not an independent egress capture.
    """
    if not isinstance(trace, dict):
        raise ValueError("Langflow trace must be an object")
    interaction_id = trace.get("id")
    correlation_id = trace.get("sessionId") or interaction_id
    agent_id = trace.get("flowId")
    input_payload, input_available = _input_payload(trace)
    trace_output, trace_output_available = _output_payload(trace)
    timestamp = _timestamp_ns(trace.get("startTime"), observed_at_ns)
    transformed_available = transformed_payload is not None
    outbound_available = outbound_payload is not None or trace_output_available
    observed_outbound = outbound_payload if outbound_payload is not None else trace_output
    observation = {
        "schema_version": "1",
        "interaction_id": interaction_id,
        "correlation_id": correlation_id,
        "agent_id": agent_id,
        "action": action,
        "scenario": scenario or ("with_processing" if transformed_available else "without_processing"),
        "policy": _policy_reference(policy),
        "context": {"principal": principal, "delegated_user": delegated_user,
                    "resource": resource, "destination": destination},
        "stages": {
                "input": _stage(source, timestamp, input_payload, input_available),
            "transformed": _stage(transformed_source or source,
                                   _timestamp_ns(transformed_observed_at_ns, timestamp),
                                              transformed_payload, transformed_available),
            "outbound": _stage(outbound_source or source,
                                _timestamp_ns(outbound_observed_at_ns, timestamp),
                                          observed_outbound, outbound_available),
        },
    }
    return validate_trace(observation)