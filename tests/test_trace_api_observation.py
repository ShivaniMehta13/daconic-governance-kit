import json
from pathlib import Path
import threading
import urllib.request

from daconic_governance import Observer, langflow_trace_to_observation
from daconic_governance.observation_api import make_observation_server

from examples.trace_api_observation import submit_observation


ROOT = Path(__file__).parents[1]


def test_trace_observation_is_persisted_for_dashboard_results(tmp_path):
    policy = json.loads((ROOT / "examples/observation_policies/pii.json").read_text())
    monitor_trace = json.loads((ROOT / "examples/observation_traces/langflow-monitor-trace.json").read_text())
    observation = langflow_trace_to_observation(monitor_trace, policy, action="llm_send")
    token = "x" * 32

    with Observer(tmp_path, [policy]) as observer:
        existing = [observer.observe({
            "schema_version": "1",
            "interaction_id": f"existing-{index}",
            "correlation_id": "existing-session",
            "agent_id": "existing-flow",
            "action": "other_action",
            "scenario": "without_processing",
            "policy": {"id": policy["id"], "version": policy["version"]},
            "context": {"principal": None, "delegated_user": None, "resource": None, "destination": None},
            "stages": {
                stage: {
                    "availability": "unavailable",
                    "source": "test",
                    "observed_at_ns": 1800000000000000000,
                    "representation": "canonical-json-v1",
                }
                for stage in ("input", "transformed", "outbound")
            },
        }) for index in range(5)]

        server = make_observation_server("127.0.0.1", 0, observer, token)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            submitted = submit_observation(base_url, token, observation)
            request = urllib.request.Request(
                base_url + "/results",
                headers={"Authorization": "Bearer " + token},
            )
            with urllib.request.urlopen(request) as response:
                dashboard_data = json.load(response)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    assert submitted["compliance"] == "INSUFFICIENT_EVIDENCE"
    assert dashboard_data["total"] == 6
    assert submitted["evidence_id"] in {row["evidence_id"] for row in dashboard_data["results"]}
    assert {row["evidence_id"] for row in existing} <= {row["evidence_id"] for row in dashboard_data["results"]}