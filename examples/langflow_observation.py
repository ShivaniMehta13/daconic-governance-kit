"""Convert one synthetic Langflow monitor trace and observe it locally."""
import json
from pathlib import Path

from daconic_governance import Observer, langflow_trace_to_observation


ROOT = Path(__file__).parent
trace = {
    "id": "trace-contact-001",
    "flowId": "flow-contact-001",
    "sessionId": "session-contact-001",
    "startTime": "2026-09-22T05:35:10.246956",
    "input": {"input_value": '{"name":"Test User","email":"synthetic@example.test"}'},
    "output": {"output": {"data": {"value": {"status": "success"}}}},
}
policy = json.loads((ROOT / "observation_policies/pii.json").read_text())
observation = langflow_trace_to_observation(trace, policy)

with Observer("./langflow-observation-state", [policy]) as observer:
    print(observer.observe(observation)["compliance"])