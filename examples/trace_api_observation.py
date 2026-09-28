"""Fetch Langflow monitor traces and evaluate them with Daconic locally."""
import json
from pathlib import Path

from daconic_governance import Observer, langflow_trace_to_observation
from daconic_governance.trace_client import fetch_traces


BASE_URL = "https://ottom8.nhtech.link"
FLOW_ID = "f12d310d-2c3d-436f-ae25-d1c3b959d9a2>"
API_KEY = "sk-DUAimQsir-R-99iRuOJ_Qo3yk1Qa7xhbX47wyIWpg-E"
BATCH_SIZE = 5

ROOT = Path(__file__).parent
POLICY = json.loads((ROOT / "observation_policies/pii.json").read_text())
traces = fetch_traces(BASE_URL, FLOW_ID, API_KEY, page=1, size=BATCH_SIZE)
print(f"Traces fetched: {len(traces)}\n")

counts = {
    "COMPLIANT": 0,
    "VIOLATION": 0,
    "INSUFFICIENT_EVIDENCE": 0,
    "NOT_APPLICABLE": 0,
}

with Observer("./trace-api-observation-state", [POLICY]) as observer:
    for trace in traces:
        observation = langflow_trace_to_observation(trace, POLICY, action="llm_send")
        result = observer.observe(observation)["compliance"]
        counts[result] += 1
        print(f"Trace: {trace.get('id')}")
        print(f"Flow: {trace.get('flowId')}")
        print(f"Result: {result}\n")

print("Summary:")
for result, count in counts.items():
    print(f"{result}: {count}")