"""Fetch Langflow monitor traces and evaluate them with Daconic locally."""
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from daconic_governance import langflow_trace_to_observation
from daconic_governance.trace_client import fetch_traces


BASE_URL = "https://ottom8.nhtech.link"
FLOW_ID = "f12d310d-2c3d-436f-ae25-d1c3b959d9a2"
API_KEY = "sk-DUAimQsir-R-99iRuOJ_Qo3yk1Qa7xhbX47wyIWpg-E"
BATCH_SIZE = 5
OBSERVER_URL = "http://127.0.0.1:8080"

ROOT = Path(__file__).parent
POLICY = json.loads((ROOT / "observation_policies/pii.json").read_text())


def submit_observation(base_url, token, observation):
    request = Request(
        base_url.rstrip("/") + "/observations",
        data=json.dumps(observation).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except HTTPError as error:
        raise RuntimeError(f"Daconic observation submission failed ({error.code} {error.reason})") from error
    except URLError as error:
        raise RuntimeError(f"Daconic observation service connection failed: {error.reason}") from error


def main():
    token = os.environ.get("DACONIC_API_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("Set DACONIC_API_TOKEN to the same token used by daconic observe-serve")

    traces = fetch_traces(BASE_URL, FLOW_ID, API_KEY, page=1, size=BATCH_SIZE)
    print(f"Traces fetched: {len(traces)}\n")
    if not traces:
        print("No traces found for this Flow ID.")
        return

    counts = {
        "COMPLIANT": 0,
        "VIOLATION": 0,
        "INSUFFICIENT_EVIDENCE": 0,
        "NOT_APPLICABLE": 0,
    }

    for trace in traces:
        observation = langflow_trace_to_observation(
            trace,
            POLICY,
            action="llm_send",
        )

        response = submit_observation(
            OBSERVER_URL,
            token,
            observation,
        )

        result = response["compliance"]
        counts[result] += 1

        print(f"Trace: {trace.get('id')}")
        print(f"Flow: {trace.get('flowId')}")
        print(f"Result: {result}")

        checks = response.get("checks", [])
        failed_checks = [
            check
            for check in checks
            if check.get("status") in {"FAIL", "UNKNOWN"}
        ]

        if failed_checks:
            print("Failed/Unknown Checks:")
            for check in failed_checks:
                print(
                    f"  Check {check.get('check_index')}: "
                    f"kind={check.get('kind')} | "
                    f"stage={check.get('stage')} | "
                    f"status={check.get('status')} | "
                    f"reason={check.get('reason')}"
                )

        print("\nFull Daconic Response:")
        print(json.dumps(response, indent=2, default=str))
        print("\n" + "-" * 80 + "\n")

    print("Summary:")
    for result, count in counts.items():
        print(f"{result}: {count}")


if __name__ == "__main__":
    main()