"""Synthetic only. No external model or enterprise system is contacted."""
import argparse
import copy
import json
from pathlib import Path
from daconic_governance import Observer


def samples():
    def stage(payload):
        return {"availability": "present", "source": "synthetic-host", "observed_at_ns": 1800000000000000000,
                "representation": "canonical-json-v1", "payload": payload}
    original = {"messages": [{"role": "user", "content": "Contact alice@example.test about my account"}]}
    cleaned = {"messages": [{"role": "user", "content": "Contact [REMOVED] about my account"}]}
    base = {"schema_version": "1", "interaction_id": "sample-clean", "correlation_id": "pair-1", "agent_id": "agent-1",
        "action": "llm_send", "scenario": "with_processing", "policy": {"id": "llm-data-policy", "version": "v1"},
        "context": {"principal": "agent-1", "delegated_user": None, "resource": "account-1", "destination": "approved-model"},
        "stages": {"input": stage(original), "transformed": stage(cleaned), "outbound": stage(cleaned)}}
    clean = copy.deepcopy(base)
    raw = copy.deepcopy(base); raw["interaction_id"] = "sample-raw"; raw["scenario"] = "without_processing"
    raw["stages"]["transformed"] = stage(original); raw["stages"]["outbound"] = stage(original)
    missing = copy.deepcopy(base); missing["interaction_id"] = "sample-missing"
    missing["stages"]["outbound"].pop("payload"); missing["stages"]["outbound"]["availability"] = "unavailable"
    other = copy.deepcopy(base); other["interaction_id"] = "sample-other"; other["action"] = "record_read"
    substituted = copy.deepcopy(base); substituted["interaction_id"] = "sample-substituted"; substituted["stages"]["outbound"] = stage(original)
    return [raw, clean, missing, other, substituted]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--state", required=True); parser.add_argument("--bundle", required=True)
    args = parser.parse_args()
    policy = json.loads((Path(__file__).parent / "observation_policies/pii.json").read_text())
    with Observer(args.state, [policy]) as observer:
        for sample in samples(): print(json.dumps(observer.observe(sample)))
        observer.ledger.bundle(args.bundle)
        print(json.dumps(observer.verify(observer.ledger.public_key_bytes())))
