import copy
import json
from pathlib import Path
from daconic_governance.observation import Observer, replay_observation_bundle, evaluate_observation
from test_observation import demo, policy


def test_replay_and_evaluator_mismatch(policy, tmp_path):
    with Observer(tmp_path / "state", [policy]) as observer:
        observer.observe(demo.samples()[1])
        key = observer.ledger.public_key_bytes()
        data = observer.ledger.bundle(tmp_path / "bundle")
        reader = lambda h: (tmp_path / "bundle" / "blobs" / h).read_bytes()
        assert replay_observation_bundle(data, key, reader)["replay"] == "PASS"
        original = json.loads(reader(data["records"][0]["blob_hash"]))["payload"]
        original["assessment"]["implementation_hash"] = "0" * 64
        observer.ledger.append("observation", original)
        newer = observer.ledger.bundle(tmp_path / "newer")
        result = replay_observation_bundle(newer, key, lambda h: (tmp_path / "newer" / "blobs" / h).read_bytes())
        assert result["replay"] == "INCOMPLETE"


def test_replay_detects_signed_wrong_assessment(policy, tmp_path):
    with Observer(tmp_path / "state", [policy]) as observer:
        observer.observe(demo.samples()[1])
        envelope = observer.ledger.records()[0]
        payload = json.loads((observer.ledger.blobs / envelope["blob_hash"]).read_bytes())["payload"]
        payload["assessment"]["compliance"] = "VIOLATION"
        observer.ledger.append("observation", payload)
        data = observer.ledger.bundle(tmp_path / "bundle")
        result = replay_observation_bundle(data, observer.ledger.public_key_bytes(), lambda h: (tmp_path / "bundle" / "blobs" / h).read_bytes())
        assert result["integrity"]["status"] == "PASS"
        assert result["replay"] == "FAIL"


def test_predicates_and_missing_context(policy):
    trace = demo.samples()[1]
    policy["checks"] = [
        {"id": "required", "kind": "required", "stage": "outbound", "path": "/messages", "value": None},
        {"id": "forbidden", "kind": "forbidden", "stage": "outbound", "path": "/password", "value": None},
        {"id": "equals", "kind": "equals", "stage": "context", "path": "/destination", "value": "approved-model"}]
    assert evaluate_observation(policy, trace)["compliance"] == "COMPLIANT"
    trace["context"]["destination"] = None
    assert evaluate_observation(policy, trace)["compliance"] == "INSUFFICIENT_EVIDENCE"
    trace["stages"]["outbound"]["payload"]["password"] = None
    assert evaluate_observation(policy, trace)["compliance"] == "VIOLATION"
