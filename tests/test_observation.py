import copy
import importlib.util
import json
from pathlib import Path
import threading
import urllib.request
import urllib.error

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from daconic_governance.observation import Observer, evaluate_observation, validate_observation_policy
from daconic_governance.observation_api import make_observation_server
from daconic_governance.common import Conflict, canonical
from daconic_governance.evidence import verify_bundle
from daconic_governance.trace_adapters import structured_trace, event_trace

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("obs_demo", ROOT / "examples/observation_demo.py")
demo = importlib.util.module_from_spec(spec); spec.loader.exec_module(demo)


@pytest.fixture
def policy(): return json.loads((ROOT / "examples/observation_policies/pii.json").read_text())


def test_scenarios(policy):
    assert [evaluate_observation(policy, t)["compliance"] for t in demo.samples()] == ["VIOLATION", "COMPLIANT", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE", "VIOLATION"]


def test_violation_survives_missing_binding(policy):
    trace = demo.samples()[0]
    trace["stages"]["transformed"].pop("payload"); trace["stages"]["transformed"]["availability"] = "unavailable"
    result = evaluate_observation(policy, trace)
    assert result["compliance"] == "VIOLATION"
    assert any(c["status"] == "UNKNOWN" for c in result["checks"])


@pytest.mark.parametrize("payload", [{}, [], "", None])
def test_empty_not_missing(policy, payload):
    trace = demo.samples()[1]
    for stage in ("transformed", "outbound"): trace["stages"][stage]["payload"] = payload
    result = evaluate_observation(policy, trace)
    assert result["checks"][-1]["status"] == "PASS"
    assert result["compliance"] == ("INSUFFICIENT_EVIDENCE" if payload is None else "COMPLIANT")


def test_masked_cannot_prove_absence(policy):
    trace = demo.samples()[1]; trace["stages"]["outbound"]["availability"] = "masked"
    assert evaluate_observation(policy, trace)["compliance"] == "INSUFFICIENT_EVIDENCE"


def test_policy_version_and_unknown_predicate(policy, tmp_path):
    with Observer(tmp_path, [policy]) as observer:
        changed = copy.deepcopy(policy); changed["actions"] = ["other"]
        with pytest.raises(Conflict): observer.install(changed)
        trace = demo.samples()[1]; trace["policy"]["version"] = "v2"
        with pytest.raises(ValueError): observer.observe(trace)
    policy["checks"][0]["kind"] = "execute"
    with pytest.raises(ValueError): validate_observation_policy(policy)


def test_durable_idempotency_and_immutable_inputs(policy, tmp_path):
    trace = demo.samples()[1]; before = copy.deepcopy(trace)
    with Observer(tmp_path, [policy]) as observer:
        first = observer.observe(trace)
        assert observer.check(trace)["compliance"] == "COMPLIANT"
        assert trace == before
    with Observer(tmp_path, [policy]) as observer:
        assert observer.observe(trace) == first
        assert len(observer.results()) == 1
        trace["scenario"] = "without_processing"
        with pytest.raises(Conflict): observer.observe(trace)
    assert before == demo.samples()[1]


def test_concurrent_duplicate(policy, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    with Observer(tmp_path, [policy]) as observer, ThreadPoolExecutor(4) as pool:
        results = list(pool.map(observer.observe, [demo.samples()[1]] * 8))
        assert len({r["evidence_id"] for r in results}) == 1
        assert len(observer.results()) == 1


def test_no_dispatch_and_safe_projection(policy, tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("Network dispatched"))
    from daconic_governance.broker import Broker
    monkeypatch.setattr(Broker, "execute", lambda *a, **k: pytest.fail("Broker dispatched"))
    with Observer(tmp_path, [policy]) as observer:
        raw = demo.samples()[0]
        raw["context"]["principal"] = "sensitive-person@example.test"
        report = observer.observe(raw)
        encoded = json.dumps(report)
        for forbidden in ("alice@example.test", "sensitive-person", "approved-model", "account-1"):
            assert forbidden not in encoded
        assert report["source_independence"] == "NOT_ESTABLISHED"
        assert report["integrity"] == "NOT_RUN"


def test_verification_and_tampering(policy, tmp_path):
    with Observer(tmp_path / "state", [policy]) as observer:
        observer.observe(demo.samples()[0])
        key = observer.ledger.public_key_bytes()
        assert observer.verify(key)["status"] == "PASS"  # A violation can have valid evidence.
        wrong = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert observer.verify(wrong)["status"] == "FAIL"
        data = observer.ledger.bundle(tmp_path / "bundle")
        assert verify_bundle(data, key)["status"] == "INCOMPLETE"
        assert verify_bundle(data, key, lambda h: None)["status"] == "FAIL"
        altered = copy.deepcopy(data); altered["records"][0]["record"]["status"] = "succeeded"
        assert verify_bundle(altered, key)["status"] == "FAIL"
        blob = observer.ledger.blobs / data["records"][0]["blob_hash"]
        blob.write_text("{}")
        with pytest.raises(ValueError): observer.results()
        assert observer.verify(key)["status"] == "FAIL"


def test_cross_interaction_commitments(policy, tmp_path):
    with Observer(tmp_path, [policy]) as observer:
        trace = demo.samples()[1]; observer.observe(trace)
        trace["interaction_id"] = "another"; observer.observe(trace)
        blobs = [json.loads((observer.ledger.blobs / e["blob_hash"]).read_text())["payload"] for e in observer.ledger.records()]
        assert blobs[0]["stage_commitments"]["transformed"] == blobs[0]["stage_commitments"]["outbound"]
        assert blobs[0]["stage_commitments"]["outbound"] != blobs[1]["stage_commitments"]["outbound"]


def test_two_integration_styles(policy):
    trace = demo.samples()[1]; metadata = copy.deepcopy(trace)
    for stage in metadata["stages"].values(): stage.pop("payload"); stage["availability"] = "unavailable"
    a = structured_trace(metadata, *[trace["stages"][s]["payload"] for s in ("input", "transformed", "outbound")])
    events = [{"interaction_id": trace["interaction_id"], "stage": s, "snapshot": trace["stages"][s]} for s in ("outbound", "input", "transformed")]
    b = event_trace(metadata, events)
    assert a == b
    assert evaluate_observation(policy, a) == evaluate_observation(policy, b)
    events[0]["interaction_id"] = "wrong"
    with pytest.raises(ValueError): event_trace(metadata, events)


def test_event_assembly_cannot_reuse_metadata_payloads(policy):
    trace = demo.samples()[1]
    empty = event_trace(trace, [])
    assert evaluate_observation(policy, empty)["compliance"] == "INSUFFICIENT_EVIDENCE"
    event = {"interaction_id": trace["interaction_id"], "stage": "input", "snapshot": trace["stages"]["input"]}
    with pytest.raises(ValueError): event_trace(trace, [event, event])


def test_transformation_version_bound_to_submission(policy, tmp_path):
    trace = demo.samples()[1]; trace["transformation"] = {"id": "redactor", "version": "v1"}
    with Observer(tmp_path, [policy]) as observer:
        observer.observe(trace)
        trace["transformation"]["version"] = "v2"
        with pytest.raises(Conflict): observer.observe(trace)


def test_http(policy, tmp_path):
    with Observer(tmp_path, [policy]) as observer:
        token = "x" * 32
        server = make_observation_server("127.0.0.1", 0, observer, token, observer.ledger.public_key_bytes())
        thread = threading.Thread(target=server.serve_forever); thread.start()
        base = "http://127.0.0.1:" + str(server.server_port)
        def request(path, data=None, auth=True):
            req = urllib.request.Request(base + path, data=None if data is None else canonical(data), headers={"Authorization": "Bearer " + (token if auth else "wrong"), "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req) as response: return response.status, json.load(response)
            except urllib.error.HTTPError as error: return error.code, json.load(error)
        try:
            assert request("/results", auth=False)[0] == 401
            for trace in demo.samples(): assert request("/observations", trace)[0] == 200
            assert request("/results")[1]["total"] == 5
            assert request("/results?compliance=VIOLATION")[1]["total"] == 2
            assert request("/results?scenario=without_processing")[1]["total"] == 1
            assert request("/verify", {})[1]["status"] == "PASS"
            assert request("/transactions", {})[0] == 404
            assert request("/observations", {"bad": True})[0] == 422
            assert "alice@example.test" not in json.dumps(request("/results")[1])
            with urllib.request.urlopen(base) as response: assert b"Compliance Audit" in response.read()
        finally: server.shutdown(); server.server_close(); thread.join()
