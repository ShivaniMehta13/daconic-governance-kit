import copy
import json
import pytest
from daconic_governance.storage import Store
from daconic_governance.evidence import Ledger, disclose, verify_disclosure, commitment, verify_bundle
from daconic_governance.boundary import egress_guard


def test_disclosure():
    key, salt = b"k" * 32, "ab" * 32
    payload = {"a": 1200, "nested": {"b": "secret"}, "empty": []}
    root, _ = commitment(key, payload, salt)
    proof = disclose(key, payload, salt, "/a")
    assert verify_disclosure(proof, root["root"])
    proof["value"] = 1201
    assert not verify_disclosure(proof, root["root"])
    assert not verify_disclosure(disclose(b"x"*32, payload, salt, "/a"), root["root"])


@pytest.mark.parametrize("attack", ["verdict", "timestamp", "delete", "suffix", "insert", "reorder", "payload", "checkpoint", "export", "signature"])
def test_tampering(tmp_path, attack):
    with Store(tmp_path / "store") as store:
        ledger = Ledger(store, checkpoint_records=2)
        for i in range(4):
            ledger.append("intent", {"secret": "customer-123", "i": i})
        data = ledger.bundle(tmp_path / "bundle")
        public = ledger.public_key_bytes()
        reader = lambda h: (ledger.blobs / h).read_bytes()
        assert verify_bundle(data, public, reader)["status"] == "PASS"
        assert verify_bundle(data, public)["status"] == "INCOMPLETE"
        damaged = copy.deepcopy(data)
        if attack == "verdict": damaged["records"][0]["record"]["status"] = "refused"
        if attack == "timestamp": damaged["records"][0]["record"]["timestamp_ns"] += 1
        if attack == "delete": damaged["records"].pop(1)
        if attack == "suffix": damaged["records"].pop()
        if attack == "insert": damaged["records"].insert(1, copy.deepcopy(damaged["records"][0]))
        if attack == "reorder": damaged["records"].reverse()
        if attack == "payload": reader = lambda h: b"corrupt"
        if attack == "checkpoint": damaged["checkpoints"].pop()
        if attack == "export": damaged["headers"][0]["record"]["seq"] = 100
        if attack == "signature": damaged["records"][0]["signature"] = "x" * 88
        assert verify_bundle(damaged, public, reader)["status"] == "FAIL"
        assert "customer-123" not in json.dumps(data["headers"])
        header = copy.deepcopy(data["headers"][0])
        header["extra"] = "secret"
        with pytest.raises(ValueError): egress_guard(header)


def test_restart_and_heartbeat(tmp_path):
    with Store(tmp_path / "store") as store:
        ledger = Ledger(store)
        ledger.append("intent", {})
        ledger.checkpoint(force=True)
        key = ledger.public_key_bytes()
    with Store(tmp_path / "store") as store:
        ledger = Ledger(store)
        assert ledger.public_key_bytes() == key
        ledger.checkpoint(force=True)
        ledger.append("outcome", {})
        data = ledger.bundle(tmp_path / "bundle")
        assert any(c["body"]["heartbeat"] for c in data["checkpoints"])
        assert verify_bundle(data, key, lambda h: (ledger.blobs/h).read_bytes())["status"] == "PASS"
