"""NOT PRODUCTION: mutable synthetic target and snapshot adapter for POC tests only."""
import copy
import json
import threading
import time
from pathlib import Path


def profile(agent="refund-agent", read_only=False):
    action = "read_record" if read_only else "refund"
    return {"agent_id": agent, "version": "v1", "rules": ["scope", "reference", "amount_integrity", "hard_ceiling", "approval", "restricted_data"],
            "params": {"autonomous_minor": 10000, "ceiling_minor": 50000, "concurrency": 2, "approval_seconds": 600, "facts_max_age_seconds": 86400},
            "capabilities": {action: {"kind": "read" if read_only else "refund", "restricted_response_paths": ["/pan", "/password"],
                "corroborate_paths": ["/record_id", "/case_id", "/balance_minor"]}},
            "routes": [{"priority": 10, "match": {"action": action}}]}


def record(record_id="record-1", amount=5000, case_id="case-1"):
    return {"record_id": record_id, "case_id": case_id, "tenant": "poc", "status": "open",
            "amount_minor": amount, "balance_minor": 100000, "version": 1, "observed_at": int(time.time()),
            "pan": 4242424242424242, "password": "fixture-secret", "email": "customer@example.test"}


class FixtureAdapter:
    def __init__(self, records=None):
        self.records = {r["record_id"]: copy.deepcopy(r) for r in (records or [record()])}
        self.lock = threading.RLock()
        self.receipts = {}
        self.calls = 0

    def read(self, case_id, record_id, tenant):
        with self.lock:
            return copy.deepcopy(self.records[record_id])

    def apply(self, action, facts, idempotency_key):
        with self.lock:
            if idempotency_key in self.receipts:
                return copy.deepcopy(self.receipts[idempotency_key])
            current = self.records[action["record_id"]]
            if current["version"] != facts["version"] or current["case_id"] != action["case_id"] or current["tenant"] != action["tenant"]:
                raise ValueError("Target precondition failed")
            if action["action"] == "refund":
                current["balance_minor"] -= facts["amount_minor"]
                current["version"] += 1
            self.calls += 1
            self.receipts[idempotency_key] = copy.deepcopy(current)
            return copy.deepcopy(current)

    def read_after(self, case_id, record_id, tenant):
        return self.read(case_id, record_id, tenant)


class ExtractAdapter:
    """Replay only: before/after snapshots supplied independently; never writes enterprise systems."""
    def __init__(self, before_file, after_file):
        self.before = {r["record_id"]: r for r in json.loads(Path(before_file).read_text())}
        self.after = {r["record_id"]: r for r in json.loads(Path(after_file).read_text())}

    def read(self, case_id, record_id, tenant):
        return copy.deepcopy(self.before[record_id])

    def apply(self, action, facts, idempotency_key):
        return {"simulation": True, "record_id": action["record_id"], "balance_minor": facts["balance_minor"] - (facts["amount_minor"] if action["action"] == "refund" else 0)}

    def read_after(self, case_id, record_id, tenant):
        return copy.deepcopy(self.after[record_id])
