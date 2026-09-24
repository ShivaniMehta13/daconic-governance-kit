"""Observation only. No adapter, dispatch callback, or outbound network access.

Submitted provenance is a claim. Equality concerns canonical JSON, not wire bytes.
Private payloads remain local; reports deliberately omit all caller text and paths.
"""
import hashlib
import hmac
import json
import re
import tempfile
from pathlib import Path

from .classification import classify, DETECTOR_HASH
from .common import canonical, digest, get_path, identifier, Conflict
from .evidence import Ledger, verify_bundle, check_signature
from .storage import Store

EVALUATOR = "observation-v1"
KINDS = {"required", "forbidden", "no_categories", "equals", "in", "matches_transformed"}
CATEGORIES = {"PII", "FINANCIAL_PII", "PAYMENT_CARD", "CREDENTIAL", "INFRASTRUCTURE"}
STAGES = ("input", "transformed", "outbound")


def implementation_hash():
    directory = Path(__file__).parent
    return digest({name: digest((directory / name).read_bytes()) for name in ("observation.py", "classification.py", "common.py")})


def exact(obj, keys):
    if type(obj) is not dict or set(obj) != set(keys):
        raise ValueError("Unexpected or missing schema fields")


def pointer(path):
    if not isinstance(path, str) or (path and not path.startswith("/")) or re.search(r"~(?![01])", path):
        raise ValueError("Expected JSON Pointer")


def validate_observation_policy(policy):
    canonical(policy)
    exact(policy, {"id", "version", "actions", "checks"})
    identifier(policy["id"]); identifier(policy["version"])
    if type(policy["actions"]) is not list or not policy["actions"]:
        raise ValueError("Actions required")
    for action in policy["actions"]: identifier(action)
    if type(policy["checks"]) is not list or not 1 <= len(policy["checks"]) <= 100:
        raise ValueError("One to 100 checks required")
    ids = set()
    for check in policy["checks"]:
        exact(check, {"id", "kind", "stage", "path", "value"})
        identifier(check["id"])
        if check["id"] in ids: raise ValueError("Duplicate check ID")
        ids.add(check["id"])
        if check["kind"] not in KINDS or check["stage"] not in (*STAGES, "context"):
            raise ValueError("Unsupported predicate or stage")
        pointer(check["path"])
        if check["kind"] == "no_categories" and (type(check["value"]) is not list or not check["value"] or any(c not in CATEGORIES for c in check["value"])):
            raise ValueError("Unsupported detector category")
        if check["kind"] == "in" and type(check["value"]) is not list:
            raise ValueError("Membership requires a list")
        if check["kind"] in {"required", "forbidden", "matches_transformed"} and check["value"] is not None:
            raise ValueError("Predicate value must be null")
        if check["kind"] == "matches_transformed" and (check["stage"] != "outbound" or check["path"] != ""):
            raise ValueError("Transformation binding compares complete outbound payload")
    return policy


def validate_trace(trace):
    canonical(trace)
    fields = {"schema_version", "interaction_id", "correlation_id", "agent_id", "action", "scenario", "policy", "context", "stages"}
    if "transformation" in trace:
        fields.add("transformation")
        exact(trace["transformation"], {"id", "version"})
        identifier(trace["transformation"]["id"]); identifier(trace["transformation"]["version"])
    exact(trace, fields)
    if trace["schema_version"] != "1": raise ValueError("Unsupported trace version")
    for field in ("interaction_id", "correlation_id", "agent_id", "action"): identifier(trace[field])
    if trace["scenario"] not in {"without_processing", "with_processing"}: raise ValueError("Invalid scenario")
    exact(trace["policy"], {"id", "version"})
    identifier(trace["policy"]["id"]); identifier(trace["policy"]["version"])
    exact(trace["context"], {"principal", "delegated_user", "resource", "destination"})
    for value in trace["context"].values():
        if value is not None and (not isinstance(value, str) or len(value) > 2048): raise ValueError("Invalid context")
    exact(trace["stages"], STAGES)
    for stage in trace["stages"].values():
        if type(stage) is not dict: raise ValueError("Invalid stage")
        expected = {"availability", "source", "observed_at_ns", "representation"}
        if stage.get("availability") in {"present", "masked"}: expected.add("payload")
        exact(stage, expected)
        if stage["availability"] not in {"present", "masked", "unavailable"}: raise ValueError("Invalid availability")
        if stage["representation"] != "canonical-json-v1": raise ValueError("Unsupported representation")
        identifier(stage["source"])
        if type(stage["observed_at_ns"]) is not int or stage["observed_at_ns"] < 1: raise ValueError("Invalid observation time")
    return trace


def evidence_requirements(policy):
    """Compile supported checks into minimum stage requirements, not proof of capture."""
    validate_observation_policy(policy)
    stages = set()
    for check in policy["checks"]:
        stages.add(check["stage"])
        if check["kind"] == "matches_transformed": stages.add("transformed")
    return {"stages": sorted(stages), "representation": "canonical-json-v1",
            "policy_snapshot_required": True, "independent_capture_required_for_independence_claim": True}


def locate(root, path):
    try: return True, get_path(root, path)
    except (KeyError, IndexError, ValueError, TypeError): return False, None


def evaluate_observation(policy, trace):
    """Pure deterministic check. Unknown coverage never becomes a passing check."""
    validate_observation_policy(policy); validate_trace(trace)
    if trace["policy"] != {"id": policy["id"], "version": policy["version"]}:
        raise ValueError("Policy reference mismatch")
    results = []
    applicable = trace["action"] in policy["actions"]
    for check in policy["checks"] if applicable else []:
        stage, kind = check["stage"], check["kind"]
        status, reason = "PASS", "condition_satisfied"
        complete = stage == "context" or trace["stages"][stage]["availability"] == "present"
        root = trace["context"] if stage == "context" else trace["stages"][stage].get("payload")
        found, value = locate(root, check["path"])
        if not complete:
            status, reason = "UNKNOWN", "original_payload_unavailable"
        elif kind == "matches_transformed":
            transformed = trace["stages"]["transformed"]
            if transformed["availability"] != "present":
                status, reason = "UNKNOWN", "transformed_payload_unavailable"
            elif canonical(root) != canonical(transformed["payload"]):
                status, reason = "FAIL", "payload_substitution"
        elif kind == "forbidden":
            if found: status, reason = "FAIL", "restricted_field_present"
        elif not found or value is None:
            status, reason = ("FAIL", "required_field_missing") if kind == "required" else ("UNKNOWN", "fact_unavailable")
        elif kind == "no_categories":
            if any(f["category"] in check["value"] for f in classify(value)):
                status, reason = "FAIL", "restricted_data_detected"
        elif kind == "equals" and canonical(value) != canonical(check["value"]):
            status, reason = "FAIL", "value_mismatch"
        elif kind == "in" and not any(canonical(value) == canonical(v) for v in check["value"]):
            status, reason = "FAIL", "value_not_permitted"
        results.append({"check_index": len(results) + 1, "kind": kind, "stage": stage, "status": status, "reason": reason})
    status = "NOT_APPLICABLE" if not applicable else "VIOLATION" if any(r["status"] == "FAIL" for r in results) else "INSUFFICIENT_EVIDENCE" if any(r["status"] == "UNKNOWN" for r in results) else "COMPLIANT"
    return {"compliance": status, "checks": results, "policy_hash": digest(policy), "evaluator": EVALUATOR,
            "requirements": evidence_requirements(policy),
            "implementation_hash": implementation_hash(), "detector_hash": DETECTOR_HASH,
            "coverage": "submitted_observations_only", "source_independence": "NOT_ESTABLISHED"}


def replay_observation_bundle(data, trusted_key, blob_reader):
    """Re-evaluate supported signed observations locally; never executes original actions.

    PASS establishes deterministic agreement with supplied authenticated inputs only.
    Older/different evaluator code is INCOMPLETE, never silently reinterpreted.
    """
    integrity = verify_bundle(data, trusted_key, blob_reader)
    if integrity["status"] != "PASS": return {"integrity": integrity, "replay": "NOT_RUN", "checked": 0}
    errors, unsupported, checked = [], [], 0
    for envelope in data["records"]:
        if envelope["record"]["event"] != "observation": continue
        try:
            payload = json.loads(blob_reader(envelope["blob_hash"]))["payload"]
            expected = payload["assessment"]
            if expected.get("implementation_hash") != implementation_hash() or expected.get("evaluator") != EVALUATOR:
                unsupported.append(envelope["record"]["id"]); continue
            actual = evaluate_observation(payload["policy"], payload["trace"])
            if actual != expected or any(payload["report"].get(k) != v for k, v in actual.items()):
                errors.append(envelope["record"]["id"])
            checked += 1
        except (KeyError, ValueError, TypeError): errors.append(envelope["record"]["id"])
    return {"integrity": integrity, "replay": "FAIL" if errors else "INCOMPLETE" if unsupported or not checked else "PASS",
            "checked": checked, "mismatched": errors, "unsupported": unsupported}


class Observer:
    def __init__(self, directory, policies=()):
        self.store = Store(directory)
        try:
            self.ledger = Ledger(self.store)
            self.store.db.executescript("""
            CREATE TABLE IF NOT EXISTS observation_policies(id TEXT, version TEXT, document TEXT, PRIMARY KEY(id,version));
            CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, fingerprint TEXT, envelope TEXT);
            """)
            for policy in policies: self.install(policy)
        except BaseException:
            self.store.close(); raise

    def opaque(self, value):
        return hmac.new(self.ledger.commitment_key, canonical(value), hashlib.sha256).hexdigest()

    def install(self, policy):
        validate_observation_policy(policy)
        encoded = canonical(policy).decode()
        with self.store.transaction() as db:
            row = db.execute("SELECT document FROM observation_policies WHERE id=? AND version=?", (policy["id"], policy["version"])).fetchone()
            if row and row[0] != encoded: raise Conflict("Policy version already has different content")
            db.execute("INSERT OR IGNORE INTO observation_policies VALUES (?,?,?)", (policy["id"], policy["version"], encoded))

    def policy(self, ref):
        with self.store.lock:
            row = self.store.db.execute("SELECT document FROM observation_policies WHERE id=? AND version=?", (ref["id"], ref["version"])).fetchone()
        if not row: raise ValueError("Policy is not installed")
        return json.loads(row[0])

    def check(self, trace):
        validate_trace(trace)
        return evaluate_observation(self.policy(trace["policy"]), trace)

    def observe(self, trace):
        trace = json.loads(canonical(validate_trace(trace)))
        key, fingerprint = self.opaque(trace["interaction_id"]), self.opaque(trace)
        with self.store.transaction() as db:
            old = db.execute("SELECT * FROM observations WHERE id=?", (key,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint: raise Conflict("Interaction ID has different content")
                return self._report(json.loads(old["envelope"]))
            policy = self.policy(trace["policy"])
            assessment = evaluate_observation(policy, trace)
            report = {**assessment, "interaction_id": key, "correlation_id": self.opaque(trace["correlation_id"]),
                      "agent_id": self.opaque(trace["agent_id"]), "action": self.opaque(trace["action"]),
                      "policy_id": self.opaque(policy["id"]), "policy_version": self.opaque(policy["version"]),
                      "scenario": trace["scenario"], "severity": "high" if assessment["compliance"] == "VIOLATION" else "none",
                      "availability": {s: trace["stages"][s]["availability"] for s in STAGES},
                      "payloads": {s: "[WITHHELD]" for s in STAGES},
                      "integrity": "NOT_RUN"}
            # Shared context prevents cross-interaction receipt reuse. These commitments
            # support local equality only; they are not remote observer attestations.
            binding = {s: self.opaque({"interaction": key, "policy_hash": digest(policy), "destination": trace["context"]["destination"], "payload": trace["stages"][s]["payload"]})
                       for s in STAGES if trace["stages"][s]["availability"] == "present"}
            envelope = self.ledger._append(db, "observation", {"trace": trace, "policy": policy,
                "assessment": assessment, "report": report, "stage_commitments": binding,
                "binding_version": "context-json-hmac-v1"})
            db.execute("INSERT INTO observations VALUES (?,?,?)", (key, fingerprint, canonical(envelope).decode()))
        self.ledger.checkpoint()
        return self._report(envelope)

    def _report(self, envelope):
        check_signature(self.ledger.key.public_key(), envelope["record"], envelope["signature"])
        if digest(envelope["record"]) != envelope["hash"]: raise ValueError("Record altered")
        check_signature(self.ledger.key.public_key(), {"record_hash": envelope["hash"], "blob_hash": envelope["blob_hash"]}, envelope["blob_signature"])
        blob_hash = envelope["blob_hash"]
        if not re.fullmatch("[0-9a-f]{64}", blob_hash): raise ValueError("Invalid blob reference")
        raw = (self.ledger.blobs / blob_hash).read_bytes()
        if digest(raw) != blob_hash: raise ValueError("Payload altered")
        report = json.loads(raw)["payload"]["report"]
        return {**report, "evidence_id": envelope["record"]["id"], "evidence_hash": envelope["hash"], "created_at_ns": envelope["record"]["timestamp_ns"]}

    def results(self):
        with self.store.lock:
            return [self._report(e) for e in self.ledger.records() if e["record"]["event"] == "observation"]

    def verify(self, trusted_key):
        with self.store.lock, tempfile.TemporaryDirectory() as directory:
            data = self.ledger.bundle(directory)
            result = verify_bundle(data, trusted_key, lambda h: (Path(directory) / "blobs" / h).read_bytes())
            return {**result, "scope": "complete_local_bundle", "record_count": len(data["records"]), "head": data["manifest"]["body"]["head"], "trust": "configured_verification_key"}

    def close(self):
        if not self.store.closed:
            try: self.ledger.checkpoint(force=True)
            finally: self.store.close()

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
