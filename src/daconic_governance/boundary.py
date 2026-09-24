"""Only public evidence projection. Free-form text and raw identifiers never exported."""
import re

HEX = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
EVENTS = {"intent", "outcome", "approval", "corroboration", "llm_intent", "llm_outcome", "observation"}
EFFECTS = {"allow", "deny", "allow_with_modification", "defer", "step_up"}
CATEGORIES = {"PAYMENT_CARD", "FINANCIAL_PII", "PII", "CREDENTIAL", "INFRASTRUCTURE"}
RULES = {"capability", "scope", "reference", "amount_integrity", "hard_ceiling", "approval", "restricted_data", "facts_unavailable", "redaction", "allow"}


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("Egress schema: unexpected or missing fields")


def hex_value(value):
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise ValueError("Expected cryptographic digest")


def validate_record(r):
    exact(r, {"format", "deployment", "seq", "id", "timestamp_ns", "event", "prev_hash", "commitment", "decision", "actor", "findings", "correlation", "status"})
    if r["format"] != "daconic-evidence-v2" or r["event"] not in EVENTS:
        raise ValueError("Unknown evidence type")
    for k in ("deployment", "id"):
        if not isinstance(r[k], str) or UUID.fullmatch(r[k]) is None:
            raise ValueError("Public identifiers must be generated UUIDs")
    for k in ("seq", "timestamp_ns"):
        if type(r[k]) is not int or r[k] < 1:
            raise ValueError("Expected positive integer")
    hex_value(r["prev_hash"])
    exact(r["commitment"], {"root", "count"})
    hex_value(r["commitment"]["root"])
    if type(r["commitment"]["count"]) is not int or r["commitment"]["count"] < 1:
        raise ValueError("Invalid commitment count")
    if r["decision"] is not None:
        d = r["decision"]
        exact(d, {"effect", "violations", "severity", "profile_hash", "bundle_hash", "evaluator"})
        if d["effect"] not in EFFECTS or d["severity"] not in {"info", "medium", "high"} or d["evaluator"] != "deterministic-v2":
            raise ValueError("Invalid decision metadata")
        if type(d["violations"]) is not list or any(v not in RULES for v in d["violations"]):
            raise ValueError("Unknown rule")
        hex_value(d["profile_hash"])
        hex_value(d["bundle_hash"])
    if r["actor"] is not None:
        exact(r["actor"], {"agent", "run", "action"})
        for value in r["actor"].values():
            hex_value(value)
    if type(r["findings"]) is not list:
        raise ValueError("Invalid findings")
    for finding in r["findings"]:
        exact(finding, {"category", "path_hash", "detector_hash", "count"})
        if finding["category"] not in CATEGORIES or type(finding["count"]) is not int or finding["count"] < 1:
            raise ValueError("Invalid finding")
        hex_value(finding["path_hash"])
        hex_value(finding["detector_hash"])
    if r["correlation"] is not None:
        hex_value(r["correlation"])
    if r["status"] not in {None, "succeeded", "refused", "unknown", "agreement", "divergence", "unavailable"}:
        raise ValueError("Unknown outcome status")


def egress_guard(header):
    exact(header, {"record", "hash", "signature"})
    validate_record(header["record"])
    hex_value(header["hash"])
    if not isinstance(header["signature"], str) or not re.fullmatch(r"[A-Za-z0-9+/]{86}==", header["signature"]):
        raise ValueError("Invalid signature encoding")
    def lengths(v):
        if isinstance(v, str) and len(v) > 128:
            raise ValueError("Export string too long")
        if isinstance(v, dict):
            for k, item in v.items():
                lengths(k)
                lengths(item)
        if isinstance(v, list):
            for item in v:
                lengths(item)
    lengths(header)
    return header


def export_header(envelope):
    r = envelope["record"]
    # Construct each level explicitly. Guard remains a separate validation pass.
    d = r["decision"]
    a = r["actor"]
    header = {"record": {
        "format": r["format"], "deployment": r["deployment"], "seq": r["seq"], "id": r["id"],
        "timestamp_ns": r["timestamp_ns"], "event": r["event"], "prev_hash": r["prev_hash"],
        "commitment": {"root": r["commitment"]["root"], "count": r["commitment"]["count"]},
        "decision": None if d is None else {"effect": d["effect"], "violations": list(d["violations"]),
            "severity": d["severity"], "profile_hash": d["profile_hash"], "bundle_hash": d["bundle_hash"], "evaluator": d["evaluator"]},
        "actor": None if a is None else {"agent": a["agent"], "run": a["run"], "action": a["action"]},
        "findings": [{"category": f["category"], "path_hash": f["path_hash"], "detector_hash": f["detector_hash"], "count": f["count"]} for f in r["findings"]],
        "correlation": r["correlation"], "status": r["status"]}, "hash": envelope["hash"], "signature": envelope["signature"]}
    return egress_guard(header)
