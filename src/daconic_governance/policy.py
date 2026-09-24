"""Validated domain rule registry; no eval(), model judgments, or permissive fallback."""
import json
from dataclasses import dataclass
from pathlib import Path
from .common import canonical, digest, identifier

RULES = {"scope", "reference", "amount_integrity", "hard_ceiling", "approval", "restricted_data"}
PLATFORM = {"hard_ceiling_minor": 1000000, "max_concurrency": 16, "max_approval_seconds": 3600,
            "rules": sorted(RULES), "version": "platform-v2"}


@dataclass(frozen=True)
class Policy:
    encoded: bytes
    profile_hash: str
    bundle_hash: str

    @property
    def document(self):
        return json.loads(self.encoded)


def validate_document(doc, platform=PLATFORM):
    canonical(doc)
    if not isinstance(doc, dict) or set(doc) != {"agent_id", "version", "capabilities", "rules", "params", "routes"}:
        raise ValueError("Policy requires exactly agent_id, version, capabilities, rules, params, routes")
    identifier(doc["agent_id"])
    identifier(doc["version"])
    if not isinstance(doc["rules"], list) or len(set(doc["rules"])) != len(doc["rules"]) or set(doc["rules"]) - RULES:
        raise ValueError("Unknown or duplicate rule name")
    params = doc["params"]
    if set(params) != {"autonomous_minor", "ceiling_minor", "concurrency", "approval_seconds", "facts_max_age_seconds"}:
        raise ValueError("Invalid policy parameters")
    if any(type(v) is not int for v in params.values()):
        raise ValueError("Policy parameters must be integers")
    if not 0 <= params["autonomous_minor"] <= params["ceiling_minor"] <= platform["hard_ceiling_minor"]:
        raise ValueError("Policy widens platform ceiling or has invalid thresholds")
    if not 1 <= params["concurrency"] <= platform["max_concurrency"]:
        raise ValueError("Concurrency outside platform bounds")
    if not 1 <= params["approval_seconds"] <= platform["max_approval_seconds"] or params["facts_max_age_seconds"] < 1:
        raise ValueError("Invalid expiry or freshness")
    if not isinstance(doc["capabilities"], dict) or not doc["capabilities"]:
        raise ValueError("Capabilities required")
    for name, cap in doc["capabilities"].items():
        identifier(name)
        if set(cap) != {"kind", "restricted_response_paths", "corroborate_paths"} or cap["kind"] not in {"read", "refund"}:
            raise ValueError("Supported POC capability kinds: read, refund; new kinds require reviewed rule logic")
        required = RULES if cap["kind"] == "refund" else {"scope", "reference", "restricted_data"}
        if not required <= set(doc["rules"]):
            raise ValueError("Capability is missing mandatory governing rules")
        for field in ("restricted_response_paths", "corroborate_paths"):
            if not isinstance(cap[field], list) or any(not isinstance(p, str) or not p.startswith("/") for p in cap[field]):
                raise ValueError("Response and corroboration paths must be JSON Pointers")
    if not isinstance(doc["routes"], list):
        raise ValueError("Routes must be a list")
    for route in doc["routes"]:
        if set(route) != {"priority", "match"} or type(route["priority"]) is not int or not isinstance(route["match"], dict):
            raise ValueError("Invalid route")
        if set(route["match"]) - {"action", "channel"} or any(not isinstance(v, str) for v in route["match"].values()):
            raise ValueError("Route match supports exact action/channel only")
    return doc


class PolicyStore:
    def __init__(self, store, directory=None, platform=None):
        self.store = store
        self.directory = Path(directory) if directory else None
        self.platform = json.loads(canonical(platform or PLATFORM))
        if self.directory:
            self.load_directory()

    def install(self, doc):
        validate_document(doc, self.platform)
        encoded = canonical(doc)
        profile_hash = digest(encoded)
        with self.store.transaction() as db:
            db.execute("INSERT OR IGNORE INTO policies VALUES (?,?)", (profile_hash, encoded.decode()))
            db.execute("INSERT INTO profiles VALUES (?,?) ON CONFLICT(agent) DO UPDATE SET hash=excluded.hash", (doc["agent_id"], profile_hash))
        return self._profile(encoded)

    def _profile(self, encoded):
        return Policy(encoded, digest(encoded), digest({"profile_hash": digest(encoded), "platform": self.platform, "evaluator": "deterministic-v2"}))

    def load_directory(self):
        files = sorted(self.directory.glob("*.json"))
        for file in files:
            doc = json.loads(file.read_text())
            if file.stem != doc["agent_id"]:
                raise ValueError("Policy filename must match agent_id")
            self.install(doc)

    def resolve(self, agent):
        identifier(agent)
        if self.directory:
            path = self.directory / (agent + ".json")
            if not path.is_file():
                raise KeyError("No configured policy for agent")
            doc = json.loads(path.read_text())
            if doc.get("agent_id") != agent:
                raise ValueError("Policy identity mismatch")
            return self.install(doc)  # Archive and validate every new run.
        with self.store.lock:
            row = self.store.db.execute("SELECT document FROM policies JOIN profiles ON policies.hash=profiles.hash WHERE agent=?", (agent,)).fetchone()
        if row is None:
            raise KeyError("No configured policy for agent")
        return self._profile(row[0].encode())

    def all(self):
        if self.directory:
            return [self.resolve(p.stem) for p in sorted(self.directory.glob("*.json"))]
        with self.store.lock:
            agents = [r[0] for r in self.store.db.execute("SELECT agent FROM profiles ORDER BY agent")]
        return [self.resolve(a) for a in agents]


def decision(policy, effect, violations, obligations=None):
    doc = policy.document
    precedence = ["capability", "scope", "reference", "amount_integrity", "hard_ceiling", "restricted_data", "facts_unavailable", "approval"]
    fired = next((name for name in precedence if name in violations), "redaction" if obligations else "allow")
    return {"effect": effect, "violations": sorted(set(violations)),
            "rule": fired, "evaluated_rules": doc["rules"],
            "reasons": sorted(set(violations)), "obligations": obligations or [],
            "severity": "high" if effect == "deny" else "medium" if effect in {"step_up", "defer"} else "info",
            "profile": doc["agent_id"], "profile_version": doc["version"],
            "profile_hash": policy.profile_hash, "bundle_hash": policy.bundle_hash, "evaluator": "deterministic-v2"}


def public_decision(d):
    return {k: d[k] for k in ("effect", "violations", "severity", "profile_hash", "bundle_hash", "evaluator")}


def evaluate(policy, action, case_id, tenant, facts, approved=False):
    doc = policy.document
    capability = doc["capabilities"].get(action["action"])
    if capability is None:
        return decision(policy, "deny", ["capability"])
    if facts is None:
        return decision(policy, "defer", ["facts_unavailable"])
    violations = []
    if facts.get("case_id") != case_id or facts.get("tenant") != tenant:
        violations.append("scope")
    if facts.get("record_id") != action["record_id"] or facts.get("status") != "open":
        violations.append("reference")
    if capability["kind"] == "refund":
        amount = action.get("amount_minor")
        authoritative = facts.get("amount_minor")
        balance = facts.get("balance_minor")
        if type(authoritative) is not int or type(balance) is not int:
            return decision(policy, "defer", ["facts_unavailable"] + violations)
        if type(amount) is not int or amount < 0 or amount != authoritative or amount > balance:
            violations.append("amount_integrity")
        # The authoritative amount determines thresholds, never the agent's claim.
        if authoritative > doc["params"]["ceiling_minor"]:
            violations.append("hard_ceiling")
        if violations:
            return decision(policy, "deny", violations)
        if authoritative > doc["params"]["autonomous_minor"] and not approved:
            return decision(policy, "step_up", ["approval"])
    if violations:
        return decision(policy, "deny", violations)
    paths = capability["restricted_response_paths"]
    return decision(policy, "allow_with_modification" if paths else "allow", [], [{"type": "strip_response", "paths": paths}] if paths else [])
