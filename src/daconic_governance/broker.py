"""Trusted host API. Agent-controlled code must never receive this object's credentials."""
import asyncio
import hmac
import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from .classification import classify, strip_restricted
from .common import canonical, digest, get_path, identifier, Conflict, EvidenceUnavailable, OutcomeUnknown
from .policy import decision, evaluate, public_decision


@dataclass(frozen=True)
class Run:
    agent: str
    case: str
    policy: object


class Broker:
    def __init__(self, policies, ledger, adapter, tenant="poc"):
        self.policies, self.ledger, self.store = policies, ledger, ledger.store
        self.adapter = adapter
        self.tenant = identifier(tenant)
        self._runs = {}

    def opaque(self, value):
        return hmac.new(self.ledger.commitment_key, canonical(value), hashlib.sha256).hexdigest()

    def start_run(self, agent_id, case_id):
        identifier(case_id)
        policy = self.policies.resolve(agent_id)
        token = secrets.token_urlsafe(32)
        with self.store.lock:
            self._runs[token] = Run(agent_id, case_id, policy)
        return token

    def end_run(self, run):
        with self.store.lock:
            self._runs.pop(run, None)

    def _run(self, token):
        with self.store.lock:
            if token not in self._runs:
                raise ValueError("Unknown run handle; use start_run")
            return self._runs[token]

    def issue_approval(self, *, agent_id, case_id, transaction_id, record_id, max_amount_minor,
                       approver_id, approver_type="human", expires_seconds=300):
        """Trusted approval-controller API only. Never expose as an agent tool."""
        policy = self.policies.resolve(agent_id)
        if type(max_amount_minor) is not int or max_amount_minor < 0:
            raise ValueError("Approval amount must be non-negative integer minor units")
        if approver_type not in {"human", "workflow"} or not isinstance(approver_id, str) or not 1 <= len(approver_id) <= 512:
            raise ValueError("Authenticated approver identity and type required")
        if type(expires_seconds) is not int or not 1 <= expires_seconds <= policy.document["params"]["approval_seconds"]:
            raise ValueError("Approval expiry exceeds policy")
        for value in (case_id, transaction_id, record_id):
            identifier(value)
        token = secrets.token_urlsafe(32)
        data = {"agent": agent_id, "case": case_id, "transaction": transaction_id, "record": record_id,
                "max_amount_minor": max_amount_minor, "approver": approver_id, "approver_type": approver_type,
                "tenant": self.tenant, "token_hash": digest(token), "expires_ns": time.time_ns() + expires_seconds * 1000000000}
        with self.store.transaction() as db:
            db.execute("INSERT INTO approvals(token_hash,data) VALUES (?,?)", (digest(token), canonical(data).decode()))
            self.ledger._append(db, "approval", data)
        self.ledger.checkpoint()
        return token

    def _approval_valid(self, db, token, run, action, facts):
        if not token:
            return False
        row = db.execute("SELECT data,consumed FROM approvals WHERE token_hash=?", (digest(token),)).fetchone()
        if row is None or row["consumed"]:
            return False
        a = json.loads(row["data"])
        return (a["tenant"] == self.tenant and a["agent"] == run.agent and a["case"] == run.case
                and a["transaction"] == action["transaction_id"] and a["record"] == action["record_id"]
                and a["expires_ns"] > time.time_ns() and type(facts.get("amount_minor")) is int
                and facts["amount_minor"] <= a["max_amount_minor"])

    def _actor(self, run_token, run, action):
        return {"agent": self.opaque(run.agent), "run": self.opaque(run_token), "action": self.opaque(action)}

    def _findings(self, findings):
        return [{"category": f["category"], "path_hash": self.opaque(f["path"]),
                 "detector_hash": f["detector_hash"], "count": f["count"]} for f in findings]

    def execute(self, run_token, action_name, arguments, transaction_id, approval_token=None):
        run = self._run(run_token)
        identifier(transaction_id)
        identifier(action_name)
        if not isinstance(arguments, dict) or set(arguments) - {"record_id", "amount_minor"} or "record_id" not in arguments:
            raise ValueError("Arguments require record_id and optional integer amount_minor; scope is injected")
        identifier(arguments["record_id"])
        if "amount_minor" in arguments and type(arguments["amount_minor"]) is not int:
            raise ValueError("Amounts are integer minor units, never floats")
        action = {"action": action_name, "transaction_id": transaction_id, **json.loads(canonical(arguments))}
        fingerprint = digest({"action": action, "agent": run.agent, "case": run.case, "tenant": self.tenant})
        operation = self.opaque([self.tenant, transaction_id])
        with self.store.lock:
            row = self.store.db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise Conflict("Transaction ID reused with different content or scope")
                if row["state"] == "done":
                    return json.loads(row["result"])
                if row["state"] in {"attempting", "unknown"}:
                    raise OutcomeUnknown("Attempt may have reached target; reconcile before any new action")
                if not approval_token and row["state"] == "waiting":
                    return json.loads(row["result"])
        doc = run.policy.document
        cap = doc["capabilities"].get(action_name)
        facts = None
        if cap is not None:  # Check capability before reading any customer data.
            try:
                facts = json.loads(canonical(self.adapter.read(run.case, arguments["record_id"], self.tenant)))
                observed = facts.get("observed_at", 0)
                if type(observed) is not int or not 0 <= time.time() - observed <= doc["params"]["facts_max_age_seconds"]:
                    facts = None
            except Exception:
                facts = None
        actor = self._actor(run_token, run, action_name)
        try:
            with self.store.transaction() as db:
                # Recheck after authoritative reads to serialize duplicate concurrent calls.
                row = db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
                if row and row["state"] not in {"waiting", "deferred"}:
                    if row["fingerprint"] != fingerprint:
                        raise Conflict("Transaction conflict")
                    if row["state"] == "done":
                        return json.loads(row["result"])
                    raise OutcomeUnknown("Transaction is already attempting or unknown")
                if row and row["fingerprint"] != fingerprint:
                    raise Conflict("Transaction conflict")
                approved = bool(facts) and self._approval_valid(db, approval_token, run, action, facts)
                verdict = evaluate(run.policy, action, run.case, self.tenant, facts, approved)
                allowed = verdict["effect"] in {"allow", "allow_with_modification"}
                if approval_token and not approved and verdict["effect"] not in {"deny", "defer"}:
                    verdict = decision(run.policy, "deny", ["approval"])
                    allowed = False
                if allowed and approved:
                    db.execute("UPDATE approvals SET consumed=1 WHERE token_hash=? AND consumed=0", (digest(approval_token),))
                findings = classify(facts) if facts is not None else []
                intent = self.ledger._append(db, "intent", {"action": action, "case": run.case, "tenant": self.tenant,
                    "facts": facts, "policy": doc, "decision": verdict, "findings": findings,
                    "approval_reference": digest(approval_token) if approved else None},
                    decision=public_decision(verdict), actor=actor, findings=self._findings(findings), status=None if allowed else "refused")
                result = {"decision": verdict, "evidence_id": intent["record"]["id"], "intent_hash": intent["hash"], "result": None}
                state = "attempting" if allowed else "waiting" if verdict["effect"] == "step_up" else "deferred" if verdict["effect"] == "defer" else "done"
                db.execute("INSERT INTO operations VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,result=excluded.result,intent_hash=excluded.intent_hash",
                           (operation, fingerprint, state, canonical(result).decode(), intent["hash"]))
        except (Conflict, OutcomeUnknown):
            raise
        except Exception as exc:
            raise EvidenceUnavailable("Intent or approval commit failed; action not dispatched") from exc
        # Checkpoint failure after intent commit prevents dispatch. State remains unknown-safe.
        self.ledger.checkpoint()
        if not allowed:
            return result
        governed_action = {**action, "case_id": run.case, "tenant": self.tenant}
        try:
            output = self.adapter.apply(governed_action, facts, operation)
            canonical(output)
        except Exception as exc:
            with self.store.transaction() as db:
                self.ledger._append(db, "outcome", {"error_type": type(exc).__name__}, actor=actor, correlation=intent["hash"], status="unknown")
                db.execute("UPDATE operations SET state='unknown' WHERE id=?", (operation,))
            raise OutcomeUnknown("Dispatch failed or returned an invalid result; inspect target before retry") from exc
        safe, removed = strip_restricted(output, cap["restricted_response_paths"])
        remaining = classify(safe)
        blocked_paths = [f["path"] for f in remaining if f["category"] in {"CREDENTIAL", "PAYMENT_CARD"}]
        safe, additional = strip_restricted(safe, blocked_paths)
        result["result"] = safe
        try:
            with self.store.transaction() as db:
                outcome = self.ledger._append(db, "outcome", {"output": output, "redacted_count": removed + additional,
                    "findings": remaining}, actor=actor, correlation=intent["hash"], status="succeeded", findings=self._findings(remaining))
                result["outcome_hash"] = outcome["hash"]
                db.execute("UPDATE operations SET state='done',result=? WHERE id=?", (canonical(result).decode(), operation))
        except Exception as exc:
            raise OutcomeUnknown("Target returned success but outcome evidence failed; do not repeat action") from exc
        self.ledger.checkpoint()
        return result

    async def aexecute(self, *args, **kwargs):
        """Async-host bridge for synchronous adapters; cancellation does not undo dispatch."""
        return await asyncio.to_thread(self.execute, *args, **kwargs)

    def corroborate(self, intent_hash):
        with self.store.lock:
            row = self.store.db.execute("SELECT envelope FROM ledger WHERE json_extract(envelope,'$.hash')=?", (intent_hash,)).fetchone()
        envelope = json.loads(row[0]) if row else None
        if envelope and envelope["record"]["event"] != "intent":
            envelope = None
        if envelope is None:
            raise KeyError("Unknown action intent")
        payload = json.loads((self.ledger.blobs / envelope["blob_hash"]).read_bytes())["payload"]
        if payload["decision"]["effect"] not in {"allow", "allow_with_modification"}:
            raise ValueError("Cannot corroborate refused action")
        action, before = payload["action"], payload["facts"]
        cap = payload["policy"]["capabilities"][action["action"]]
        expected = dict(before)
        if cap["kind"] == "refund":
            expected["balance_minor"] = before["balance_minor"] - before["amount_minor"]
        try:
            actual = self.adapter.read_after(payload["case"], action["record_id"], payload["tenant"])
            comparisons = []
            for path in cap["corroborate_paths"]:
                try:
                    observed = get_path(actual, path)
                    wanted = get_path(expected, path)
                    equal = canonical(observed) == canonical(wanted)
                    comparisons.append({"path": path, "equal": equal, "expected": wanted, "actual": observed})
                except (KeyError, TypeError, IndexError):
                    comparisons.append({"path": path, "equal": False, "missing": True})
            finding = {"status": "agreement" if comparisons and all(p["equal"] for p in comparisons) else "divergence", "fields": comparisons,
                       "profile_hash": envelope["record"]["decision"]["profile_hash"], "state_hash": digest(actual)}
        except KeyError:
            finding = {"status": "divergence", "fields": [{"path":p,"equal":False,"missing":True} for p in cap["corroborate_paths"]]}
        except Exception:
            finding = {"status": "unavailable", "fields": []}
        self.ledger.append("corroboration", finding, correlation=intent_hash, status=finding["status"], actor=envelope["record"]["actor"])
        return finding

    def record_llm_call(self, run_token, *, target, request, dispatch):
        """Wraps dispatch to block BEFORE the call. Target metadata stays local and committed."""
        run = self._run(run_token)
        required = {"provider", "model", "model_version", "endpoint", "request_id", "generation_parameters"}
        if not isinstance(target, dict) or set(target) != required:
            raise ValueError("Complete target metadata required")
        canonical(target)
        findings = classify(request)
        blocked = any(f["category"] in {"PAYMENT_CARD", "CREDENTIAL"} for f in findings)
        verdict = decision(run.policy, "deny" if blocked else "allow", ["restricted_data"] if blocked else [])
        actor = self._actor(run_token, run, "model_call")
        intent = self.ledger.append("llm_intent", {"target": target, "request": request, "findings": findings},
            decision=public_decision(verdict), actor=actor, findings=self._findings(findings), status="refused" if blocked else None)
        if blocked:
            return {"decision": verdict, "result": None, "intent_hash": intent["hash"]}
        try:
            response = dispatch(request)
            canonical(response)
        except Exception as exc:
            self.ledger.append("llm_outcome", {"error_type": type(exc).__name__}, actor=actor, correlation=intent["hash"], status="unknown")
            raise OutcomeUnknown("Model call outcome unavailable") from exc
        findings = classify(response)
        safe, removed = strip_restricted(response, [f["path"] for f in findings if f["category"] in {"PAYMENT_CARD", "CREDENTIAL"}])
        self.ledger.append("llm_outcome", {"target": target, "response": response, "findings": findings, "redacted_count": removed},
                          actor=actor, correlation=intent["hash"], findings=self._findings(findings), status="succeeded")
        return {"decision": verdict, "result": safe, "intent_hash": intent["hash"]}
