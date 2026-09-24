import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from daconic_governance import Governance, Conflict, EvidenceUnavailable, OutcomeUnknown
from daconic_governance.fixtures import FixtureAdapter, profile, record
from daconic_governance.classification import classify


def app_at(tmp_path, amount=5000):
    adapter = FixtureAdapter([record(amount=amount)])
    app = Governance(tmp_path / "state", adapter)
    app.policies.install(profile())
    app.policies.install(profile("reader-agent", True))
    return app, adapter


def execute(app, amount, txn="tx-1", approval=None, run=None):
    run = run or app.broker.start_run("refund-agent", "case-1")
    return app.broker.execute(run, "refund", {"record_id": "record-1", "amount_minor": amount}, txn, approval)


def approve(app, **kwargs):
    return app.broker.issue_approval(**{"agent_id": "refund-agent", "case_id": "case-1", "transaction_id": "tx-1",
        "record_id": "record-1", "max_amount_minor": 50000, "approver_id": "reviewer", **kwargs})


@pytest.mark.parametrize("amount,effect", [(10000,"allow_with_modification"),(10001,"step_up"),(50000,"step_up"),(50001,"deny")])
def test_thresholds(tmp_path, amount, effect):
    app, adapter = app_at(tmp_path, amount)
    with app:
        result = execute(app, amount)
        assert result["decision"]["effect"] == effect
        assert adapter.calls == (1 if effect == "allow_with_modification" else 0)


def test_approval_bound_consumed_and_idempotent(tmp_path):
    app, adapter = app_at(tmp_path, 20000)
    with app:
        assert execute(app, 20000)["decision"]["effect"] == "step_up"
        token = approve(app)
        result = execute(app, 20000, approval=token)
        assert result["decision"]["effect"] == "allow_with_modification"
        assert execute(app, 20000, approval=token) == result
        assert adapter.calls == 1
        assert execute(app, 20000, txn="tx-2", approval=token)["decision"]["effect"] == "deny"
        assert app.store.db.execute("SELECT consumed FROM approvals").fetchone()[0] == 1
        issuance = next(e for e in app.ledger.records() if e["record"]["event"] == "approval")
        issued = json.loads((app.ledger.blobs / issuance["blob_hash"]).read_bytes())["payload"]
        intents = [json.loads((app.ledger.blobs/e["blob_hash"]).read_bytes())["payload"] for e in app.ledger.records() if e["record"]["event"] == "intent"]
        assert any(p["approval_reference"] == issued["token_hash"] for p in intents)


@pytest.mark.parametrize("change", ["different_record", "expired", "ceiling", "max_amount", "agent"])
def test_invalid_approvals(tmp_path, change):
    amount = 50001 if change == "ceiling" else 20000
    app, adapter = app_at(tmp_path, amount)
    with app:
        opts = {}
        if change == "different_record": opts["record_id"] = "other"
        if change == "max_amount": opts["max_amount_minor"] = 100
        if change == "agent": opts["agent_id"] = "reader-agent"
        token = approve(app, **opts)
        if change == "expired":
            row = app.store.db.execute("SELECT token_hash,data FROM approvals").fetchone()
            data = json.loads(row["data"]); data["expires_ns"] = 1
            app.store.db.execute("UPDATE approvals SET data=? WHERE token_hash=?", (json.dumps(data), row["token_hash"]))
        assert execute(app, amount, approval=token)["decision"]["effect"] == "deny"
        assert adapter.calls == 0


@pytest.mark.parametrize("violation", ["scope", "reference", "amount_integrity", "capability", "facts_unavailable"])
def test_rules(tmp_path, violation):
    app, adapter = app_at(tmp_path)
    with app:
        amount = 5000
        agent = "refund-agent"
        if violation == "scope": adapter.records["record-1"]["tenant"] = "other"
        if violation == "reference": adapter.records["record-1"]["status"] = "closed"
        if violation == "amount_integrity": amount = 1
        if violation == "capability": agent = "reader-agent"
        if violation == "facts_unavailable": adapter.records["record-1"]["observed_at"] = 0
        result = execute(app, amount, run=app.broker.start_run(agent,"case-1"))
        assert violation in result["decision"]["violations"]
        assert result["result"] is None and adapter.calls == 0


def test_policy_validation_and_pinning(tmp_path):
    app, _ = app_at(tmp_path)
    with app:
        with pytest.raises(KeyError): app.broker.start_run("missing", "case-1")
        doc = profile(); doc["params"]["ceiling_minor"] = 1000001
        with pytest.raises(ValueError): app.policies.install(doc)
        doc = profile(); doc["rules"] = ["scope"]
        with pytest.raises(ValueError): app.policies.install(doc)
        doc = profile(); doc["rules"].append("unknown")
        with pytest.raises(ValueError): app.policies.install(doc)
        run = app.broker.start_run("refund-agent", "case-1")
        old = app.broker._run(run).policy.profile_hash
        doc = profile(); doc["version"] = "v2"; doc["params"]["autonomous_minor"] = 1
        app.policies.install(doc)
        assert app.broker._run(run).policy.profile_hash == old
        assert execute(app,5000, run=run)["decision"]["profile_hash"] == old
        assert app.store.db.execute("SELECT count(*) FROM policies").fetchone()[0] == 3


def test_response_redaction_and_corroboration(tmp_path):
    app, adapter = app_at(tmp_path)
    with app:
        result = execute(app, 5000)
        assert "pan" not in result["result"] and "password" not in result["result"]
        first = app.broker.corroborate(result["intent_hash"])
        assert first["status"] == "agreement"
        assert app.broker.corroborate(result["intent_hash"]) == first
        adapter.records["record-1"]["balance_minor"] += 1
        assert app.broker.corroborate(result["intent_hash"])["status"] == "divergence"
        del adapter.records["record-1"]["balance_minor"]
        assert app.broker.corroborate(result["intent_hash"])["status"] == "divergence"
        del adapter.records["record-1"]
        assert app.broker.corroborate(result["intent_hash"])["status"] == "divergence"


def test_pre_dispatch_evidence_failure(tmp_path, monkeypatch):
    app, adapter = app_at(tmp_path, 20000)
    with app:
        token = approve(app)
        def fail(*args, **kwargs): raise OSError("disk full")
        monkeypatch.setattr(app.ledger, "_append", fail)
        with pytest.raises(EvidenceUnavailable): execute(app, 20000, approval=token)
        assert adapter.calls == 0
        assert app.store.db.execute("SELECT consumed FROM approvals").fetchone()[0] == 0


def test_unknown_does_not_redispatch(tmp_path):
    app, adapter = app_at(tmp_path)
    original = adapter.apply
    def crash(*args):
        original(*args)
        raise RuntimeError("connection lost after target success")
    adapter.apply = crash
    with app:
        with pytest.raises(OutcomeUnknown): execute(app, 5000)
        with pytest.raises(OutcomeUnknown): execute(app, 5000)
        assert adapter.calls == 1


def test_concurrent_duplicate_calls(tmp_path):
    app, adapter = app_at(tmp_path)
    with app:
        def call(_):
            try: return execute(app,5000)
            except OutcomeUnknown: return None
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(call, range(50)))
        assert adapter.calls == 1
        with pytest.raises(Conflict): execute(app, 100)


def test_model_request_block_and_response_screen(tmp_path):
    app, _ = app_at(tmp_path)
    with app:
        run = app.broker.start_run("refund-agent", "case-1")
        target = {"provider":"fixture", "model":"fixture", "model_version":"v1", "endpoint":"local", "request_id":"q1", "generation_parameters":{}}
        calls = []
        def dispatch(request): calls.append(request); return {"password":"secret", "text":"ok"}
        blocked = app.broker.record_llm_call(run,target=target,request={"pan":4242424242424242},dispatch=dispatch)
        assert blocked["decision"]["effect"] == "deny" and not calls
        result = app.broker.record_llm_call(run,target=target,request={"text":"hello"},dispatch=dispatch)
        assert result["result"] == {"text":"ok"}
        records = app.ledger.records()
        assert records[-1]["record"]["correlation"] == records[-2]["hash"]


@pytest.mark.parametrize("value,category", [
    ({"pan":4242424242424242},"PAYMENT_CARD"), ({"cvv":123},"PAYMENT_CARD"),
    ({"x":"GB82WEST12345698765432"},"FINANCIAL_PII"), ({"x":"a@example.com"},"PII"),
    ({"x":"+14155552671"},"PII"), ({"x":"sk-abcdefghijklmnopqrstuvwxyz"},"CREDENTIAL"),
    ({"x":"eyJabc.abcdef.abcdef"},"CREDENTIAL"), ({"x":"-----BEGIN PRIVATE KEY-----abc"},"CREDENTIAL"),
    ({"password":"something"},"CREDENTIAL"), ({"x":"mongodb://admin:pw@internal.svc.local"},"CREDENTIAL"),
    ({"x":"192.168.10.44"},"INFRASTRUCTURE"), ({"x":"host.internal"},"INFRASTRUCTURE"),
    ({"x":"AKIAABCDEFGHIJKLMNOP"},"CREDENTIAL")])
def test_classification(value, category):
    findings = classify(value)
    assert any(f["category"] == category for f in findings)
    assert all(set(f) == {"category","path","detector","count","detector_hash"} for f in findings)


def test_classifier_negatives_and_span_claims():
    assert not classify({"order":"ORD-12345678", "invoice":"INV-555", "amount_minor":12000,
                         "time":"2026-09-07T12:00:00Z", "id":"b184963a-09ac-4151-9317-067e4a620fde"})
    findings = classify({"x":"mongodb://admin:pw@internal.svc.local"})
    assert len(findings) == 1 and findings[0]["detector"] == "database_uri"
