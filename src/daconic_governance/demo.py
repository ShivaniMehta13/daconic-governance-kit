"""Executable synthetic acceptance walkthrough. All enterprise effects are fixtures."""
import copy
import json
from pathlib import Path
from .application import Governance
from .common import canonical
from .evidence import disclose, verify_disclosure, verify_bundle
from .fixtures import FixtureAdapter, profile, record
from .storage import atomic_write


def run_demo(destination):
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Demo destination must be empty")
    records = [record("allowed", 5000), record("approval", 20000), record("ceiling", 50001),
               record("scope", 5000, "other-case"), record("closed", 5000), record("integrity", 5000)]
    records[4]["status"] = "closed"
    adapter = FixtureAdapter(records)
    results = {}
    with Governance(destination / "deployment", adapter, checkpoint_records=3, checkpoint_seconds=1) as app:
        app.policies.install(profile())
        app.policies.install(profile("reader-agent", True))
        run = app.broker.start_run("refund-agent", "case-1")
        def act(name, amount, token=None):
            return app.broker.execute(run,"refund",{"record_id":name,"amount_minor":amount},"tx-"+name,token)
        allowed = act("allowed",5000)
        results["allowed"] = allowed["decision"]["effect"]
        for name, amount in [("approval",20000),("ceiling",50001),("scope",5000),("closed",5000),("integrity",1)]:
            results[name] = act(name,amount)["decision"]
        token = app.broker.issue_approval(agent_id="refund-agent",case_id="case-1",transaction_id="tx-approval",
            record_id="approval",max_amount_minor=20000,approver_id="demo-human")
        results["approved"] = act("approval",20000,token)["decision"]["effect"]
        reader = app.broker.start_run("reader-agent","case-1")
        results["capability"] = app.broker.execute(reader,"refund",{"record_id":"allowed","amount_minor":5000},"tx-ungranted")["decision"]
        target = {"provider":"fixture", "model":"echo", "model_version":"v1", "endpoint":"local-only", "request_id":"demo-llm", "generation_parameters":{}}
        def must_not_run(request): raise AssertionError("Blocked model call dispatched")
        results["model_block"] = app.broker.record_llm_call(run,target=target,request={"pan":4242424242424242},dispatch=must_not_run)["decision"]
        results["model_capture"] = app.broker.record_llm_call(run,target=target,request={"text":"hello"},dispatch=lambda request:{"text":"world"})["decision"]
        results["agreement"] = app.broker.corroborate(allowed["intent_hash"])["status"]
        adapter.records["allowed"]["balance_minor"] += 5
        results["divergence"] = app.broker.corroborate(allowed["intent_hash"])["status"]
        envelope = next(e for e in app.ledger.records() if e["hash"] == allowed["intent_hash"])
        blob = json.loads((app.ledger.blobs / envelope["blob_hash"]).read_bytes())
        proof = disclose(app.ledger.commitment_key,blob["payload"],blob["salt"],"/action/amount_minor")
        results["disclosure"] = verify_disclosure(proof,envelope["record"]["commitment"]["root"])
        forged = copy.deepcopy(proof); forged["value"] += 1
        results["forged_disclosure_rejected"] = not verify_disclosure(forged,envelope["record"]["commitment"]["root"])
        bundle = app.ledger.bundle(destination / "private-verification-bundle")
        results["verification"] = verify_bundle(bundle,app.ledger.public_key_bytes(),lambda h:(app.ledger.blobs/h).read_bytes())
        damaged = copy.deepcopy(bundle); damaged["records"][0]["record"]["timestamp_ns"] += 1
        results["tamper_verification"] = verify_bundle(damaged,app.ledger.public_key_bytes(),lambda h:(app.ledger.blobs/h).read_bytes())
        atomic_write(destination / "authorized-disclosure.json", canonical(proof))
        atomic_write(destination / "public-export.json", canonical(bundle["headers"]))
    assert results["verification"]["status"] == "PASS"
    assert results["tamper_verification"]["status"] == "FAIL"
    assert results["agreement"] == "agreement" and results["divergence"] == "divergence"
    assert results["disclosure"] and results["forged_disclosure_rejected"]
    atomic_write(destination / "demo-report.json", canonical(results))
    return results
