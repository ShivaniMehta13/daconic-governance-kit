import asyncio
import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from daconic_governance import Governance, OutcomeUnknown
from daconic_governance.boundary import egress_guard,export_header
from daconic_governance.common import digest
from daconic_governance.evidence import commitment,disclose,verify_disclosure,verify_bundle
from daconic_governance.fixtures import FixtureAdapter,profile,record,ExtractAdapter
from daconic_governance.runtime import Queue


@pytest.mark.parametrize("amount",[10001,50000])
def test_valid_approval_exact_thresholds(tmp_path,amount):
    with Governance(tmp_path/"state",FixtureAdapter([record(amount=amount)])) as app:
        app.policies.install(profile())
        run=app.broker.start_run("refund-agent","case-1")
        token=app.broker.issue_approval(agent_id="refund-agent",case_id="case-1",transaction_id="tx",record_id="record-1",max_amount_minor=amount,approver_id="human")
        result=app.broker.execute(run,"refund",{"record_id":"record-1","amount_minor":amount},"tx",token)
        assert result["decision"]["effect"]=="allow_with_modification"


def test_cumulative_violations(tmp_path):
    row=record(amount=50001); row["status"]="closed"; row["tenant"]="other"
    with Governance(tmp_path/"state",FixtureAdapter([row])) as app:
        app.policies.install(profile())
        run=app.broker.start_run("refund-agent","case-1")
        result=app.broker.execute(run,"refund",{"record_id":"record-1","amount_minor":1},"tx")
        assert set(result["decision"]["violations"])=={"scope","reference","hard_ceiling","amount_integrity"}


def test_policy_changed_between_messages(tmp_path):
    with Governance(tmp_path/"state",FixtureAdapter([record("record-1"),record("record-2")])) as app:
        app.policies.install(profile())
        def enqueue(i):
            app.queue.enqueue({"transaction_id":f"tx-{i}","case_id":"case-1","action":"refund","arguments":{"record_id":f"record-{i}","amount_minor":5000}},"refund-agent")
        enqueue(1); enqueue(2)
        app.workers.process_one("refund-agent")
        p=profile(); p["params"]["autonomous_minor"]=1; p["version"]="v2"
        app.policies.install(p)
        app.workers.process_one("refund-agent")
        assert app.queue.status("tx-1")["state"]=="done"
        assert app.queue.status("tx-2")["state"]=="holding"


def test_router_priority_specificity_and_ambiguity(tmp_path):
    with Governance(tmp_path/"state",FixtureAdapter()) as app:
        p=profile(); app.policies.install(p)
        q=profile("special-agent"); q["routes"][0]["match"]["channel"]="special"; app.policies.install(q)
        assert app.router.route({"action":"refund","channel":"special"})=="special-agent"
        r=profile("duplicate-agent"); app.policies.install(r)
        assert app.router.route({"action":"refund"}) is None
        r["routes"][0]["priority"]=100; app.policies.install(r)
        assert app.router.route({"action":"refund"})=="duplicate-agent"


def test_partial_missing_blobs_incomplete_vs_fail(tmp_path):
    with Governance(tmp_path/"state",FixtureAdapter()) as app:
        app.ledger.append("intent",{})
        data=app.ledger.bundle(tmp_path/"bundle",include_blobs=False)
        assert verify_bundle(data,app.ledger.public_key_bytes(),None)["status"]=="INCOMPLETE"
        assert verify_bundle(data,app.ledger.public_key_bytes(),lambda h:None)["status"]=="FAIL"


@pytest.mark.parametrize("payload",[{},[],{"a/b":{"~x":None}},{"x":[1,True,[],{}]}, {str(i):i for i in range(7)}])
def test_merkle_empty_odd_and_escaped_paths(payload):
    from daconic_governance.common import flatten
    key=b"x"*32; salt="12"*32
    root,_=commitment(key,payload,salt)
    for path,_ in flatten(payload):
        d=disclose(key,payload,salt,path)
        assert verify_disclosure(d,root["root"])
        d["field_key"]="00"*32
        assert not verify_disclosure(d,root["root"])


def test_same_field_value_other_record_key_not_reusable():
    key=b"x"*32; payload={"amount":1}
    first=disclose(key,payload,"11"*32,"/amount")
    second=disclose(key,payload,"22"*32,"/amount")
    assert first["field_key"]!=second["field_key"]
    assert not verify_disclosure(first,second["root"])


def test_egress_oversized_nested_values(tmp_path):
    with Governance(tmp_path/"state",FixtureAdapter()) as app:
        e=app.ledger.append("intent",{})
        h=export_header(e); h["record"]["status"]="x"*1000
        with pytest.raises(ValueError): egress_guard(h)
        h=export_header(e); h["record"]["commitment"]["unlisted"]="x"
        with pytest.raises(ValueError): egress_guard(h)


def test_completed_result_survives_restart(tmp_path):
    adapter=FixtureAdapter()
    with Governance(tmp_path/"state",adapter) as app:
        app.policies.install(profile())
        run=app.broker.start_run("refund-agent","case-1")
        expected=app.broker.execute(run,"refund",{"record_id":"record-1","amount_minor":5000},"tx")
    with Governance(tmp_path/"state",adapter) as app:
        run=app.broker.start_run("refund-agent","case-1")
        assert app.broker.execute(run,"refund",{"record_id":"record-1","amount_minor":5000},"tx")==expected
        assert adapter.calls==1


def test_unknown_queue_work_held(tmp_path):
    adapter=FixtureAdapter()
    def fail(*a): raise ConnectionError("unknown")
    adapter.apply=fail
    with Governance(tmp_path/"state",adapter) as app:
        app.policies.install(profile())
        app.queue.enqueue({"transaction_id":"tx","case_id":"case-1","action":"refund","arguments":{"record_id":"record-1","amount_minor":5000}},"refund-agent")
        app.workers.process_one("refund-agent")
        assert app.queue.status("tx")["error"]=="outcome_unknown"
        with pytest.raises(ValueError): app.queue.resume("tx",None)


def test_queue_approval_resume(tmp_path):
    with Governance(tmp_path/"state",FixtureAdapter([record(amount=20000)])) as app:
        app.policies.install(profile())
        t={"transaction_id":"tx","case_id":"case-1","action":"refund","arguments":{"record_id":"record-1","amount_minor":20000}}
        app.queue.enqueue(t,"refund-agent"); app.workers.process_one("refund-agent")
        assert app.queue.status("tx")["error"]=="step_up"
        token=app.broker.issue_approval(agent_id="refund-agent",case_id="case-1",transaction_id="tx",record_id="record-1",max_amount_minor=20000,approver_id="human")
        app.queue.resume("tx",token); app.workers.process_one("refund-agent")
        assert app.queue.status("tx")["state"]=="done"
        assert app.queue.enqueue(t,"refund-agent")["status"]=="duplicate"


def test_corruption_checkpoint_signature_and_wrong_key(tmp_path):
    with Governance(tmp_path/"state",FixtureAdapter()) as app:
        app.ledger.append("intent",{})
        data=app.ledger.bundle(tmp_path/"bundle")
        reader=lambda h:(app.ledger.blobs/h).read_bytes()
        assert verify_bundle(data,b"x"*32,reader)["status"]=="FAIL"
        data["checkpoints"][0]["signature"]="x"*88
        assert verify_bundle(data,app.ledger.public_key_bytes(),reader)["status"]=="FAIL"
