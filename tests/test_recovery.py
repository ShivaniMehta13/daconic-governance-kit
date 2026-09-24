import json
import threading
import time
from pathlib import Path
import pytest
from daconic_governance import Governance, EvidenceUnavailable, OutcomeUnknown
from daconic_governance.fixtures import FixtureAdapter,profile,record
from daconic_governance.runtime import Queue
from daconic_governance.common import canonical
from daconic_governance.storage import Store


def test_key_loss_refuses_start(tmp_path):
    state = tmp_path / "state"
    with Governance(state,FixtureAdapter()) as app:
        app.ledger.append("intent",{})
    (state/"signing.key").rename(state/"saved.key")
    with pytest.raises(EvidenceUnavailable): Governance(state,FixtureAdapter())


def test_multiple_store_owners_refused(tmp_path):
    with Store(tmp_path/"state"):
        with pytest.raises(RuntimeError): Store(tmp_path/"state")


def test_post_dispatch_evidence_failure_and_restart(tmp_path,monkeypatch):
    adapter = FixtureAdapter()
    with Governance(tmp_path/"state",adapter) as app:
        app.policies.install(profile())
        original = app.ledger._append
        def fail_outcome(db,event,*args,**kwargs):
            if event=="outcome": raise OSError("outcome disk full")
            return original(db,event,*args,**kwargs)
        monkeypatch.setattr(app.ledger,"_append",fail_outcome)
        run = app.broker.start_run("refund-agent","case-1")
        with pytest.raises(OutcomeUnknown): app.broker.execute(run,"refund",{"record_id":"record-1","amount_minor":5000},"tx-1")
        assert adapter.calls==1
    with Governance(tmp_path/"state",adapter) as app:
        run = app.broker.start_run("refund-agent","case-1")
        with pytest.raises(OutcomeUnknown): app.broker.execute(run,"refund",{"record_id":"record-1","amount_minor":5000},"tx-1")
        assert adapter.calls==1


def test_long_call_lease_is_renewed(tmp_path):
    adapter = FixtureAdapter()
    original = adapter.apply
    def slow(*args):
        time.sleep(0.15)
        return original(*args)
    adapter.apply = slow
    with Governance(tmp_path/"state",adapter) as app:
        app.policies.install(profile())
        app.queue = Queue(app.store,visibility_seconds=0.06)
        app.workers.queue = app.queue
        app.queue.enqueue({"transaction_id":"tx-1","case_id":"case-1","action":"refund","arguments":{"record_id":"record-1","amount_minor":5000}},"refund-agent")
        app.workers.process_one("refund-agent")
        assert app.queue.status("tx-1")["state"]=="done"


def test_async_integration(tmp_path):
    import asyncio
    with Governance(tmp_path/"state",FixtureAdapter()) as app:
        app.policies.install(profile())
        run = app.broker.start_run("refund-agent","case-1")
        result = asyncio.run(app.broker.aexecute(run,"refund",{"record_id":"record-1","amount_minor":5000},"tx-1"))
        assert result["result"]["balance_minor"]==95000


def test_response_export_does_not_leak_dynamic_keys(tmp_path):
    from daconic_governance.boundary import export_header
    with Governance(tmp_path/"state",FixtureAdapter()) as app:
        app.policies.install(profile())
        run = app.broker.start_run("refund-agent","case-1")
        target={"provider":"fixture","model":"echo","model_version":"v1","endpoint":"https://user:secret@internal.local","request_id":"CUSTOMER-secret","generation_parameters":{}}
        app.broker.record_llm_call(run,target=target,request={"CUSTOMER-secret":"hello"},dispatch=lambda r:r)
        exported = json.dumps([export_header(e) for e in app.ledger.records()])
        for secret in ("CUSTOMER-secret","hello","internal.local","user:secret"):
            assert secret not in exported


def test_schema_strict_canonical():
    for bad in (float("nan"),1.0,{1:"key"},object()):
        with pytest.raises(ValueError): canonical(bad)
