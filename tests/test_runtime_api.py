import json
import threading
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
import pytest
from daconic_governance import Governance, Conflict
from daconic_governance.api import make_server
from daconic_governance.evidence import verify_bundle
from daconic_governance.fixtures import FixtureAdapter, profile, record
from daconic_governance.runtime import Queue, validate_transaction


def transaction(i=1):
    return {"transaction_id":f"tx-{i}","case_id":"case-1","action":"refund","arguments":{"record_id":f"record-{i}","amount_minor":5000}}


@pytest.fixture
def app(tmp_path):
    with Governance(tmp_path / "state",FixtureAdapter([record(f"record-{i}") for i in range(100)])) as app:
        app.policies.install(profile()); app.policies.install(profile("reader-agent",True))
        yield app


def test_queue_exclusive_leases(app):
    for i in range(50): app.queue.enqueue(transaction(i),"refund-agent")
    with ThreadPoolExecutor(max_workers=20) as pool:
        messages = list(pool.map(lambda _:app.queue.lease("refund-agent"),range(80)))
    leased = [m for m in messages if m]
    assert len(leased) == len({m["id"] for m in leased}) == 50
    assert app.queue.ack(leased[0])
    assert not app.queue.ack(leased[0])


def test_retry_reap_dead_letter(app):
    q = Queue(app.store,visibility_seconds=0.01,max_attempts=2,backoff_seconds=0)
    q.enqueue(transaction(),"refund-agent")
    first = q.lease("refund-agent")
    app.store.db.execute("UPDATE queue SET lease_until=0")
    assert q.reap() == 1
    second = q.lease("refund-agent")
    assert second["token"] != first["token"]
    assert not q.ack(first)
    assert q.nack(second)
    assert q.status("tx-1")["state"] == "dead"


def test_idempotency_and_holding(app):
    t = transaction()
    assert app.queue.enqueue(t,"refund-agent")["status"] == "accepted"
    assert app.queue.enqueue(t,"refund-agent")["status"] == "duplicate"
    t["arguments"]["amount_minor"] = 1
    with pytest.raises(Conflict): app.queue.enqueue(t,"refund-agent")
    t = transaction(2); t["action"] = "unrouted"
    assert app.router.route(t) is None
    assert app.queue.enqueue(t,None)["state"] == "holding"


def test_workers_concurrency_intact(app,tmp_path):
    for i in range(80):
        t = transaction(i)
        if i%2: t["action"] = "read_record"
        app.queue.enqueue(t,app.router.route(t))
    app.workers.start()
    deadline = time.monotonic()+10
    while app.queue.counts().get("done",0)<80 and time.monotonic()<deadline:
        time.sleep(0.01)
    app.workers.close()
    assert app.queue.counts() == {"done":80}
    assert not app.workers.errors
    records = app.ledger.records()
    assert len({e["record"]["seq"] for e in records}) == len(records)
    data = app.ledger.bundle(tmp_path / "bundle")
    assert verify_bundle(data,app.ledger.public_key_bytes(),lambda h:(app.ledger.blobs/h).read_bytes())["status"]=="PASS"


def test_malformed_in_queue_dead_letter(app):
    q = Queue(app.store,max_attempts=1)
    app.workers.queue = q
    q.enqueue(transaction(),"refund-agent")
    app.store.db.execute("UPDATE queue SET payload='{}'")
    assert app.workers.process_one("refund-agent")
    assert q.status("tx-1")["state"]=="dead"


def test_api_batch_schema_auth_duplicates(app):
    credential = "a"*40
    server = make_server("127.0.0.1",0,app.queue,app.router,credential)
    thread = threading.Thread(target=server.serve_forever); thread.start()
    def request(data, token=credential, path="/transactions"):
        req = urllib.request.Request(f"http://127.0.0.1:{server.server_port}"+path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Content-Type":"application/json","Authorization":"Bearer "+token})
        try:
            with urllib.request.urlopen(req) as response: return response.status,json.load(response)
        except urllib.error.HTTPError as e:
            return e.code,json.load(e)
    try:
        assert request(transaction(),token="wrong")[0]==401
        assert request(None,path="/schema")[0]==200
        status, body = request([transaction(),{"bad":1},transaction(2)])
        assert status==207 and [r["http_status"] for r in body]==[202,422,202]
        assert app.queue.counts()=={"ready":2}
        assert request(transaction())[0]==200
        changed = transaction(); changed["arguments"]["amount_minor"] = 3
        assert request(changed)[0]==409
        assert request({"bad":1})[0]==422
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_no_leaked_store_handle(tmp_path):
    state = tmp_path / "state"
    app = Governance(state,FixtureAdapter())
    app.close()
    assert app.store.closed and app.store._lease.closed
    app = Governance(state,FixtureAdapter())
    app.close()
    (state / "state.sqlite3").rename(state / "renamed.sqlite3")


@pytest.mark.parametrize("bad", [None,[],{"x":1},{**transaction(),"arguments":{"record_id":"x","amount_minor":1.5}}, {**transaction(),"case_id":"../x"}])
def test_validation(bad):
    with pytest.raises(ValueError): validate_transaction(bad)
