"""Paced HTTP ingestion -> durable workers -> evidence -> sampled corroboration."""
import json
import os
import platform
import secrets
import threading
import time
import urllib.request
from pathlib import Path
from .application import Governance
from .api import make_server
from .common import canonical
from .evidence import verify_bundle
from .fixtures import FixtureAdapter, profile, record
from .storage import atomic_write


def benchmark(destination, seconds=180, rate=50):
    if seconds < 10 or rate < 1:
        raise ValueError("Benchmark requires >=10 seconds and positive integer rate")
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Benchmark output must be empty")
    total = seconds * rate
    adapter = FixtureAdapter([record(f"record-{i}",5000) for i in range(total)])
    token = secrets.token_urlsafe(32)
    with Governance(destination / "deployment",adapter,checkpoint_records=100,checkpoint_seconds=10) as app:
        app.policies.install(profile())
        app.policies.install(profile("reader-agent",True))
        app.workers.corroborate_every = 10
        app.workers.start()
        server = make_server("127.0.0.1",0,app.queue,app.router,token)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        accepted, rejected, max_backlog = 0, 0, 0
        started = time.monotonic()
        wall_started = time.time_ns()
        samples = []
        try:
            for second in range(seconds):
                delay = started + second - time.monotonic()
                if delay > 0:
                    app.workers.stop_event.wait(delay)
                # 80% refunds / 20% reads, across two agent worker pools.
                batch = [{"transaction_id":f"tx-{i}","case_id":"case-1","action":"read_record" if i%5==0 else "refund",
                          "arguments":{"record_id":f"record-{i}","amount_minor":5000}}
                         for i in range(second*rate,(second+1)*rate)]
                request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/transactions", data=canonical(batch),
                    headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
                with urllib.request.urlopen(request,timeout=30) as response:
                    result = json.load(response)
                accepted += sum(r.get("status") == "accepted" for r in result)
                rejected += sum(r.get("http_status",500) >= 400 for r in result)
                counts = app.queue.counts()
                backlog = sum(counts.get(k,0) for k in ("ready","leased","holding"))
                max_backlog = max(max_backlog,backlog)
                samples.append({"second":second,"done":counts.get("done",0),"backlog":backlog})
                if app.workers.errors:
                    raise RuntimeError("Workers failed: " + str(app.workers.errors))
            remaining = started + seconds - time.monotonic()
            if remaining > 0:
                app.workers.stop_event.wait(remaining)
            deadline = time.monotonic()+60
            while app.queue.counts().get("done",0) < total and time.monotonic() < deadline:
                if app.workers.stop_event.wait(0.02): break
            finished = time.monotonic()
        finally:
            server.shutdown(); server.server_close(); thread.join()
            app.workers.close()
        counts = app.queue.counts()
        bundle = app.ledger.bundle(destination / "verification-bundle",include_blobs=False)
        verification = verify_bundle(bundle,app.ledger.public_key_bytes(),lambda h:(app.ledger.blobs/h).read_bytes())
        envelopes = bundle["records"]
        corroborations = [e for e in envelopes if e["record"]["event"] == "corroboration"]
        windows = []
        for minute in range((seconds+59)//60):
            start = wall_started + minute*60*1000000000
            end = min(wall_started+seconds*1000000000,start+60*1000000000)
            outcomes = sum(e["record"]["event"] == "outcome" and start<=e["record"]["timestamp_ns"]<end for e in envelopes)
            windows.append({"minute":minute+1,"outcomes":outcomes,"window_seconds":(end-start)//1000000000})
        elapsed = finished-started
        measured_costs = {"ledger_append_including_blob_crypto_sql_ms":app.ledger.metrics["append_ns"]//1000000,
                          "blob_write_ms":app.ledger.metrics["blob_write_ns"]//1000000,
                          "commitment_sign_insert_ms":app.ledger.metrics["commitment_sign_ns"]//1000000,
                          "sqlite_commit_ms":app.store.commit_ns//1000000,
                          "checkpoint_ms":app.ledger.metrics["checkpoint_ns"]//1000000}
        report = {"fixture_only":True,"duration_seconds":seconds,"elapsed_ms":round(elapsed*1000),
            "offered_transactions":total,"accepted":accepted,"rejected":rejected,"completed":counts.get("done",0),
            "completed_per_minute":round(counts.get("done",0)/elapsed*60),"target_per_minute":rate*60,
            "evidence_records":len(envelopes),"records_per_1000_transactions":round(len(envelopes)/total*1000),
            "corroborated":len(corroborations),"corroboration_divergences":sum(e["record"]["status"]!="agreement" for e in corroborations),
            "checkpoint_count":len(bundle["checkpoints"]),"maximum_sampled_backlog":max_backlog,"queue_states":counts,
            "verification":verification,"minute_windows":windows,"queue_samples":samples,
            "hardware":{"platform":platform.platform(),"python":platform.python_version(),"logical_cpus":os.cpu_count()},
            "workload":{"refund_percent":80,"read_percent":20,"workers":4,"classification":"request facts + output","payload":"synthetic small record with PAN/credential/PII","corroboration_sampling":"transaction hash modulo 10"},
            "durability":{"sqlite":"WAL synchronous=FULL","blob":"fsync + atomic rename + directory fsync","checkpoint_records":100,"checkpoint_seconds":10},
            "measured_stage_costs":measured_costs,
            "limiting_component":"Not established by paced test; use saturation profiling before claiming a bottleneck",
            "plumbed_acceptance":"Pending agreed workload, hardware, duration and customer environment"}
        atomic_write(destination / "benchmark-report.json",canonical(report))
        return report
