"""Durable at-least-once work delivery. Execution deduplication belongs to Broker."""
import json
import secrets
import threading
import time
from .common import canonical, digest, identifier, Conflict, OutcomeUnknown, EvidenceUnavailable


def validate_transaction(value):
    if not isinstance(value, dict) or set(value) - {"transaction_id", "case_id", "action", "arguments", "channel", "approval_token"}:
        raise ValueError("Unexpected transaction fields")
    for key in ("transaction_id", "case_id", "action"):
        if key not in value:
            raise ValueError("Missing " + key)
        identifier(value[key])
    args = value.get("arguments")
    if not isinstance(args, dict) or set(args) - {"record_id", "amount_minor"} or "record_id" not in args:
        raise ValueError("arguments requires record_id and optional amount_minor")
    identifier(args["record_id"])
    if "amount_minor" in args and (type(args["amount_minor"]) is not int or args["amount_minor"] < 0):
        raise ValueError("amount_minor must be a non-negative integer")
    if "channel" in value:
        identifier(value["channel"])
    if "approval_token" in value and (not isinstance(value["approval_token"], str) or len(value["approval_token"]) > 128):
        raise ValueError("Invalid approval token")
    canonical(value)
    return value


class Router:
    def __init__(self, policies):
        self.policies = policies

    def route(self, transaction):
        candidates = []
        for policy in self.policies.all():
            doc = policy.document
            for route in doc["routes"]:
                if all(transaction.get(k) == v for k, v in route["match"].items()):
                    candidates.append((route["priority"], len(route["match"]), doc["agent_id"]))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        top = candidates[0]
        if any(c[:2] == top[:2] and c[2] != top[2] for c in candidates[1:]):
            return None  # Ambiguous routing is held rather than silently selecting authority.
        return top[2]


class Queue:
    def __init__(self, store, visibility_seconds=30, max_attempts=3, backoff_seconds=1, max_depth=10000):
        if visibility_seconds <= 0 or max_attempts < 1 or backoff_seconds < 0 or max_depth < 1:
            raise ValueError("Invalid queue configuration")
        self.store, self.visibility = store, visibility_seconds
        self.max_attempts, self.backoff, self.max_depth = max_attempts, backoff_seconds, max_depth

    def enqueue(self, transaction, agent):
        validate_transaction(transaction)
        fingerprint = digest(transaction)
        with self.store.transaction() as db:
            row = db.execute("SELECT fingerprint,state FROM queue WHERE id=?", (transaction["transaction_id"],)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise Conflict("Idempotency key reused with different payload; use resume for approval")
                return {"status": "duplicate", "state": row["state"]}
            count = db.execute("SELECT count(*) FROM queue WHERE state NOT IN ('done','dead')").fetchone()[0]
            if count >= self.max_depth:
                raise OverflowError("Queue capacity reached")
            state = "ready" if agent else "holding"
            db.execute("INSERT INTO queue(id,fingerprint,payload,agent,state,available) VALUES (?,?,?,?,?,?)",
                       (transaction["transaction_id"], fingerprint, canonical(transaction).decode(), agent, state, time.time()))
        return {"status": "accepted", "state": state}

    def lease(self, agent):
        now = time.time()
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM queue WHERE state='ready' AND agent=? AND available<=? ORDER BY available,id LIMIT 1", (agent, now)).fetchone()
            if row is None:
                return None
            token = secrets.token_hex(16)
            db.execute("UPDATE queue SET state='leased',attempts=attempts+1,lease_token=?,lease_until=? WHERE id=?", (token, now + self.visibility, row["id"]))
            return {"id": row["id"], "token": token, "payload": json.loads(row["payload"]), "attempt": row["attempts"] + 1}

    def _finish(self, message, state, error=None, delay=0):
        with self.store.transaction() as db:
            cursor = db.execute("UPDATE queue SET state=?,error=?,available=?,lease_until=NULL,lease_token=NULL WHERE id=? AND state='leased' AND lease_token=? AND lease_until>?",
                (state, error, time.time()+delay, message["id"], message["token"], time.time()))
            return cursor.rowcount == 1

    def ack(self, message):
        return self._finish(message, "done")

    def nack(self, message, error="processing_failure"):
        terminal = message["attempt"] >= self.max_attempts
        return self._finish(message, "dead" if terminal else "ready", error, min(300, self.backoff * 2 ** (message["attempt"]-1)))

    def hold(self, message, reason):
        return self._finish(message, "holding", reason)

    def reap(self):
        now = time.time()
        with self.store.transaction() as db:
            rows = db.execute("SELECT id,attempts FROM queue WHERE state='leased' AND lease_until<=?", (now,)).fetchall()
            for row in rows:
                terminal = row["attempts"] >= self.max_attempts
                db.execute("UPDATE queue SET state=?,available=?,lease_token=NULL,lease_until=NULL,error='lease_expired' WHERE id=?",
                    ("dead" if terminal else "ready", now + min(300, self.backoff * 2 ** (row["attempts"]-1)), row["id"]))
            return len(rows)

    def renew(self, message):
        with self.store.transaction() as db:
            return db.execute("UPDATE queue SET lease_until=? WHERE id=? AND state='leased' AND lease_token=? AND lease_until>?",
                (time.time()+self.visibility, message["id"], message["token"], time.time())).rowcount == 1

    def resume(self, transaction_id, approval_token, agent=None):
        """Trusted operator action; never requeue unknown outcomes automatically."""
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM queue WHERE id=?", (transaction_id,)).fetchone()
            if row is None or row["state"] != "holding" or row["error"] not in (None, "step_up", "defer"):
                raise ValueError("Only unrouted, approval-pending or deferred work may resume")
            data = json.loads(row["payload"])
            if approval_token:
                data["approval_token"] = approval_token
            validate_transaction(data)
            db.execute("UPDATE queue SET payload=?,agent=?,state='ready',available=? WHERE id=?",
                (canonical(data).decode(), agent or row["agent"], time.time(), transaction_id))

    def status(self, transaction_id):
        with self.store.lock:
            row = self.store.db.execute("SELECT id,state,attempts,error FROM queue WHERE id=?", (transaction_id,)).fetchone()
        return dict(row) if row else None

    def counts(self):
        with self.store.lock:
            return {r[0]: r[1] for r in self.store.db.execute("SELECT state,count(*) FROM queue GROUP BY state")}

    def close(self):
        """Queue opens no connections. Shared Store owner closes after workers stop."""


class Workers:
    def __init__(self, queue, broker, corroborate_every=1):
        self.queue, self.broker = queue, broker
        self.corroborate_every = corroborate_every
        self.stop_event = threading.Event()
        self.threads = []
        self.errors = []

    def process_one(self, agent):
        message = self.queue.lease(agent)
        if message is None:
            return False
        run = None
        renewal_stop = threading.Event()
        def renew_lease():
            while not renewal_stop.wait(max(0.001, self.queue.visibility / 3)):
                try:
                    if not self.queue.renew(message):
                        return
                except Exception:
                    return  # Broker deduplication still prevents repeated dispatch.
        renewal = threading.Thread(target=renew_lease, daemon=False)
        renewal.start()
        try:
            t = message["payload"]
            validate_transaction(t)
            run = self.broker.start_run(agent, t["case_id"])
            result = self.broker.execute(run, t["action"], t["arguments"], t["transaction_id"], t.get("approval_token"))
            effect = result["decision"]["effect"]
            if effect in {"step_up", "defer"}:
                self.queue.hold(message, effect)
            else:
                if effect in {"allow", "allow_with_modification"} and self.corroborate_every and int(digest(t["transaction_id"]), 16) % self.corroborate_every == 0:
                    self.broker.corroborate(result["intent_hash"])
                self.queue.ack(message)
        except OutcomeUnknown:
            self.queue.hold(message, "outcome_unknown")
        except EvidenceUnavailable:
            self.queue.hold(message, "evidence_unavailable")
        except Exception as exc:
            self.queue.nack(message, type(exc).__name__)
        finally:
            renewal_stop.set()
            renewal.join()
            if run:
                self.broker.end_run(run)
        return True

    def start(self):
        if self.threads:
            raise RuntimeError("Workers already started")
        for policy in self.broker.policies.all():
            doc = policy.document
            for _ in range(doc["params"]["concurrency"]):
                thread = threading.Thread(target=self._loop, args=(doc["agent_id"],), daemon=False)
                thread.start()
                self.threads.append(thread)
        maintenance = threading.Thread(target=self._maintenance, daemon=False)
        maintenance.start()
        self.threads.append(maintenance)

    def _loop(self, agent):
        while not self.stop_event.is_set():
            try:
                if not self.process_one(agent):
                    self.stop_event.wait(0.02)
            except Exception as exc:
                self.errors.append(type(exc).__name__)
                self.stop_event.set()

    def _maintenance(self):
        while not self.stop_event.wait(0.2):
            try:
                self.queue.reap()
                self.broker.ledger.checkpoint()
            except Exception as exc:
                self.errors.append(type(exc).__name__)
                self.stop_event.set()

    def close(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=10)
        if any(t.is_alive() for t in self.threads):
            raise RuntimeError("Adapter is still blocked; cannot safely close storage")
        self.threads.clear()
