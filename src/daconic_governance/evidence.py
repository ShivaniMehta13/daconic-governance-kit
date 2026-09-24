"""Signed public chain, separately authenticated local blobs, keyed field proofs."""
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from .common import canonical, digest, flatten, EvidenceUnavailable
from .storage import atomic_write

ZERO = "0" * 64


def sign(key, value):
    return base64.b64encode(key.sign(canonical(value))).decode()


def check_signature(key, value, signature):
    key.verify(base64.b64decode(signature, validate=True), canonical(value))


def leaf_hash(value):
    return hashlib.sha256(b"\x00" + value).digest()


def merkle(items):
    if not items:
        return hashlib.sha256(b"").digest()
    if len(items) == 1:
        return leaf_hash(items[0])
    split = 1 << ((len(items) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + merkle(items[:split]) + merkle(items[split:])).digest()


def inclusion(items, index):
    if not 0 <= index < len(items):
        raise IndexError(index)
    if len(items) == 1:
        return []
    split = 1 << ((len(items) - 1).bit_length() - 1)
    if index < split:
        return inclusion(items[:split], index) + [{"side": "right", "hash": merkle(items[split:]).hex()}]
    return inclusion(items[split:], index - split) + [{"side": "left", "hash": merkle(items[:split]).hex()}]


def field_material(key, salt, path, value):
    field_key = hmac.new(key, b"daconic-field-v1\x00" + bytes.fromhex(salt) + canonical(path), hashlib.sha256).digest()
    leaf = hmac.new(field_key, canonical(path) + b"\x00" + canonical(value), hashlib.sha256).digest()
    return field_key, leaf


def commitment(key, payload, salt):
    pairs = flatten(payload)
    leaves = [field_material(key, salt, path, value)[1] for path, value in pairs]
    return {"root": merkle(leaves).hex(), "count": len(leaves)}, leaves


def disclose(key, payload, salt, path):
    pairs = flatten(payload)
    index = [p for p, _ in pairs].index(path)
    value = pairs[index][1]
    root, leaves = commitment(key, payload, salt)
    field_key, leaf = field_material(key, salt, path, value)
    return {"path": path, "value": value, "field_key": field_key.hex(), "leaf": leaf.hex(),
            "index": index, "count": len(pairs), "proof": inclusion(leaves, index), "root": root["root"]}


def verify_disclosure(disclosure, expected_root):
    """Expected root MUST come from previously authenticated evidence, not the proof."""
    try:
        d = disclosure
        leaf = hmac.new(bytes.fromhex(d["field_key"]), canonical(d["path"]) + b"\x00" + canonical(d["value"]), hashlib.sha256).digest()
        if leaf.hex() != d["leaf"] or not 0 <= d["index"] < d["count"]:
            return False
        def sides(count, index):
            if count == 1:
                return []
            split = 1 << ((count - 1).bit_length() - 1)
            return (sides(split, index) + ["right"] if index < split
                    else sides(count - split, index - split) + ["left"])
        if [p["side"] for p in d["proof"]] != sides(d["count"], d["index"]):
            return False
        node = leaf_hash(leaf)
        for step in d["proof"]:
            sibling = bytes.fromhex(step["hash"])
            if len(sibling) != 32:
                return False
            node = hashlib.sha256(b"\x01" + (sibling + node if step["side"] == "left" else node + sibling)).digest()
        return hmac.compare_digest(node.hex(), expected_root)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


class Ledger:
    def __init__(self, store, checkpoint_records=100, checkpoint_seconds=30):
        self.store = store
        self.metrics = {"append_ns": 0, "blob_write_ns": 0, "commitment_sign_ns": 0, "checkpoint_ns": 0, "appends": 0}
        self.blobs = store.directory / "blobs"
        self.checkpoints = store.directory / "checkpoints"
        self.blobs.mkdir(exist_ok=True, mode=0o700)
        self.checkpoints.mkdir(exist_ok=True, mode=0o700)
        self.checkpoint_records = checkpoint_records
        self.checkpoint_seconds = checkpoint_seconds
        if checkpoint_records < 1 or checkpoint_seconds <= 0:
            raise ValueError("Invalid checkpoint interval")
        key_file = store.directory / "signing.key"
        commitment_file = store.directory / "commitment.key"
        with store.lock:
            existing = store.db.execute("SELECT count(*) FROM ledger").fetchone()[0]
            if existing and (not key_file.exists() or not commitment_file.exists()):
                raise EvidenceUnavailable("Existing evidence has missing keys; refusing rotation")
            if not key_file.exists():
                key = Ed25519PrivateKey.generate()
                atomic_write(key_file, key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            if not commitment_file.exists():
                atomic_write(commitment_file, secrets.token_bytes(32))
            self.key = Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())
            self.commitment_key = commitment_file.read_bytes()
        with store.transaction() as db:
            db.execute("INSERT OR IGNORE INTO meta VALUES ('deployment', ?)", (str(uuid.uuid4()),))
            self.deployment = db.execute("SELECT value FROM meta WHERE key='deployment'").fetchone()[0]
            public = self.public_key_bytes().hex()
            db.execute("INSERT OR IGNORE INTO meta VALUES ('public_key', ?)", (public,))
            if db.execute("SELECT value FROM meta WHERE key='public_key'").fetchone()[0] != public:
                raise EvidenceUnavailable("Signing key does not match deployment")
        self.last_checkpoint_time = time.monotonic()
        files = sorted(self.checkpoints.glob("*.json"))
        self.checkpoint_number = len(files)
        self.last_checkpoint_seq = 0
        self.last_checkpoint_hash = ZERO
        if files:
            cp = json.loads(files[-1].read_text())
            check_signature(self.key.public_key(), cp["body"], cp["signature"])
            self.last_checkpoint_seq = cp["body"]["end"]
            self.last_checkpoint_hash = digest(cp)

    def public_key_bytes(self):
        return self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _append(self, db, event, payload, *, decision=None, actor=None, findings=None, correlation=None, status=None):
        """Internal only: caller holds Store.transaction, allowing atomic token+intent writes."""
        started_append = time.perf_counter_ns()
        row = db.execute("SELECT seq,envelope FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        seq = row["seq"] + 1 if row else 1
        previous = json.loads(row["envelope"])["hash"] if row else ZERO
        salt = secrets.token_hex(32)
        started_crypto = time.perf_counter_ns()
        root, _ = commitment(self.commitment_key, payload, salt)
        crypto_ns = time.perf_counter_ns() - started_crypto
        blob_bytes = canonical({"salt": salt, "payload": payload})
        blob_hash = digest(blob_bytes)
        blob_path = self.blobs / blob_hash
        started_blob = time.perf_counter_ns()
        if not blob_path.exists():
            atomic_write(blob_path, blob_bytes)
        elif digest(blob_path.read_bytes()) != blob_hash:
            raise EvidenceUnavailable("Existing payload blob is corrupt")
        self.metrics["blob_write_ns"] += time.perf_counter_ns() - started_blob
        record = {"format": "daconic-evidence-v2", "deployment": self.deployment, "seq": seq,
                  "id": str(uuid.uuid4()), "timestamp_ns": time.time_ns(), "event": event,
                  "prev_hash": previous, "commitment": root, "decision": decision,
                  "actor": actor, "findings": findings or [], "correlation": correlation, "status": status}
        from .boundary import validate_record
        validate_record(record)
        record_hash = digest(record)
        started_crypto = time.perf_counter_ns()
        envelope = {"record": record, "hash": record_hash, "signature": sign(self.key, record),
                    "blob_hash": blob_hash, "blob_signature": sign(self.key, {"record_hash": record_hash, "blob_hash": blob_hash})}
        db.execute("INSERT INTO ledger VALUES (?,?)", (seq, canonical(envelope).decode()))
        self.metrics["commitment_sign_ns"] += crypto_ns + time.perf_counter_ns() - started_crypto
        self.metrics["append_ns"] += time.perf_counter_ns() - started_append
        self.metrics["appends"] += 1
        return envelope

    def append(self, event, payload, **kwargs):
        try:
            with self.store.transaction() as db:
                envelope = self._append(db, event, payload, **kwargs)
            self.checkpoint()
            return envelope
        except Exception as exc:
            raise EvidenceUnavailable("Evidence write failed; inspect local cause") from exc

    def records(self):
        with self.store.lock:
            return [json.loads(r[0]) for r in self.store.db.execute("SELECT envelope FROM ledger ORDER BY seq")]

    def checkpoint(self, force=False):
        with self.store.lock:
            last = self.store.db.execute("SELECT max(seq) FROM ledger").fetchone()[0] or 0
            if not force and last - self.last_checkpoint_seq < self.checkpoint_records and time.monotonic() - self.last_checkpoint_time < self.checkpoint_seconds:
                return
            started_checkpoint = time.perf_counter_ns()
            rows = self.store.db.execute("SELECT envelope FROM ledger WHERE seq>? ORDER BY seq", (self.last_checkpoint_seq,)).fetchall()
            hashes = [bytes.fromhex(json.loads(r[0])["hash"]) for r in rows]
            body = {"deployment": self.deployment, "number": self.checkpoint_number + 1,
                    "start": self.last_checkpoint_seq + 1, "end": last, "heartbeat": not bool(hashes),
                    "root": merkle(hashes).hex(), "previous": self.last_checkpoint_hash, "timestamp_ns": time.time_ns()}
            envelope = {"body": body, "signature": sign(self.key, body)}
            atomic_write(self.checkpoints / f"{body['number']:012d}.json", canonical(envelope))
            self.last_checkpoint_hash = digest(envelope)
            self.last_checkpoint_seq = last
            self.checkpoint_number += 1
            self.last_checkpoint_time = time.monotonic()
            self.metrics["checkpoint_ns"] += time.perf_counter_ns() - started_checkpoint

    def bundle(self, destination, include_blobs=True):
        from .boundary import export_header
        destination = Path(destination)
        if destination.exists() and any(destination.iterdir()):
            raise ValueError("Bundle destination must be empty")
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.store.lock:
            self.checkpoint(force=True)
            records = self.records()
            headers = [export_header(e) for e in records]
            checkpoints = [json.loads(p.read_text()) for p in sorted(self.checkpoints.glob("*.json"))]
            manifest = {"deployment": self.deployment, "count": len(records),
                        "head": records[-1]["hash"] if records else ZERO,
                        "checkpoint_head": digest(checkpoints[-1]), "headers_hash": digest(headers)}
            data = {"records": records, "headers": headers, "checkpoints": checkpoints,
                    "manifest": {"body": manifest, "signature": sign(self.key, manifest)}}
            atomic_write(destination / "evidence.json", canonical(data))
            atomic_write(destination / "public.key", self.public_key_bytes())
            atomic_write(destination / "export.json", canonical(headers))
            if include_blobs:
                for e in records:
                    atomic_write(destination / "blobs" / e["blob_hash"], (self.blobs / e["blob_hash"]).read_bytes())
        return data


def verify_bundle(data, public_key, blob_reader=None):
    """No deployment access. Public key must be authenticated out of band."""
    from .boundary import export_header
    errors, warnings = [], []
    if blob_reader is None:
        warnings.append("PAYLOADS_NOT_CHECKED")
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        records = data["records"]
        manifest = data["manifest"]
        check_signature(key, manifest["body"], manifest["signature"])
        m = manifest["body"]
        previous = ZERO
        hashes = []
        for expected_seq, envelope in enumerate(records, 1):
            try:
                r = envelope["record"]
                seq = r["seq"]
                if seq != expected_seq:
                    errors.append(f"record {expected_seq}: sequence gap or reorder")
                if r["deployment"] != m["deployment"]:
                    errors.append(f"record {expected_seq}: wrong deployment")
                actual = digest(r)
                hashes.append(bytes.fromhex(actual))
                if actual != envelope["hash"]:
                    errors.append(f"record {seq}: content hash mismatch")
                if r["prev_hash"] != previous:
                    errors.append(f"record {seq}: chain mismatch")
                check_signature(key, r, envelope["signature"])
                check_signature(key, {"record_hash": actual, "blob_hash": envelope["blob_hash"]}, envelope["blob_signature"])
                previous = actual  # Never trust the stored hash for chain verification.
                if blob_reader is not None:
                    blob = blob_reader(envelope["blob_hash"])
                    if blob is None or digest(blob) != envelope["blob_hash"]:
                        errors.append(f"record {seq}: missing or corrupt payload")
                export_header(envelope)
            except Exception as exc:
                errors.append(f"record {expected_seq}: invalid {type(exc).__name__}")
                # Advance using content even when signature validation failed.
                previous = digest(envelope["record"])
        if len(records) != m["count"] or previous != m["head"]:
            errors.append("manifest: record count or head mismatch (including suffix deletion)")
        checkpoint_previous, end = ZERO, 0
        for number, cp in enumerate(data["checkpoints"], 1):
            body = cp["body"]
            check_signature(key, body, cp["signature"])
            if body["number"] != number or body["previous"] != checkpoint_previous or body["deployment"] != m["deployment"]:
                errors.append(f"checkpoint {number}: continuity mismatch")
            if body["start"] != end + 1 or not end <= body["end"] <= len(records):
                errors.append(f"checkpoint {number}: invalid coverage")
            if body["heartbeat"] != (body["end"] == end):
                errors.append(f"checkpoint {number}: heartbeat mismatch")
            if merkle(hashes[end:body["end"]]).hex() != body["root"]:
                errors.append(f"checkpoint {number}: Merkle mismatch")
            end = body["end"]
            checkpoint_previous = digest(cp)
        if end != len(records) or checkpoint_previous != m["checkpoint_head"]:
            errors.append("checkpoint: incomplete coverage or deleted suffix")
        expected_headers = [export_header(e) for e in records]
        if data["headers"] != expected_headers or digest(data["headers"]) != m["headers_hash"]:
            errors.append("export: mismatch against local records or manifest")
    except Exception as exc:
        errors.append(f"bundle: malformed or invalid signature ({type(exc).__name__})")
    return {"status": "FAIL" if errors else "INCOMPLETE" if warnings else "PASS", "errors": errors, "warnings": warnings}
