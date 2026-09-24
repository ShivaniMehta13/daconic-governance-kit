"""Bounded standard-library HTTP adapter for an isolated POC, not a production gateway."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .common import canonical, Conflict, identifier
from .runtime import validate_transaction

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Daconic transaction", "type": "object", "additionalProperties": False,
    "required": ["transaction_id", "case_id", "action", "arguments"],
    "properties": {**{k: {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,80}$"} for k in ("transaction_id", "case_id", "action", "channel")},
        "arguments": {"type": "object", "additionalProperties": False, "required": ["record_id"],
            "properties": {"record_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,80}$"}, "amount_minor": {"type": "integer", "minimum": 0}}},
        "approval_token": {"type": "string", "maxLength": 128}}}


def make_server(host, port, queue, router, credential, max_bytes=1048576, max_batch=100):
    if not isinstance(credential, str) or len(credential) < 32:
        raise ValueError("POC bearer credential must contain at least 32 characters")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            pass  # Never log credentials, URLs, or payload identifiers.

        def send_json(self, status, value):
            body = canonical(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), ("Bearer " + credential).encode()):
                self.send_json(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self.authorized(): return
            path = urlsplit(self.path).path
            if path == "/schema":
                self.send_json(200, {"single": SCHEMA, "batch": {"type": "array", "minItems": 1, "maxItems": max_batch, "items": SCHEMA}})
            elif path == "/health":
                self.send_json(200, {"status": "up", "queue": queue.counts()})
            elif path.startswith("/transactions/"):
                try:
                    transaction_id = identifier(path.rsplit("/", 1)[-1])
                    result = queue.status(transaction_id)
                    self.send_json(200 if result else 404, result or {"error": "not_found"})
                except ValueError:
                    self.send_json(400, {"error": "invalid_id"})
            else:
                self.send_json(404, {"error": "not_found"})

        def do_POST(self):
            if not self.authorized(): return
            if self.path != "/transactions":
                self.send_json(404, {"error": "not_found"})
                return
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                self.send_json(400, {"error": "single_content_length_required"})
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                self.send_json(415, {"error": "application_json_required"})
                return
            try:
                length = int(self.headers["Content-Length"])
                if not 0 < length <= max_bytes:
                    self.send_json(413, {"error": "payload_size_limit"})
                    return
                def unique_pairs(pairs):
                    obj = {}
                    for key, value in pairs:
                        if key in obj: raise ValueError("Duplicate JSON key")
                        obj[key] = value
                    return obj
                data = json.loads(self.rfile.read(length), object_pairs_hook=unique_pairs)
            except (ValueError, UnicodeError, OSError):
                self.send_json(400, {"error": "invalid_json_or_length"})
                return
            batch = isinstance(data, list)
            items = data if batch else [data]
            if not 1 <= len(items) <= max_batch:
                self.send_json(400, {"error": "invalid_batch_size"})
                return
            results = []
            for index, item in enumerate(items):
                try:
                    validate_transaction(item)
                    result = queue.enqueue(item, router.route(item))
                    results.append({"index": index, "http_status": 200 if result["status"] == "duplicate" else 202, **result})
                except Conflict:
                    results.append({"index": index, "http_status": 409, "error": "idempotency_conflict"})
                except OverflowError:
                    results.append({"index": index, "http_status": 503, "error": "queue_capacity"})
                except (ValueError, KeyError) as exc:
                    results.append({"index": index, "http_status": 422, "error": str(exc)[:128]})
                except Exception:
                    results.append({"index": index, "http_status": 503, "error": "storage_unavailable"})
            self.send_json(207 if batch else results[0]["http_status"], results if batch else results[0])

    return ThreadingHTTPServer((host, port), Handler)
