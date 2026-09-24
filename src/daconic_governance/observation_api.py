"""Authenticated local observation service. Never enables execution APIs."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from .common import canonical, Conflict

STATUSES = ("COMPLIANT", "VIOLATION", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE")


def make_observation_server(host, port, observer, token, trusted_key=None):
    if len(token) < 32: raise ValueError("API token must have at least 32 characters")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass  # No payloads, tokens, paths or identities in logs.

        def reply(self, status, payload, content_type="application/json"):
            body = canonical(payload) if content_type == "application/json" else payload
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(body)

        def auth(self):
            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, ("Bearer " + token).encode()):
                self.reply(401, {"error": "unauthorized"}); return False
            return True

        def do_GET(self):
            path = urlsplit(self.path).path
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if path in assets:
                name, kind = assets[path]
                return self.reply(200, (Path(__file__).parent / "dashboard" / name).read_bytes(), kind)
            if not self.auth(): return
            try:
                if path == "/health": return self.reply(200, {"status": "ok", "mode": "observe"})
                if path == "/results":
                    rows = observer.results()
                    query = parse_qs(urlsplit(self.path).query)
                    for field in ("compliance", "scenario", "agent_id", "severity"):
                        if field in query: rows = [r for r in rows if r[field] == query[field][0]]
                    if "q" in query:
                        q = query["q"][0].lower()
                        rows = [r for r in rows if q in canonical(r).decode().lower()]
                    return self.reply(200, {"results": rows, "counts": {s: sum(r["compliance"] == s for r in rows) for s in STATUSES}, "total": len(rows)})
                if path == "/policies":
                    with observer.store.lock:
                        policies = [json.loads(r[0]) for r in observer.store.db.execute("SELECT document FROM observation_policies")]
                    from .observation import evidence_requirements
                    return self.reply(200, {"policies": [{"id": observer.opaque(p["id"]), "version": observer.opaque(p["version"]), "checks": [{"kind": c["kind"], "stage": c["stage"]} for c in p["checks"]], "requirements": evidence_requirements(p)} for p in policies]})
                return self.reply(404, {"error": "not_found"})
            except Exception:
                self.reply(503, {"error": "evidence_or_storage_unavailable"})

        def do_POST(self):
            if not self.auth(): return
            path = urlsplit(self.path).path
            if path not in {"/observations", "/verify"}: return self.reply(404, {"error": "not_found"})
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                return self.reply(400, {"error": "single_content_length_required"})
            try: length = int(self.headers["Content-Length"])
            except ValueError: return self.reply(400, {"error": "invalid_length"})
            if not 0 <= length <= 1048576: return self.reply(413, {"error": "payload_too_large"})
            if self.headers.get_content_type() != "application/json": return self.reply(415, {"error": "json_required"})
            self.connection.settimeout(10)
            try:
                raw = self.rfile.read(length)
                if len(raw) != length: raise ValueError("Incomplete request")
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result: raise ValueError("Duplicate JSON key")
                        result[key] = value
                    return result
                data = json.loads(raw, object_pairs_hook=unique)
                if path == "/verify":
                    if data != {}: raise ValueError("Verification takes an empty object")
                    if trusted_key is None: return self.reply(409, {"error": "trusted_key_not_configured"})
                    return self.reply(200, observer.verify(trusted_key))
                return self.reply(200, observer.observe(data))
            except Conflict: self.reply(409, {"error": "identifier_conflict"})
            except (ValueError, TypeError, KeyError, RecursionError): self.reply(422, {"error": "invalid_observation_or_policy"})
            except Exception: self.reply(503, {"error": "evidence_or_storage_unavailable"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = False
    return server
