#!/usr/bin/env python3
"""Process-owned Python HTTP fixture for RouteCairn's public credibility corpus."""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STATE = {}

class Handler(BaseHTTPRequestHandler):
    server_version = "RouteCairnPythonFixture/1"

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def do_DELETE(self):
        self.route()

    def route(self):
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if parsed.path == "/healthz":
            return self.reply(200, {"status": "ready"})
        if len(parts) < 3:
            return self.reply(404, {"error": "not_found"})
        family, control, variant = parts[0], parts[1], parts[2]
        try:
            variant_index = int(variant.lstrip("v"))
        except ValueError:
            variant_index = 0
        vulnerable = control == "vulnerable"
        near = control == "near-miss"
        if family == "object":
            if vulnerable:
                value = {"id": "tenant-a-object", "tenantId": "tenant-a", "record": {"dialect": variant_index}} if variant_index % 2 else {"id": "tenant-a-object", "tenantId": "tenant-a", "variant": variant}
                return self.reply(200, value)
            if near:
                value = {"kind": "public-help", "record": {"id": "documentation-example"}} if variant_index % 2 else {"kind": "public-help", "variant": variant}
                return self.reply(200, value)
            return self.reply([401, 403, 404][variant_index % 3], {"error": "resource_hidden" if variant_index % 2 else "forbidden"})
        if family == "admin":
            if vulnerable:
                value = {"privileged": True, "result": {"dialect": variant_index}} if variant_index % 2 else {"privileged": True, "variant": variant}
                return self.reply(200, value)
            if near:
                value = {"kind": "public-capability-description", "capability": {"privileged": False}} if variant_index % 2 else {"kind": "public-capability-description", "variant": variant}
                return self.reply(200, value)
            return self.reply([401, 403, 404][variant_index % 3], {"error": "capability_hidden" if variant_index % 2 else "forbidden"})
        if family == "search":
            query = parsed.query.lower()
            if vulnerable and ("%27" in query or "'" in query or "%22" in query):
                dialects = ["SQL syntax error near corpus canary", "PostgreSQL error: unterminated quoted string", "MySQL warning: invalid query", "ORA-00933 corpus fixture", "SQLSTATE[42000] corpus fixture"]
                return self.reply([400, 422, 500][variant_index % 3], {"error": dialects[variant_index % len(dialects)]})
            return self.reply(200, {"matches": [], "variant": variant})
        if family == "redirect":
            destination = parse_qs(parsed.query).get("next", ["/home"])[0]
            if vulnerable:
                return self.redirect(destination, [301, 302, 307, 308][variant_index % 4])
            if near:
                return self.redirect("https://routecairn.invalid.example/safe/%s" % variant_index, [301, 302, 307, 308][variant_index % 4])
            return self.redirect("/home?variant=%s" % variant_index, [301, 302, 307, 308][variant_index % 4])
        if family == "auth" and len(parts) >= 4 and parts[3] == "login" and self.command == "POST":
            values = self.form()
            known = values.get("username") == "known@benchmark.test"
            if vulnerable and not known:
                return self.reply(404, {"error": "account_not_found", "recovery": True})
            status = 404 if near else 401
            return self.reply(status, {"error": "invalid_credentials"})
        if family == "auth" and len(parts) >= 4 and parts[3] == "cleanup" and self.command == "POST":
            return self.empty(204)
        if family == "second-order" and len(parts) >= 4:
            operation = parts[3]
            key = control + ":" + variant
            if operation == "stage" and self.command == "POST":
                STATE[key] = self.form().get("payload", "")
                return self.reply(202, {"accepted": True})
            if operation == "render" and self.command == "GET":
                unsafe = vulnerable and bool(STATE.get(key))
                return self.reply(200, {"safe": not unsafe, "rendered": "stored-value" if unsafe else "encoded-value"})
            if operation == "cleanup" and self.command == "DELETE":
                STATE.pop(key, None)
                return self.empty(204)
        return self.reply(404, {"error": "not_found"})

    def form(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        content_type = self.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                return json.loads(raw)
            except Exception:
                return {}
        return {key: values[0] for key, values in parse_qs(raw).items()}

    def reply(self, status, value):
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("location", location)
        self.send_header("content-length", "0")
        self.end_headers()

    def empty(self, status):
        self.send_response(status)
        self.send_header("content-length", "0")
        self.end_headers()

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({"port": server.server_address[1]}), flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
