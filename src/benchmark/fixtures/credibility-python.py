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
        if family in ("sql-boolean", "sql-union", "nosql", "crlf", "template", "traversal"):
            query = parse_qs(parsed.query).get("q", ["fixture"])[0]
            if family == "sql-boolean":
                return self.reply(200, {"matches": [] if vulnerable and "1'='2" in query else ["fixture"]})
            if family == "sql-union":
                match = re.search(r"UNION SELECT '([^']+)'", query, re.I)
                return self.reply(200, {"matches": [match.group(1)] if vulnerable and match else []})
            if family == "nosql":
                try:
                    operator = isinstance(json.loads(query).get("$ne"), str)
                except (ValueError, AttributeError):
                    operator = False
                return self.reply(200, {"matches": ["CORPUS_PRIVATE_DOCUMENT"] if vulnerable and operator else []})
            if family == "crlf":
                match = re.search(r"\r\nX-RouteCairn-Proof: ([A-Za-z0-9_]+)", query)
                return self.reply_headers(200, {"accepted": True}, {"x-routecairn-proof": match.group(1)} if vulnerable and match else {})
            if family == "template":
                if not vulnerable and "{{" in query:
                    return self.reply(422, {"error": "literal_only", "example": query if near else ""})
                return self.reply(200, {"rendered": query.replace("{{7*7}}", "49") if vulnerable else query})
            if family == "traversal":
                if not vulnerable and "../" in query:
                    return self.reply(422, {"error": "path_rejected", "example": "../documentation.txt" if near else ""})
                return self.reply(200, {"content": "CORPUS_PRIVATE_FILE" if vulnerable and "../" in query else "public file"})
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
        if length > 65536:
            raise ValueError("fixture request too large")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        content_type = self.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                return json.loads(raw)
            except Exception:
                return {}
        return {key: values[0] for key, values in parse_qs(raw).items()}

    def reply(self, status, value):
        return self.reply_headers(status, value, {})

    def reply_headers(self, status, value, headers):
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(payload)))
        for name, value in headers.items():
            self.send_header(name, value)
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

class WsgiHandler(Handler):
    def __init__(self, environ):
        self.path = environ["PATH_INFO"] + "?" + environ.get("QUERY_STRING", "")
        self.command = environ["REQUEST_METHOD"]
        self.rfile = environ["wsgi.input"]
        self.headers = {"content-length": environ.get("CONTENT_LENGTH", "0"), "content-type": environ.get("CONTENT_TYPE", "")}
        self.status = 500
        self.response_headers = []
        self.payload = b""

    def reply_headers(self, status, value, headers):
        self.status = status
        self.payload = json.dumps(value, separators=(",", ":")).encode()
        self.response_headers = [("Content-Type", "application/json"), ("Content-Length", str(len(self.payload))), ("Cache-Control", "no-store")] + list(headers.items())

    def redirect(self, location, status=302):
        self.status = status
        self.payload = b""
        self.response_headers = [("Location", location), ("Content-Length", "0")]

    def empty(self, status):
        self.status = status
        self.payload = b""
        self.response_headers = [("Content-Length", "0")]

if "--wsgi" in sys.argv:
    from wsgiref.simple_server import make_server, WSGIRequestHandler
    from http import HTTPStatus

    class QuietRequestHandler(WSGIRequestHandler):
        def log_message(self, *_args):
            pass

    def application(environ, start_response):
        handler = WsgiHandler(environ)
        try:
            handler.route()
        except (ValueError, KeyError):
            handler.reply(400, {"error": "invalid_request"})
        start_response(str(handler.status) + " " + HTTPStatus(handler.status).phrase, handler.response_headers)
        return [handler.payload]

    server = make_server("127.0.0.1", 0, application, handler_class=QuietRequestHandler)
else:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({"port": server.server_address[1]}), flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
