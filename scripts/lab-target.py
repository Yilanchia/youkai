"""youkai lab target.

A deliberately small, deliberately vulnerable-by-configuration web app used by the
acceptance script. It exists so the discipline can be tested against a real
server:

  /.git/config        exposed (a read-only probe should find it)
  /search?q=          reflects the parameter (reflection candidate)
  POST /login         sets sid=sess-<username> (single attempt, no retry)
  GET  /orders/1      only alice's cookie may read it -> BOLA/IDOR material
  POST /api/orders    creates one minimal object for the signed-in identity
  GET  /spa           a page that fetches one same-origin XHR and one
                      out-of-scope beacon (the CDP gate must block the beacon)
  GET  /signup        a CAPTCHA page (youkai must stop, not solve it)

Everything is in-memory and per-process: no persistence, no real accounts.
"""
import http.server
import json
import socketserver
import sys
from urllib.parse import parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080

_orders = {}
_next_id = [0]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("lab: " + (fmt % args) + "\n")

    # ---- helpers ---------------------------------------------------------
    def _send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # headers may be a dict or a list of (name, value) pairs; the list form is
        # how a response carries more than one Set-Cookie.
        pairs = headers.items() if isinstance(headers, dict) else (headers or [])
        for k, v in pairs:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    # ---- routes ----------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?")[0]
        query = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}

        if path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n", "text/plain")
            return
        if path == "/sql":
            # Deliberately vulnerable: a quote in q reaches a concatenated query.
            # This is what the whitebox lead about /sql is supposed to find.
            q = query.get("q", [""])[0]
            if "'" in q or '"' in q:
                self._send(500, "You have an error in your SQL syntax; check the manual", "text/plain")
                return
            self._send(200, "results for " + q, "text/plain")
            return

        if path == "/search":
            q = query.get("q", [""])[0]
            self._send(200,
                "<html><head><title>Lab search</title></head><body>"
                "<h1>Search</h1><form><input name='q'></form>"
                "<p>results for " + q + "</p></body></html>")
            return
        if path == "/login":
            self._send(200,
                "<html><head><title>Lab login</title></head><body>"
                "<form method='POST' action='/login'>"
                "<input name='username'><input name='password' type='password'>"
                "<button>sign in</button></form></body></html>")
            return
        if path == "/orders/1":
            # Correctly restricted: only alice may read her object.
            if self._cookie("sid") == "sess-alice":
                self._send(200, "ORD-1 owned by alice", "text/plain")
            else:
                self._send(403, "forbidden", "text/plain")
            return
        if path == "/orders/2":
            # DELIBERATELY BROKEN (IDOR): any signed-in identity can read it, so a
            # two-account comparison has something real to find.
            if self._cookie("sid"):
                self._send(200, "ORD-2 owned by alice", "text/plain")
            else:
                self._send(401, "login first", "text/plain")
            return
        if path == "/api/data":
            self._send(200, '{"ok":true,"items":[1,2,3]}', "application/json")
            return
        if path == "/spa":
            self._send(200, SPA_HTML)
            return
        if path == "/openapi.json":
            self._send(200, OPENAPI, "application/json")
            return
        if path == "/jwt-cookie":
            # Deliberately terrible token: alg=none, no exp, admin claim.
            self._send(200, "<html><title>jwt</title><body>ok</body></html>", headers={
                "Set-Cookie": "jwt=" + WEAK_JWT + "; Path=/",
            })
            return
        if path == "/.well-known/openid-configuration":
            self._send(200, json.dumps({
                "issuer": "http://127.0.0.1:%d" % PORT,
                "authorization_endpoint": "http://127.0.0.1:%d/authorize" % PORT,
                "token_endpoint": "http://127.0.0.1:%d/token" % PORT,
                "response_types_supported": ["code"],
            }), "application/json")
            return
        if path == "/authorize":
            # Lax by design: any redirect_uri is accepted and echoed back.
            q = query.get("redirect_uri", [""])[0]
            self._send(302, "", "text/plain", {"Location": q + "?code=LABCODE"})
            return
        if path == "/graphql":
            # Open introspection: a tiny schema with one query and one mutation.
            self._send(200, json.dumps({"data": {"__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"kind": "OBJECT", "name": "Query", "fields": [{"name": "order", "args": [{"name": "id"}]}]},
                    {"kind": "OBJECT", "name": "Mutation", "fields": [{"name": "deleteOrder", "args": [{"name": "id"}]}]},
                ],
            }}}), "application/json")
            return
        if path == "/signup":
            self._send(200,
                "<html><head><title>Sign up</title></head><body>"
                "<form method='POST' action='/signup'>"
                "<input name='email'><input name='captcha'>"
                "<button>create account</button></form>"
                "<p>please complete the captcha</p></body></html>")
            return
        self._send(200, "<html><head><title>Lab</title></head><body>"
                        "<h1>youkai lab target</h1></body></html>")

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")

        if path == "/login":
            fields = parse_qs(body)
            user = (fields.get("username") or [""])[0]
            if not user:
                self._send(400, "username required", "text/plain")
                return
            # Two cookies: the session the account layer stores, and a deliberately
            # weak JWT so the v0.9 JWT audit has something real to look at.
            # Two cookies: the session the account layer stores, and a deliberately
            # weak JWT so the v0.9 JWT audit has something real to look at.
            self._send(302, "", "text/plain", [
                ("Location", "/"),
                ("Set-Cookie", "sid=sess-" + user + "; Path=/; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "jwt=" + WEAK_JWT + "; Path=/"),
            ])
            return
        if path == "/api/orders":
            if not self._cookie("sid"):
                self._send(401, '{"error":"no session"}', "application/json")
                return
            _next_id[0] += 1
            oid = _next_id[0]
            marker = "ORD-%d" % oid
            _orders[oid] = {"id": oid, "marker": marker, "owner": self._cookie("sid")}
            self._send(200, json.dumps(_orders[oid]), "application/json")
            return
        if path == "/graphql":
            # Open introspection over POST (the usual transport).
            self._send(200, json.dumps({"data": {"__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"kind": "OBJECT", "name": "Query", "fields": [{"name": "order", "args": [{"name": "id"}]}]},
                    {"kind": "OBJECT", "name": "Mutation", "fields": [{"name": "deleteOrder", "args": [{"name": "id"}]}]},
                ],
            }}}), "application/json")
            return
        if path == "/signup":
            self._send(200,
                "<html><head><title>Verify</title></head><body>"
                "<p>Please complete the CAPTCHA to continue</p></body></html>")
            return
        if path == "/chat/completions":
            # A minimal OpenAI-compatible endpoint, so the acceptance script can
            # exercise the LLM "test connection" path without a real model.
            self._send(200, json.dumps({
                "choices": [{"message": {"content": "pong"}}],
            }), "application/json")
            return
        self._send(404, "not found", "text/plain")


SPA_HTML = """<!doctype html>
<html><head><title>SPA lab</title></head><body>
<h1>spa</h1>
<a href="/second">second</a>
<div id="out"></div>
<script>
  fetch('/api/data').then(function(r){ return r.json(); }).then(function(d){
    document.getElementById('out').textContent = JSON.stringify(d);
  });
  // Out-of-scope beacon: the CDP gate must refuse this before DNS.
  fetch('http://out-of-scope.invalid/beacon').catch(function(){});
</script>
</body></html>"""


# A deliberately weak JWT: alg=none, no exp, an admin claim. Base64url, unsigned.
WEAK_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9"
    "."
)

# A tiny OpenAPI 3 document describing the lab's own API. One operation is declared
# against a host outside any sane passport, to exercise the scope check.
OPENAPI = json.dumps({
    "openapi": "3.0.3",
    "info": {"title": "youkai lab api", "version": "1.0"},
    "servers": [{"url": "http://127.0.0.1:%d" % PORT}],
    "paths": {
        "/api/orders/{id}": {"get": {"summary": "read order"}},
        "/spa": {"get": {"summary": "spa page"}},
        "/orders/1": {"get": {"summary": "restricted order"}},
        "/api/orders": {"get": {"summary": "list orders"}, "post": {"summary": "create order"}},
    },
})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", PORT), Handler) as httpd:
        sys.stderr.write("lab target listening on 127.0.0.1:%d\n" % PORT)
        httpd.serve_forever()
