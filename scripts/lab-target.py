import http.server
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("lab: " + (fmt % args) + "\n")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/.git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/search":
            q = ""
            if "?" in self.path:
                from urllib.parse import parse_qs
                q = parse_qs(self.path.split("?", 1)[1]).get("q", [""])[0]
            body = (
                "<html><head><title>Lab search</title></head><body>"
                "<h1>Search</h1><form><input name='q'></form>"
                "<p>results for " + q + "</p></body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<html><head><title>Lab</title></head><body><h1>youkai lab target</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    sys.stderr.write("lab target listening on 127.0.0.1:%d\n" % PORT)
    httpd.serve_forever()
