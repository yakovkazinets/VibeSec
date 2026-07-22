#!/usr/bin/env python3
"""Inert HTTP fixture for the VibeSec passive ZAP baseline."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path not in {"/", "/positive", "/negative", "/health", "/external-link"}:
            self.send_error(404)
            return
        body = b"<html><body>VibeSec passive fixture</body></html>"
        if self.path == "/external-link":
            body = b'<html><body><a href="http://external.invalid/never">isolated link</a></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.path != "/positive":
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


if __name__ == "__main__":
    port = int(os.environ.get("VIBESEC_FIXTURE_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
