#!/usr/bin/env python3
"""Harmless deterministic server for trusted API accountability only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/defect":
            self._send({"value": "controlled schema mismatch"})
        elif self.path == "/compliant":
            self._send({"value": "compliant"})
        else:
            self.send_error(404)

    def _send(self, payload: dict[str, object]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
