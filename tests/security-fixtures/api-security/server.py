#!/usr/bin/env python3
"""Harmless deterministic server for trusted API accountability only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

FIXTURE_TOKEN = "vibesec-local-fixture-token"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/defect":
            self._send({"value": "controlled schema mismatch"})
        elif self.path == "/compliant":
            self._send({"value": "compliant"})
        elif self.path == "/public":
            self._send({"value": "public"})
        elif self.path in {"/private-defect", "/private-compliant"}:
            if self.headers.get("Authorization") != f"Bearer {FIXTURE_TOKEN}":
                self._send({"error": "authentication required"}, status=401)
            elif self.path == "/private-defect":
                self._send({"value": "controlled authenticated schema mismatch"})
            else:
                self._send({"value": "authenticated compliant"})
        else:
            self.send_error(404)

    def _send(self, payload: dict[str, object], status: int = 200) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
