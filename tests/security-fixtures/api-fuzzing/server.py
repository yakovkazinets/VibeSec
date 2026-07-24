#!/usr/bin/env python3
"""Harmless local-only active API fixture; markers remain inert data."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import unquote, urlsplit, parse_qs

FIXTURE_TOKEN = "vibesec-local-fixture-token"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("value", [""])[0]
        if parsed.path == "/boundary" and "VIBESEC_SQL_MARKER" in value:
            self._send({"error": "controlled marker"}, 500)
        elif parsed.path == "/reflect" and "VIBESEC_CMD_MARKER" in value:
            self._send({"value": "VIBESEC_CMD_MARKER"})
        elif parsed.path.startswith("/files/") and "VIBESEC_PATH_MARKER" in unquote(parsed.path):
            self._send({"path": "VIBESEC_PATH_MARKER"})
        elif parsed.path == "/template" and "VIBESEC_TEMPLATE_MARKER" in value:
            self._send({"error": "template error"})
        elif parsed.path == "/headers" and "VIBESEC_HEADER_MARKER" in self.headers.get("X-Fixture-Value", ""):
            self._send({"value": "handled"}, extra_header=("X-Fixture-Echo", "VIBESEC_HEADER_MARKER"))
        elif parsed.path == "/private":
            if self.headers.get("Authorization") != f"Bearer {FIXTURE_TOKEN}":
                self._send({"error": "authentication required"}, 401)
            elif "VIBESEC_SQL_MARKER" in value:
                self._send({"error": "controlled private marker"}, 500)
            else:
                self._send({"value": "authenticated clean"})
        elif parsed.path in {"/boundary", "/reflect", "/template", "/headers", "/compliant"}:
            self._send({"value": "clean"})
        else:
            self.send_error(404)

    def _send(self, payload: dict[str, object], status: int = 200,
              extra_header: tuple[str, str] | None = None) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if extra_header is not None:
            self.send_header(*extra_header)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
