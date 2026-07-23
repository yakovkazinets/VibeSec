#!/usr/bin/env python3
"""Trusted, bounded in-container launcher for reviewed inert injection markers."""

from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
import socket
import sys
from urllib.parse import quote, urlencode, urlsplit

MAX_PLAN_BYTES = 262_144
MAX_REGISTRY_BYTES = 32_768


def load(path: Path, maximum: int):
    data = path.read_bytes()
    if not 1 <= len(data) <= maximum:
        raise ValueError("bounded input is empty or oversized")
    return json.loads(data)


def emit(stream, event):
    stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--response-limit", type=int, required=True)
    parser.add_argument("--request-limit", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--safe-methods-only", choices=("true", "false"), required=True)
    parser.add_argument("--authenticated", choices=("true", "false"), required=True)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 5 or not 1 <= args.response_limit <= 262_144 or not 1 <= args.request_limit <= 65_536:
        return 3
    parsed = urlsplit(args.url)
    if parsed.scheme != "http" or parsed.hostname != "api-target" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return 3
    token = None
    if args.authenticated == "true":
        token = sys.stdin.readline(16_385).rstrip("\n")
        if not token or len(token.encode()) > 16_384 or any(ord(char) < 32 or ord(char) == 127 for char in token) or sys.stdin.read(1):
            return 3
    try:
        plan = load(args.plan, MAX_PLAN_BYTES)
        registry = load(args.registry, MAX_REGISTRY_BYTES)
        if plan.get("schema_version") != 1 or registry.get("schema_version") != 1 or registry.get("profile") != "safe-v1":
            return 3
        safe = {"GET", "HEAD", "OPTIONS"}
        operations = plan.get("operations")
        families = registry.get("families")
        if not isinstance(operations, list) or len(operations) > 200 or not isinstance(families, list) or len(families) != 5:
            return 3
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as output:
            for operation in operations:
                method = operation["method"]
                if args.safe_methods_only == "true" and method not in safe:
                    continue
                for family in families:
                    for location in family["locations"]:
                        candidates = ([item for item in operation["parameters"] if item["location"] == location]
                                      if location != "body" else [{"name": name, "location": "body"} for name in operation["body_fields"]])
                        for candidate in candidates[:8]:
                            path = operation["path_template"]
                            query = {}
                            headers = {"Accept": "application/json", "User-Agent": "VibeSec-active-api/1"}
                            if token is not None:
                                headers["Authorization"] = "Bearer " + token
                            body = None
                            marker = family["marker_id"]
                            payload = family["payload"]
                            if location == "path":
                                path = path.replace("{" + candidate["name"] + "}", quote(payload, safe=""))
                            elif location == "query":
                                query[candidate["name"]] = payload
                            elif location == "header":
                                if candidate["name"].casefold() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
                                    continue
                                headers[candidate["name"]] = payload
                            else:
                                body = json.dumps({candidate["name"]: payload}, separators=(",", ":")).encode()
                                if len(body) > args.request_limit:
                                    continue
                                headers["Content-Type"] = "application/json"
                            target_path = parsed.path.rstrip("/") + path
                            if query:
                                target_path += "?" + urlencode(query)
                            status = None
                            response_data = b""
                            response_headers = []
                            reason = None
                            check = None
                            pattern = None
                            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=args.timeout)
                            try:
                                connection.request(method, target_path, body=body, headers=headers)
                                response = connection.getresponse()
                                status = response.status
                                response_data = response.read(args.response_limit + 1)
                                if len(response_data) > args.response_limit:
                                    response_data = response_data[:args.response_limit]
                                response_headers = [value for name, value in response.getheaders() if name.casefold() != "set-cookie"]
                                if status >= 500:
                                    reason, check = "controlled_5xx", "not_a_server_error"
                                elif marker.encode() in response_data or any(marker in value for value in response_headers):
                                    reason, check = "reflected_marker", "reflected_marker"
                                else:
                                    lowered = response_data.lower()
                                    patterns = ((b"sql syntax", "database-error-shape"), (b"command not found", "process-error-shape"),
                                                (b"template error", "template-error-shape"), (b"path traversal", "path-error-shape"))
                                    for needle, pattern_id in patterns:
                                        if needle in lowered:
                                            reason, check, pattern = "framework_error_pattern", "framework_error_pattern", pattern_id
                                            break
                            except socket.timeout:
                                reason, check = "request_timeout", "request_timeout"
                            except (ConnectionError, http.client.HTTPException, OSError):
                                reason, check = "unexpected_connection_closure", "unexpected_connection_closure"
                            finally:
                                connection.close()
                            if reason is not None:
                                emit(output, {
                                    "event": "finding", "operation_id": operation["operation_id"], "method": method,
                                    "path_template": operation["path_template"], "parameter_location": location,
                                    "payload_family_id": family["family_id"], "payload_marker_id": marker,
                                    "detection_reason": reason, "response_status": status, "scanner_check_id": check,
                                    "framework_pattern_id": pattern, "authenticated_context": token is not None,
                                    "replay_seed": args.seed,
                                })
            emit(output, {"event": "summary", "completed": True, "mode": "injection", "operation_count": len(operations)})
        return 0
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
        return 3
    finally:
        token = None


if __name__ == "__main__":
    raise SystemExit(main())
