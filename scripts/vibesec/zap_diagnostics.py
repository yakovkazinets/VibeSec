"""Bounded, sanitized diagnostics for stopped pinned ZAP containers."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

ERROR_CODES = {
    "automation_job_error",
    "target_unreachable",
    "report_generation_failed",
    "report_template_unavailable",
    "filesystem_permission_failed",
    "zap_home_unwritable",
    "java_out_of_memory",
    "java_thread_limit",
    "container_killed",
    "passive_rule_unavailable",
    "unknown_zap_runtime_error",
}
JOB_TYPES = ("spider", "passiveScan-wait", "report", "exitStatus")
MAX_DIAGNOSTIC_CHARS = 512
MAX_LOG_BYTES = 262_144
URL = re.compile(r"\b(?:https?|file)://\S+", re.IGNORECASE)
HOST_PATH = re.compile(r"(?<![A-Za-z0-9_.-])(?:/[A-Za-z0-9._-]+){2,}")
WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\s\\]+\\)+[^\s\\]*")
IDENTIFIER = re.compile(
    r"\b(?:[0-9a-f]{12,}|[0-9a-f]{8}-[0-9a-f-]{27,}|vibesec-[a-z0-9_.-]+|"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)\b",
    re.IGNORECASE,
)
IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
ERROR_LINE = re.compile(
    r"error|failed|failure|exception|fatal|unable|cannot|denied|unreachable|"
    r"outofmemory|killed|thread|template|add-on|addon",
    re.IGNORECASE,
)


def read_private_log_tail(path: Path) -> str:
    """Read at most the bounded tail of one regular, private copied ZAP log."""
    if path.is_symlink() or not path.is_file():
        return ""
    size = path.stat().st_size
    with path.open("rb") as stream:
        if size > MAX_LOG_BYTES:
            stream.seek(size - MAX_LOG_BYTES)
        data = stream.read(MAX_LOG_BYTES)
    return data.decode("utf-8", errors="replace")


def _flags(text: str, state: dict[str, Any]) -> dict[str, bool]:
    lowered = text.casefold()
    state_error = str(state.get("Error", "")).casefold()
    raw_exit = state.get("ExitCode")
    state_exit = raw_exit if isinstance(raw_exit, int) and not isinstance(raw_exit, bool) else None
    return {
        "oom": state.get("OOMKilled") is True or any(marker in lowered for marker in (
            "outofmemoryerror", "java heap space", "gc overhead limit exceeded", "killed process",
        )),
        "thread": any(marker in lowered for marker in (
            "unable to create native thread", "pthread_create failed", "cannot create worker gc thread",
            "resource temporarily unavailable", "failed to start thread",
        )),
        "filesystem": any(marker in lowered for marker in (
            "permission denied", "accessdeniedexception", "read-only file system", "not writable",
        )),
        "home": "unable to create home directory" in lowered or (
            "/zap/vibesec-home" in lowered and any(marker in lowered for marker in (
                "permission denied", "accessdeniedexception", "read-only file system", "not writable",
            ))
        ),
        "target": any(marker in lowered for marker in (
            "target unreachable", "failed to access url", "connection refused", "unknown host",
            "name or service not known", "temporary failure in name resolution", "no route to host",
        )),
        "report": "report" in lowered and any(marker in lowered for marker in (
            "failed", "failure", "unable", "cannot", "exception", "not found", "unavailable",
        )),
        "template": "template" in lowered and any(marker in lowered for marker in (
            "not found", "unavailable", "unknown", "unsupported", "failed", "missing",
        )),
        "addon": any(marker in lowered for marker in (
            "add-on", "addon", "extensionreport", "pscanrules", "passive scan rule",
        )) and any(marker in lowered for marker in (
            "not found", "unavailable", "unknown", "unsupported", "failed", "missing",
        )),
        "killed": state_exit in {137, 143} or "killed" in state_error,
    }


def _job(text: str) -> str:
    for line in reversed(text.splitlines()):
        if ERROR_LINE.search(line):
            for job in JOB_TYPES:
                if job.casefold() in line.casefold():
                    return job
    return "unknown"


def _message(text: str) -> str:
    lines = [line for line in text.splitlines() if ERROR_LINE.search(line)]
    candidate = lines[-1] if lines else "no allowlisted runtime message"
    candidate = URL.sub("<url>", candidate)
    candidate = WINDOWS_PATH.sub("<path>", candidate)
    candidate = HOST_PATH.sub("<path>", candidate)
    candidate = IDENTIFIER.sub("<id>", candidate)
    candidate = IP_ADDRESS.sub("<host>", candidate)
    candidate = CONTROL.sub(" ", candidate)
    candidate = " ".join(candidate.split())
    candidate = re.sub(r"[^A-Za-z0-9 <>._,:;()'\[\]-]", "?", candidate)
    return candidate[:180] or "no allowlisted runtime message"


def classify_zap_runtime(text: str, state: dict[str, Any]) -> dict[str, Any]:
    """Classify untrusted runtime text without interpreting it as instructions."""
    bounded = text[-MAX_LOG_BYTES:]
    state_error = str(state.get("Error", ""))[:8192]
    evidence = bounded + ("\n" + state_error if state_error else "")
    flags = _flags(evidence, state)
    lowered = evidence.casefold()
    job = _job(evidence)
    if flags["oom"]:
        code = "java_out_of_memory"
    elif flags["thread"]:
        code = "java_thread_limit"
    elif flags["home"]:
        code = "zap_home_unwritable"
    elif flags["filesystem"]:
        code = "filesystem_permission_failed"
    elif flags["target"]:
        code = "target_unreachable"
    elif flags["template"]:
        code = "report_template_unavailable"
    elif flags["report"]:
        code = "report_generation_failed"
    elif flags["addon"] and any(marker in lowered for marker in ("pscan", "passive", "rule")):
        code = "passive_rule_unavailable"
    elif flags["killed"]:
        code = "container_killed"
    elif job != "unknown" or "automation framework" in lowered:
        code = "automation_job_error"
    else:
        code = "unknown_zap_runtime_error"
    if code not in ERROR_CODES:  # Defensive guard for future edits.
        code = "unknown_zap_runtime_error"
    return {"code": code, "job": job, "message": _message(evidence), **flags}


def render_zap_runtime_diagnostic(*, case: str, exit_code: int, state: dict[str, Any],
                                  report: Path, runtime_text: str) -> str:
    classified = classify_zap_runtime(runtime_text, state)
    safe_case = case if case in {"positive", "negative"} else "unknown"
    exists = report.is_file() and not report.is_symlink()
    size = report.stat().st_size if exists else 0
    raw_state_exit = state.get("ExitCode")
    state_exit = raw_state_exit if isinstance(raw_state_exit, int) and not isinstance(raw_state_exit, bool) else "unknown"
    fields = (
        f"live ZAP runtime: case={safe_case} exit={exit_code} state_exit={state_exit} "
        f"code={classified['code']} job={classified['job']} "
        f"report_exists={str(exists).lower()} report_bytes={size} "
        f"oom={str(classified['oom']).lower()} thread={str(classified['thread']).lower()} "
        f"filesystem={str(classified['filesystem']).lower()} target={str(classified['target']).lower()} "
        f"report={str(classified['report']).lower()} template={str(classified['template']).lower()} "
        f"addon={str(classified['addon']).lower()} killed={str(classified['killed']).lower()} message="
    )
    remaining = max(0, MAX_DIAGNOSTIC_CHARS - len(fields))
    return (fields + classified["message"][:remaining])[:MAX_DIAGNOSTIC_CHARS]
