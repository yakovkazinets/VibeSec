#!/usr/bin/env python3
"""Verify an untrusted VibeSec release artifact directory before extraction."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, SUCCESS, VERIFICATION_FAILED  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.strict_json import canonical_json, loads_strict  # noqa: E402
from vibesec.supply_chain import (  # noqa: E402
    OIDC_ISSUER, WORKFLOW_IDENTITY, SupplyChainError, verification_record,
    verify_release,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--cosign", type=Path)
    parser.add_argument("--certificate-identity", default=WORKFLOW_IDENTITY)
    parser.add_argument("--certificate-oidc-issuer", default=OIDC_ISSUER)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--release-reference")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = verify_release(
            args.directory, require_signature=args.require_signature, cosign=args.cosign,
            certificate_identity=args.certificate_identity,
            certificate_oidc_issuer=args.certificate_oidc_issuer,
        )
        if args.record is not None:
            tools = loads_strict((ROOT / "config/tools.json").read_bytes())
            cosign_version = tools["cosign"]["version"] if result.signature_verified else None
            record = verification_record(
                result, release_reference=args.release_reference,
                verification_tool=f"cosign/{cosign_version}" if cosign_version else None,
            )
            if args.record.exists() or args.record.is_symlink() or not args.record.parent.is_dir():
                raise SupplyChainError("verification record destination must be a new file in an existing directory")
            descriptor = os.open(args.record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_json(record))
                stream.flush()
                os.fsync(stream.fileno())
        emit(envelope("verify_release_artifacts", result.manifest["version"], "valid", result={
            "source_commit": result.manifest["source"]["commit"],
            "artifact_count": len(result.manifest["artifacts"]),
            "checksums_verified": True,
            "signature_verified": result.signature_verified,
            "publisher_identity_verified": result.signature_verified,
        }, information=["Artifact integrity does not establish that software is safe."]), as_json=args.json)
        return SUCCESS
    except SupplyChainError as exc:
        emit(envelope("verify_release_artifacts", "unknown", "invalid", errors=[str(exc)]), as_json=args.json)
        return VERIFICATION_FAILED
    except OSError as exc:
        emit(envelope("verify_release_artifacts", "unknown", "infrastructure_failure", errors=[type(exc).__name__]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
