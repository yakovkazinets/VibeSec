# Example: no existing security tooling

## Evidence

A Python web repository contains `pyproject.toml`, a lockfile, a Dockerfile, and one GitHub Actions test workflow. No scanner configuration, dependency-update automation, baseline, or suppression records are present.

## Response pattern

Report the detected artifacts and absence of controls without assuming there are none outside repository scope. Propose a minimal profile: Trivy for locked dependencies, Dockerfile/configuration, and secret patterns; Gitleaks for dedicated secret scanning; and actionlint for the existing workflow. Explain overlap between Trivy and Gitleaks and why dedicated secret coverage is retained.

If the user requests Standard, propose Opengrep only for the detected Python source, OSV-Scanner for detected source manifests, and Syft for both SBOM formats. Treat Checkov as `not_applicable` because no supported IaC was detected. Treat image scanning as `not_configured` unless the user supplies an already-built immutable digest on a trusted event. Do not infer Kubernetes or Terraform from a Dockerfile.

Before writing, present workflow permissions, immutable pins, expected runtime, OSV network/privacy behavior, observation-first profile-specific baseline behavior, files to add, and validation. Do not add DAST, build execution, dependency installation, or Docker builds.

End with the full coverage matrix, checked and unchecked scope, tool and parser errors, and residual risk. Say “no existing repository security tooling was detected,” not “the repository has no security controls.”
