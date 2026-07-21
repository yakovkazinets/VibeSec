# Example: no existing security tooling

## Evidence

A Python web repository contains `pyproject.toml`, a lockfile, a Dockerfile, and one GitHub Actions test workflow. No scanner configuration, dependency-update automation, baseline, or suppression records are present.

## Response pattern

Report the detected artifacts and absence of controls without assuming there are none outside repository scope. Propose a minimal profile: Trivy for locked dependencies, Dockerfile/configuration, and secret patterns; Gitleaks for dedicated secret scanning; and actionlint for the existing workflow. Explain overlap between Trivy and Gitleaks and why dedicated secret coverage is retained.

Before writing, present workflow permissions, immutable pins, expected runtime, observation-first baseline behavior, files to add, and validation. Do not add Kubernetes, Terraform, SAST, DAST, or build execution when repository evidence does not justify them.

End with checked, unchecked, tool-error, and residual-risk sections. Say “no existing repository security tooling was detected,” not “the repository has no security controls.”
