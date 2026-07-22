# Conditionally enforced image scanning

`standard.trivy-image` is conditionally enforced. It may run only for an explicitly supplied immutable digest on a trusted event. A fork, pull request, unknown event, tag-only reference, Dockerfile alone, or unavailable private registry authority must not become `ran`; report `not_configured` or `not_applicable` with the matrix rationale. Never build the Dockerfile or add credentials to obtain coverage.
