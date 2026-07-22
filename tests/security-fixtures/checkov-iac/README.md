# Checkov IaC fixture

The Terraform is inert text and is never initialized, planned, or applied. The positive fixture intentionally triggers `CKV_AWS_24`; the negative fixture restricts the same ingress rule. Target-controlled `.checkov.yml` and `.checkov.yaml` files attempt to skip Terraform, suppress the finding, enable downloads, and inject an API key, but the trusted explicit configuration must make them non-authoritative. Controlled JSON validates normalization, while CI exercises both fixtures with the immutable, network-disabled, read-only container invocation.
