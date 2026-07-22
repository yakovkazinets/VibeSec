# Prebuilt-image fixture

No public image is pulled or scanned. Controlled Trivy JSON validates image-result normalization, while integration tests enforce digest-only trusted events, fork disabling, tag rejection, missing-runtime errors, and `not_configured` semantics.
