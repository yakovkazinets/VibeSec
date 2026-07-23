# Controlled active API fixtures

The positive event stream contains exactly three reviewed findings: a controlled server error, a reflected inert SQL marker, and a deterministic path-normalization mismatch. The negative stream is clean. The failure stream represents a bounded request timeout and must become `tool_error`, never a clean result. No fixture contains credentials, operational exploitation, raw request bodies, raw response bodies, external callbacks, or destructive payloads.
