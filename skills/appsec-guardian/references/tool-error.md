# Tool error

Treat a missing executable, timeout, non-zero execution failure, malformed/truncated/oversized output, wrong schema, or stale result as scanner infrastructure failure. Report the capability ID and safe error class, set coverage to `tool_error`, keep it distinct from findings and policy violations, remove stale output, and refuse a clean claim.
