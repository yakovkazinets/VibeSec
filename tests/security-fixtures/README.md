# Scanner accountability fixtures

These fixtures are tiny, synthetic, non-operational, and safe to publish. Files under `positive/` exercise a maintained finding or artifact path; files under `negative/` are nearby safe variants. `expected.json` is trusted repository metadata validated against `config/security-capabilities.json`.

The only secret-shaped marker is `VIBESEC_FAKE_SECRET_DO_NOT_USE_000000000000`. It is deliberately outside every live provider format, is not accepted by any service, and exists only for the local `vibesec-synthetic-secret` test rule. Raw secret values are never copied into normalized or uploaded reports.

Controlled raw scanner documents make advisory and container behavior deterministic. They are untrusted parser inputs, not claims that a live mutable database currently returns the same result. Pinned-tool self-scans separately prove current orchestration completes.
