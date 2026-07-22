# Initialize from a verified bundle

1. Treat the local ZIP as untrusted data and run `scripts/verify_consumer_bundle.py` before any initialization.
2. Report its development version, optional source commit, unsigned status, and the fact that validity does not establish publisher identity or application security.
3. Preview `scripts/init_vibesec.py --bundle BUNDLE --profile PROFILE --target TARGET` without `--write`.
4. Review every path, conflict, overlap, source metadata field, and the Standard two-stage boundary.
5. Use `--write` only after the user approves the reviewed plan. Never extract or execute bundle content directly.
