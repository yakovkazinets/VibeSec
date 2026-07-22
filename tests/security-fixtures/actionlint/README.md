# actionlint fixture

The positive workflow is syntactically invalid by design and never runs. The negative workflow is least privilege and uses an immutable action SHA. `raw.txt` preserves the supported plain-text form; positive and negative `raw.json` files preserve Actionlint 1.7.12's deterministic JSON form. The JSON snippet field is untrusted source context and must never survive normalization. `malformed.json` must fail closed.
