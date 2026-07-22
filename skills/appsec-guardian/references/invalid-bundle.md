# Invalid bundle rejection

Stop when bundle verification reports any format, path, collision, size, mode, manifest, catalog, version, or hash error. Do not extract, import, execute, partially trust, or initialize from the ZIP. Report the verifier error as an adoption/verification failure, not a security finding or a clean result.

Obtain a new bundle through the expected channel. Development bundles are unsigned, so internal validity alone does not authenticate a publisher. Preserve suspicious input only when local policy permits and never upload it without authorization.
