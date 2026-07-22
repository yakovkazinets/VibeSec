# Finding intelligence

VibeSec Standard and the opt-in DAST/API runners emit `finding-groups.json` and `prioritized-findings.json` in addition to their core sanitized artifacts. The original scanner finding and version-1 fingerprint remain authoritative for baselines and suppressions. Correlation is a separate versioned view; it never deletes an original finding or silently migrates fingerprints. Runtime runners publish structurally valid empty intelligence views for clean, not-configured, not-applicable, and tool-error states that contain no findings.

Every source finding retains its scanner, rule ID, source profile and artifact, original normalized severity, confidence, file or route identity, authentication context, and scanner fingerprint. Every finding belongs to exactly one group. Findings without sufficient reviewed evidence form explained singleton groups.

Reviewed offline correlation rules are:

- `scanner-exact`: identical scanner fingerprints only when rule, category, family, sink, code location, route, authentication, and dependency identity evidence all agree. Source profile and artifact may differ so repeated observations can group. A missing-versus-present or conflicting reviewed identity field is treated as a possible fingerprint collision and remains separate with explicit provenance;
- `code-location`: the same repository-relative file, overlapping or adjacent lines, compatible reviewed vulnerability family, and compatible sink;
- `dependency`: the same ecosystem, package, installed version, and advisory;
- `runtime-route`: the same sanitized method and path template, compatible family, and compatible authentication context.

A generic CWE alone is never sufficient. Unknown scanners and malformed CWE identifiers fail closed. Unknown families, missing locations, and ambiguous relationships remain separate. Applied and singleton decisions include machine-readable provenance. Correlation does not prove that findings are identical, exploitable, or reachable.

Priority is separate from scanner severity. The base tier is normalized severity. Independent scanners, confirmed runtime observations, statically proven reachable sinks, and offline known-exploited metadata can raise it through fixed transitions. Authentication-only exposure, dependency directness, baseline state, suppression state, and confidence are explicit reasons. Missing evidence is never inferred.

Optional group policy is disabled by default in `policy/severity-thresholds.yml`. Maintainers can explicitly enable minimum priority, independent-scanner count, or confirmed-runtime requirements. Legacy policy remains the default and tool errors always block.

The layer is deterministic, bounded, local, and performs no source upload, prose interpretation, online threat-data lookup, AI severity generation, or probabilistic scoring. Group keys can change when membership changes; scanner fingerprints remain stable for baseline compatibility.
