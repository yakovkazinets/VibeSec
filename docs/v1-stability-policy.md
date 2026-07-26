# VibeSec Guardian v1 stability and deprecation policy

The machine-readable source of truth is [`machine/interfaces.json`](../machine/interfaces.json) plus the domain catalogs under [`machine/`](../machine/). Human tables are generated from those files. A prose statement cannot silently override a machine status.

## Status meanings

- `stable`: validated and documented behavior that cannot change incompatibly during v1.x. Additive optional fields require explicit schema handling.
- `experimental`: a named preview whose availability or shape can change with release notes. It must not be presented as a supported stable API.
- `conditionally_enforced`: validated behavior whose coverage requires an explicit eligible target, trusted event, platform, or other documented precondition.
- `deprecated`: still accepted for a documented migration period and linked to migration guidance.
- `internal`: implementation detail that is not a supported public API.

Unknown fields remain rejected wherever strictness is part of the documented contract. A breaking change to a stable interface requires a new major version. Security fixes may make validation stricter when accepting the former input would cross a documented trust boundary.

## Coverage state contract

- `ran`: the named scanner completed its declared scope and produced structurally valid evidence.
- `not_applicable`: the declared scope was evaluated and is provably irrelevant to the target.
- `not_configured`: an explicit opt-in input or eligible target was not supplied. It is not equivalent to `ran`.
- `tool_error`: the scanner, runtime, parser, sanitizer, publication step, or required cleanup failed. It is never a clean result.

Missing and unknown states fail closed. A `ran` state says only that the declared check completed; it does not claim the application is secure.

## Exit-code contract

Profile scanners use `0` for a completed scan without policy violation, `1` for policy violation, `2` for scanner or runtime failure, and `3` for invalid configuration or malformed input.

Distribution and lifecycle commands use `0` for success, `1` for actionable warnings, `2` for verification failure, `3` for invalid input, and `4` for infrastructure failure. Individual command help identifies the applicable contract. Parser, serialization, scanner, policy, and infrastructure outcomes remain distinct.

The one required GitHub status context is exactly `validate`. New required offline jobs join `validate.needs`; they do not replace or rename the aggregate.

## Deprecation

A stable CLI command, ID, schema field, artifact, profile, scanner identity, adapter, task pack, or workflow template must be marked `deprecated` before incompatible removal. The deprecation must identify a replacement, migration steps, and the last supported major line. No current v1 interface is deprecated.
