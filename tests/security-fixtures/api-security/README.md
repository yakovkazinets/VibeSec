# API security accountability fixture

`openapi.yaml` defines two harmless `GET` operations. The controlled server returns a string where `/defect` documents an integer, producing exactly `response_schema_conformance`; `/compliant` conforms. The checked-in NDJSON models the pinned Schemathesis 4.24.2 structured event format. Raw bodies and headers are deliberate canaries and must never reach normalized artifacts.
