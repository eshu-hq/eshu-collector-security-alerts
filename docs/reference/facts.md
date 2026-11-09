# Fact kinds

This table mirrors the `emittedFacts` list in [manifest.yaml](../../manifest.yaml). "Mirrors" matters: the manifest is the source of truth, and this page explains it in friendlier words. If you change one, update the other in the same change so they never drift apart.

Every kind below sits at schema `1.0.0` with confidence `reported`, meaning the source said so and Eshu hasn't checked it directly. Every fact carries where it came from: source system, scope, generation, a stable key, a cleaned source address, and a source record ID.

| Fact kind | One fact describes |
| --- | --- |
| `security_alert.repository_alert` | one Dependabot alert on one repository |

Web addresses are cleaned before anything leaves the collector, each fact notes how complete its read was (for example, whether paging or the organization follow-up was cut short), and facts carry a freshness digest so Eshu can spot duplicate work.

All of these kinds belong to Eshu core, so the host refuses them without a producer grant (written permission for this component to publish that kind). Eshu core issues grants. This repository mints none.

For the story behind the table, including a worked example from the test fixtures, see [concepts](../concepts/README.md).
