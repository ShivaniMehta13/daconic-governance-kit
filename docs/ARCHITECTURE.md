# Daconic shared architecture, proposed boundaries / implementation v0.3.0

Execution remains in the client runtime. The client supplies complete JSON
observations through direct imports or the observation HTTP endpoint. Observer
validates envelopes, resolves an immutable policy version, evaluates deterministic
predicates and records trace, policy, findings, report and contextual commitments
in the signed ledger. The dashboard reads only privacy-safe projections. The
offline verifier authenticates private bundles; optional replay re-evaluates
supported observations without executing actions.

| Component | Current ownership | Boundary / dependency |
| --- | --- | --- |
| Agent compliance | `observation.py`, policy schema, evaluator, requirements, snapshot/event helpers | Inputs are claims; no framework runtime or network dependency |
| Local Adapter | Existing broker abstraction plus new host trace helpers | Live independent source connectors are prospective |
| Evidence | Local `evidence.py`, keyed field commitments, signed chain/checkpoints/manifest | SQLite/files and cryptography; no central hosted registry |
| Verifier | `verify_bundle`, observation replay, CLI | Trusted key, bundle and optional private payloads; no original deployment access required |
| Dashboard/API | `observation_api.py` and static assets | Shared-token single-client POC; reports only |
| Legacy enforcement | `Broker`, approvals, transaction queue and adapters | Explicit separate API/server; unchanged execution semantics |
| FlexProof | Separate whole-file fingerprinting product as described by owner | No imported package, remote call, format compatibility or merged repository claimed |

Source independence is NOT_ESTABLISHED in this implementation. A future independent
observer needs authenticated source keys and a precisely specified transport /
commitment / receipt protocol. The v0.3 contextual HMAC is computed by the local
host and cannot be presented as such a distributed protocol.

## Implemented versus planned

Implemented: generic action labels, context predicates, PII heuristics, requirements
derived from predicates, canonical-JSON substitution detection, signed evidence,
local replay, observation HTTP service and read-only dashboard.

Demonstrated locally: synthetic direct snapshots and stage events yield identical
assessments; conflict, corruption and missing-data cases; legacy regression suite.

Prospective: Plumbed integration, independent source attestation, actual vendor
runtime adapters, streaming or batching reconciliation, fine-grained identities,
central evidence registry, FlexProof integration and a general policy language.

The first pilot needs Plumbed's policies, representative original and outbound
payloads, expected outcomes, meaning of 'parsed', allowed local processing, and
capture-point definition. No synthetic sample establishes those requirements.

## Invariants

Observation never calls a target or blocks execution. A lack of sufficient evidence
never becomes a passing check. A demonstrated violation survives other unknown
checks. Policy version content cannot change through install. A transaction conflict
cannot append a second observation with changed content. Evidence integrity does
not establish compliant behavior. Authentic signatures do not establish truth.
