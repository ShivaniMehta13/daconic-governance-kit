# Revised SOW acceptance traceability

Status below is synthetic implementation evidence, not customer sign-off. Automated tests exercise the implementation. Plumbed policies, signed-off domain interpretation, representative traces, field maps, approval identity source, before/after extracts and reference environment have not been supplied.

| SOW criterion | Implementation / test evidence | Remaining customer acceptance |
|---|---|---|
| 1 permitted action and policy identity | Broker intent includes policy document/hash, bundle, verdict; threshold tests | Signed-off customer policy |
| 2 ungranted capability refusal | `test_rules[capability]`, demo | Agent inventory |
| 3 autonomous threshold without approval | `test_thresholds`, demo step-up | Threshold values |
| 4 valid approval executes and consumes | `test_approval_bound_consumed_and_idempotent` | Authenticated approver integration |
| 5 bound approval cannot authorize another record | `test_invalid_approvals`, replay test | Approval model |
| 6 approval cannot override ceiling | `test_invalid_approvals[ceiling]` | Ceiling values |
| 7 scope refusal | `test_rules[scope]` | Trusted case assignment |
| 8 no policy, no run | `test_policy_validation_and_pinning` | None for core |
| 9 reject widening platform bounds | policy validation test | Platform bounds |
| 10 different agent capabilities | reader/refund tests and demo | Two agent profiles |
| 11 block restricted model request | model request test + demo | Schema and provider adapter |
| 12 detect personal data | category tests | Customer payload/classification coverage |
| 13 model identity and correlated request/response commitments | model capture test; complete target blob | Genuine provider metadata |
| 14 untampered evidence passes | verifier tests and demo | Customer evidence set |
| 15 verdict alteration detected | tampering tests | None for core |
| 16 payload alteration detected | tampering payload test | None for core |
| 17 record deletion detected | deletion/suffix tests | None for core |
| 18 fabricated record detected | insertion/signature tests | None for core |
| 19 field disclosure and forged value rejection | keyed disclosure tests and demo | Authorized disclosure procedure |
| 20 public export excludes content and customer IDs | public projection tests, dynamic-key test | Field coverage review |
| 21 unknown export field rejected | egress guard test | None for core |
| 22 offline verifier | standalone CLI using copied bundle and separate public key | Authenticated key distribution |
| 23 concurrent intact chain | multi-agent worker and duplicate-call tests | Customer load validation |
| 24 runtime-invalid records dead-letter; duplicates don't repeat | queue corruption and dedup tests | Recovery ownership |
| 25 single API ingestion | API tests and load harness | Customer deployment |
| 26 batch ingestion | batch tests and load harness | Customer batch mix |
| 27 schema failure rejected pre-queue | API test checks queue counts | Published schema review |
| 28 partial batch success | per-record 207 API test | Integration handling |
| 29 duplicate accepted request succeeds without new action | API duplicate + broker dedup tests | Target-side idempotency for actual connector |
| 30 agreement signed | corroboration tests, demo | Independently produced post-state |
| 31 absent affected state divergence | missing-field corroboration tests | Real absent-effect trace |
| 32 wrong value divergence | corroboration test and demo | Real divergent trace |
| 33 reproducible reconciliation | repeat finding equality test | Snapshot provenance/version |
| 34 sustained rate + integrity | `reports/benchmark-report.json` | Agreed hardware/workload/duration; not accepted by fixture result |
| 35 measured report, records/transaction, limiting component | load report records measured rate and ratio | Saturation profiling needed to establish actual bottleneck |
| 36 corroboration under load | sampled corroboration in load harness | Agreed subset and read-back behavior |

## SOW deliverables not fulfilled by a generated package alone

D1 policy sign-off, D3 customer classification map, D4 deployment in Plumbed's environment, D7 placement into Plumbed's repository, D9 customer extract results, D10 customer reference-hardware acceptance and D11 a recorded customer walkthrough require customer inputs/access. The package supplies code, synthetic tests, schemas, run instructions and an executable walkthrough, not those external completion claims.

## Clarifications implemented

- API schema failures are rejected before queueing. Processing-time failures can dead-letter. These are distinct cases.
- Shared bearer authentication is included; production-grade authentication is not.
- `step_up` and `defer` prevent dispatch; they are not represented as successful execution.
- Complete offline payload verification includes blob files. Omission is INCOMPLETE, never PASS.
- Approval/intent atomicity is local; external side effects are not assumed transactional with SQLite.
- Disclosures use derived field keys to support offline proof without releasing the tenant key.
- Public metadata is narrower than the original prompt to prevent identifiers leaking through JSON keys or endpoint text.
- The package implements read/refund domain primitives; new domain rule logic is explicit development, not a claim of automatic policy translation.
