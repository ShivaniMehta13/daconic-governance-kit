# Release validation: 0.3.0

Date: 16 September 2026. Baseline: locally available Daconic 0.2.0.
Runtime: Linux / Python 3.12. Tests are synthetic; no Plumbed client acceptance or
independent production-source observation is claimed.

| Check | Result |
| --- | --- |
| Python test suite | 103 passed in 2.26 seconds; JUnit in tests-v03.xml |
| Existing broker regression suite | Included and passing |
| Five-scenario observation demo | Expected compliance results |
| Complete demo bundle integrity | PASS |
| Deterministic observation replay | PASS, five observations |
| Corrupt/missing payload and wrong key | Rejected by tests |
| Signed but incorrect assessment | Integrity PASS, replay FAIL as expected |
| Unsupported evaluator implementation | Replay INCOMPLETE |
| Observation-only operation | Broker/network dispatch prohibited in test |
| HTTP authentication, filters, input validation and counts | Passing live localhost tests |
| Dashboard JavaScript syntax | PASS, node --check |
| Dashboard DOM interactions against live API | PASS using jsdom |
| Wheel and sdist build | PASS |
| Installed wheel | Version/imports, dashboard assets and offline replay PASS |
| Docker image build/start | NOT RUN: Docker unavailable |
| Rendered browser visual check | NOT RUN: Chromium download timed out |
| Real client or vendor runtime integration | NOT RUN: client samples/access pending |

The DOM check exercised login, summary counts, compliance filtering, detail drawer,
safe JSON copy, correlated scenarios, live evidence verification, empty search and
refresh. jsdom does not perform browser layout or prove screenshot fidelity. The
script is included at scripts/check_dashboard.cjs and requires optional jsdom plus
a live five-sample observation service with a configured trusted verification key.

No new throughput benchmark was run. Reports under reports/legacy-v02 describe
the older broker and must not be treated as observation service measurements.

Known constraints: one client/state owner, shared API credential, no pagination or
rate limiting, plaintext private storage, heuristic PII classification, canonical
JSON rather than wire-byte equality, and asserted rather than authenticated source
provenance. The shipped examples are synthetic. No novelty/patentability claim.
