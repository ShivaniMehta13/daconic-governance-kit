# Release validation

Version: 0.2.0. Tests run on Linux x86-64, Python 3.12.13, cryptography 46.0.0.

## Executed

- 83 automated test cases passed. Machine-readable result: `tests.xml`.
- Coverage-instrumented test execution completed; raw coverage is in `coverage.json`. Demo, CLI and benchmark were also executed separately, outside that coverage run. Coverage percentage alone is not acceptance coverage.
- Wheel and source distribution built successfully. Each Python source file in the wheel was compared byte-for-byte with the release source.
- Wheel installed into a separate virtual environment without downloading dependencies; existing runtime cryptography dependency was used.
- Installed CLI demo exercised allow, threshold step-up, approval, hard-ceiling refusal, scope refusal, reference refusal, amount integrity, capability refusal, model request block, model response capture, corroboration agreement/divergence, field disclosure, and tamper detection.
- Installed CLI verified a copied evidence bundle from a separate temporary directory with socket creation and DNS disabled. Valid bundle PASS/exit 0; payload checks omitted INCOMPLETE/exit 2; modified payload FAIL/exit 1.
- Sustained HTTP ingestion benchmark report is included as `benchmark-report.json`; it states actual offered/completed counts, minute windows, evidence-record ratio, queue backlog, sampled corroboration, durability configuration and stage timings.

## Benchmark interpretation

This is a paced synthetic test, not a saturation benchmark and not Plumbed's final acceptance test. Target workload is 50 transactions/second for 180 seconds, with an 80% refund/20% read mix, two agents/four worker threads, small synthetic payloads including restricted fields, and approximately 10% corroboration. Integer rate reporting is rounded; minute windows provide actual completed counts.

The report's stage timings identify measured serialized work. `ledger_append_including_blob_crypto_sql_ms` includes its blob and cryptographic subcomponents; do not add nested timings together. `commitment_sign_insert_ms` includes SQLite insertion overhead. Paced operation below capacity does not establish the maximum-throughput bottleneck. Customer workload sizing still requires saturation profiling and agreed host resources.

## Not executed / not claimed

- Docker daemon unavailable: Dockerfile provided, image build/run not validated.
- Windows and Python 3.10/3.11 not available in this run; compatibility is declared but not platform-tested.
- No Plumbed environment/repository deployment, real enterprise writes, customer approval-provider authentication or notification delivery.
- No customer policy sign-off or review of customer field-classification completeness.
- No HSM/KMS, external timestamping, encryption at rest, mandatory egress enforcement, or production security certification.
- No claim of exactly-once external effects without target-side idempotency and reconciliation.

No deployment database, signing key, tenant commitment key or real customer payload is included in this release archive. Sample public evidence is generated solely from synthetic demo data.
