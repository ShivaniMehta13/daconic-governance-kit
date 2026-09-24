# Daconic Governance 0.2.0

Importable Python governance core, optional durable runtime and HTTP ingestion service, independent verifier, and synthetic POC scenario suite. Implements the revised SOW's technical core with explicit integration dependencies. This is not Plumbed acceptance, regulatory certification, or a production security boundary.

## Install and run

Python 3.10+; one runtime dependency (`cryptography`). Tested runtime and measured results are in `reports/`.

```bash
python -m pip install .
python -m pip install '.[test]'
python -m pytest -q
daconic demo --output ./demo-output
daconic verify ./demo-output/private-verification-bundle --public-key ./demo-output/private-verification-bundle/public.key
python examples/integration.py
```

Output directories must be empty. The public key shipped in a bundle is a convenience, not a trust anchor: compare it against a deployment public key authenticated separately before trusting verification.

## Import into an existing agent runtime

```python
from daconic_governance import Governance

# Implement the adapter contract in docs/INTEGRATION.md.
with Governance("/var/lib/daconic", adapter=your_adapter,
                policy_directory="./policies", tenant="poc") as gov:
    run = gov.broker.start_run("refund-agent", "case-1")
    result = gov.broker.execute(
        run, "refund",
        {"record_id": "record-1", "amount_minor": 5000},
        transaction_id="stable-business-operation-id",
    )
    if result["decision"]["effect"] in {"allow", "allow_with_modification"}:
        tool_result = result["result"]
    gov.broker.end_run(run)
```

`aexecute(...)` bridges an async runtime to synchronous adapters using a worker thread. Adapters must implement bounded I/O and must be thread-safe. Cancellation does not undo an action already sent to the target. No LangChain, LangGraph or model-provider dependency is required. Register the narrow wrapper in your agent framework, not the broker or approval controller.

## HTTP POC

Set `DACONIC_API_TOKEN` to a securely generated random secret of at least 32 characters. No default credential is supplied.

```bash
daconic serve --fixture --state ./poc-state --host 127.0.0.1 --port 8080
```

For supplied snapshots:

```bash
daconic serve --before ./before.json --after ./after.json --policies ./policies --state ./poc-state
```

`ExtractAdapter` replays supplied before/after snapshots. It does not perform real enterprise writes. Live connectors and authentic approver integration must be provided by the customer integration, not inferred from these fixtures.

Authenticated endpoints:

- `POST /transactions`: single record (202 accepted; 200 duplicate; 409 changed-content duplicate; 422 invalid).
- Batch input: 207 with a status per record; a rejected record is never queued.
- `GET /transactions/{id}`: local processing state.
- `GET /schema`: exact single and batch request schemas.
- `GET /health`: queue counts, not proof of end-to-end readiness.

The stdlib HTTP server keeps the dependency tree small. It is for isolated POC use, with 1 MiB requests, 100-record batches, socket timeouts, a shared bearer secret and a bounded queue. It does not replace a hardened TLS gateway, per-client quotas or production authentication. Bind to loopback or use customer-controlled authenticated TLS transport. No API endpoint issues approvals or changes policy.

## Evidence and privacy

Every allowed action has durable intent before dispatch and an outcome after. Approval consumption and intent creation occur in the same SQLite transaction. Refusals also produce evidence. SQLite uses WAL and `synchronous=FULL`; blobs and checkpoints use fsync plus atomic replacement. One coordinator process owns each deployment; worker threads share one serialized transaction coordinator. A second coordinator is rejected.

The public record chain is SHA-256 linked and Ed25519 signed. Local payloads are content-addressed and bound to records by a separate Ed25519 signature. Per-field keyed commitments support authorized disclosure with a field-specific key. Checkpoints are chained, signed, range-covering, and stored outside the SQLite file. Workers emit idle heartbeats; embedding without workers requires periodic `gov.ledger.checkpoint()` from the host scheduler.

`export.json` and `public-export.json` are public projections. `evidence.json`, `blobs/`, databases and full verification bundles are private and can contain customer data. Never export the private bundle through the public boundary. Raw model metadata, customer/transaction identifiers and arbitrary JSON keys remain local; actor references and finding paths are HMAC-pseudonymized. This intentionally narrows the earlier prompt's export metadata allowlist.

Verification returns PASS, FAIL, or INCOMPLETE. `--no-blobs` always returns INCOMPLETE (exit 2), not PASS. Missing or modified blobs with payload checks enabled fail (exit 1). Success is exit 0. No service, private signing key, or tenant commitment key is needed by the verifier.

**Trust boundary:** a host administrator with signing-key access can rewrite and re-sign history. Same-host checkpoints do not remove that limitation. Public-key substitution, deletion of the entire deployment, and presenting an older valid bundle require an independently retained key/head/checkpoint to detect. Crypto verifies recorded evidence, not completeness of unobserved activity or truth of an untrusted adapter.

## What is implemented

- Immutable run-pinned policies, archived by content hash; platform bounds and required-rule validation.
- Capability, scope, open-reference, authoritative amount, balance, approval and hard-ceiling checks.
- Five decision effects; exact integer-minor-unit thresholds and combined deny violations.
- Bound single-use approvals including tenant, agent, case, transaction, record, amount, identity/type and expiry.
- Structural response redaction, deterministic classification, both-direction model-call capture.
- Durable action deduplication, conservative unknown-outcome handling, atomic approvals + intents.
- Priority/specificity routing, visible holding, exclusive renewable leases, retries and dead letters.
- Shared-credential ingestion API and single/batch validation.
- Field-level snapshot corroboration, signed agreements/divergences, independent verifier and field disclosure.
- Container recipe, CLI, API schema, demo, tests and paced HTTP load harness.

## Deliberate limitations

- Supported reviewed domain kinds are `read` and `refund`. New action names may bind to these kinds; new business semantics require a reviewed evaluator and adapter update. This is not a general policy language.
- No managed keys, immutable/external anchoring, payload encryption, transport identity, mandatory model-egress proxy, production monitoring or dashboard.
- A Python process cannot isolate agent code from credentials held in the same process. Enforce process/network separation outside this library when non-bypassability is required.
- Pattern detection is heuristic, even with Luhn, IBAN and context checks. It does not guarantee absence of restricted data, including obfuscated data. Customer schema restrictions remain essential.
- Unknown downstream outcomes are held for reconciliation, never automatically replayed. At-least-once delivery does not imply exactly-once external effects.
- CLI/HTTP approvals resume via trusted Python `queue.resume(...)`; actual human/workflow authentication and notifications are integration work.
- Policy edits apply on the next run; pool size changes require worker restart. Existing runs remain pinned.
- Version 0.2 is a breaking API revision; do not point it at the 0.1 prototype database. Preserve the old package separately.
- Benchmark fixture results are not the SOW's customer-hardware/workload acceptance. Container runtime, Windows and Python 3.10 are not claimed tested unless the report says so.

See `docs/INTEGRATION.md`, `docs/SECURITY.md`, `docs/ACCEPTANCE.md` and `reports/`.
