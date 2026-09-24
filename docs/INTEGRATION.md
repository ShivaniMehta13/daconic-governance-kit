# Integration contract

## Trusted host versus agent

The trusted host owns `Governance`, policy installation, approval issuance, adapter credentials and run creation. It assigns the case and agent identity, then exposes only a narrow action wrapper to the agent. `start_run(agent_id, case_id)` returns an opaque handle; callers cannot submit policy documents or run-profile objects to `execute`.

Configured identifiers are not authenticated workload identity. An untrusted caller with access to the complete Broker object can request another identity, issue approvals or inspect memory. Python object encapsulation is not a security boundary. The POC is explicitly cooperative integration.

## Adapter interface

Implement three synchronous, thread-safe methods:

```python
class CustomerAdapter:
    def read(self, case_id: str, record_id: str, tenant: str) -> dict:
        # Authoritative snapshot, never arguments copied from the agent.
        ...

    def apply(self, action: dict, facts: dict, idempotency_key: str) -> dict:
        # Credential-bearing action. Enforce expected record version at the target.
        # Persist/deduplicate idempotency_key atomically with the external effect.
        ...

    def read_after(self, case_id: str, record_id: str, tenant: str) -> dict:
        # Independently supplied post-action snapshot for POC, live read in future.
        ...
```

The read snapshot must include `record_id`, `case_id`, `tenant`, `status`, `observed_at` (Unix seconds) and, for refunds, `amount_minor`, `balance_minor` and a target concurrency/version token. The target must check version/freshness again when applying a write. Broker evaluation alone cannot close a time-of-check/time-of-use race at a remote system.

Amounts are non-negative integer minor units. Currency is fixed by the adapter/domain configuration; cross-currency operations are unsupported. `amount_minor` is the authoritative refund instruction amount, not necessarily the original order total. A proposed amount must equal it and cannot exceed the balance.

`facts_max_age_seconds` determines snapshot freshness. Extract timestamps must reflect provenance, not be refreshed merely to pass validation. Missing/unavailable/stale facts produce `defer`; the adapter must not silently substitute agent-provided values.

`FixtureAdapter` mutates synthetic in-memory records and has in-memory idempotency receipts. It is not restart-durable downstream storage. `ExtractAdapter` reads supplied before/after JSON arrays and simulates execution. A real connector is not included and must not be inferred from a successful fixture test.

## Policies

Policies contain `agent_id`, `version`, `capabilities`, `rules`, `params`, `routes`. See `examples/policies/`. Install by calling `gov.policies.install(document)`, or provide a directory containing `AGENT_ID.json`. Documents are archived by hash in SQLite and embedded in action evidence. Invalid documents fail load. File edits are resolved on the next run; existing run handles retain an immutable serialized policy snapshot.

Rule logic is reviewed Python, not user-supplied expressions. The registry supports read and refund behavior. It evaluates capabilities first, then authoritative scope/reference/amount conditions, hard ceiling before approval, and finally output obligations. All known deny violations are retained. Missing facts defer without dispatch. Invalid supplied approval tokens deny. A valid token cannot override scope, amount integrity or a hard ceiling.

Tenant-specific parameters can narrow platform limits. Rules needed by each action kind cannot be removed. Trusted code may provide platform bounds when constructing PolicyStore; these are not an agent API.

## Approvals

```python
token = gov.broker.issue_approval(
    agent_id="refund-agent", case_id="case-1", transaction_id="tx-123",
    record_id="record-1", max_amount_minor=20000,
    approver_id="identity-provider-subject", approver_type="human",
    expires_seconds=300,
)
```

Only the trusted approval controller may call this. Validate the real approver identity and authorization before issuing. The POC does not implement an identity provider or notification channel. `workflow` is also supported as an explicit approver type. Approval events are durably evidenced and stored token identifiers are SHA-256 digests of random 256-bit tokens.

For direct calls, resubmit the same transaction with the approval token after `step_up`. For queued calls, use trusted `gov.queue.resume(transaction_id, token)`. Ordinary API retries must remain byte-equivalent canonical transactions; changed content returns 409. Resuming changes only the stored execution payload, retaining the original ingress fingerprint for safe producer retries.

Consume approval and write action intent in the same SQLite transaction. If either fails, neither commits. Crash after that commit can leave an approval consumed without a confirmed effect; this is intentional fail-closed behavior requiring reconciliation.

## Outcomes and retries

`execute` returns a dict with `decision`, `evidence_id`, `intent_hash`, and a sanitized `result`. Successful dispatch also provides `outcome_hash`. Refusals are returned as decisions. Storage failures raise `EvidenceUnavailable`; uncertain external effects raise `OutcomeUnknown`.

Operation states: `waiting` for approval; `deferred` for unavailable facts; `attempting` after committed intent; `done` after a terminal refusal or committed success; `unknown` when dispatch may have reached the target.

A duplicate terminal operation returns its stored result, never invokes the adapter again. An `attempting` or `unknown` duplicate raises `OutcomeUnknown`. No automatic reset API exists. Inspect the target and evidence, then make an explicit business recovery decision. Do not simply generate a new transaction ID to bypass this protection.

Queue visibility leasing is independent of action authorization. Lease renewal prevents ordinary long calls from expiring; unique lease tokens fence stale ack/nack operations. If a worker dies, the lease is reaped. Broker operation state then determines whether execution is safe, pending approval, already complete or unknown. Expired leases and ordinary pre-dispatch processing failures retry with capped exponential backoff and eventually dead-letter. Schema-invalid HTTP input never enters this queue.

## Model integration

`record_llm_call` is a dispatch wrapper, not an after-the-fact logging function. Pass complete target metadata and a callback. Classification of the request runs before the callback; PAN/credential findings block the request. Responses are classified before being returned; detected PAN/credential fields are removed. Prompts, responses and target metadata are local blobs committed to evidence.

```python
result = gov.broker.record_llm_call(
    run,
    target={"provider":"configured-provider", "model":"configured-model",
            "model_version":"configured-version", "endpoint":"configured-endpoint",
            "request_id":"provider-or-host-request-id", "generation_parameters":{}},
    request={"messages":[{"role":"user", "content":"Summarize this approved record"}]},
    dispatch=your_model_callback,
)
```

Strict canonical format accepts integer JSON only. Represent fractional configuration as documented decimal strings, not floats. Model provider adapters are responsible for translating configuration types. Capture is voluntary; bypassed traffic is not observed or screened.

## Corroboration

`gov.broker.corroborate(intent_hash)` loads the original pinned facts/policy and compares configured JSON Pointer paths against the post-action extract. Refund expected balance is computed from authoritative pre-action balance minus authoritative amount. The result contains field-level comparisons, policy hash and state hash and is signed as a new event. Repeated checks against unchanged data return the same finding, although evidence event IDs/timestamps differ.

This proves consistency with supplied snapshots, not provenance or causation in a live target. Define snapshot producer, timestamp, record version and correlation as part of Plumbed integration. Delayed visibility produces divergence/unavailable, not proof of fraud. Generic eventual-consistency retry windows are not implemented in the POC.

## Shutdown

Stop HTTP request handling, then workers, then checkpoint and close the shared store. The application context manager does this for its workers/storage. Bounded adapter I/O is mandatory: shutdown raises rather than closes storage under an adapter still running. The queue itself creates no separate connections. One deployment owner uses a process-held lock; a crash releases ownership, while SQLite recovers committed state.
