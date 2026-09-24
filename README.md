# Daconic Governance 0.3.0

Importable Python governance library and local observation dashboard. This release
adds generic **observe-and-report** evaluation to the existing v0.2 broker.
It never executes or blocks the original action through the observation surface.
Existing `Governance` and `Broker` APIs remain separate.

## Quick start

Python 3.10+ is required; this release was tested on Python 3.12. Install from source
in a virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install '.[test]'
python examples/observation_demo.py --state ./demo-state --bundle ./demo-proof
```

The demo creates five synthetic observations: prohibited PII, cleaned content,
missing outbound evidence, a non-applicable action and a substituted payload.
Nothing is sent to a model or external enterprise system. Outputs include safe
reports; private traces reside in the local deployment and private proof bundle.

Independently verify and replay the demo (this key bootstrap is suitable only for
the local demo; obtain the key through a separately authenticated channel in use):

```sh
daconic verify ./demo-proof --public-key ./demo-proof/public.key
daconic verify ./demo-proof --public-key ./demo-proof/public.key --replay-observations
```

Start the read-only results dashboard and observation API:

```sh
export DACONIC_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
daconic observe-serve --state ./demo-state \
  --policies ./examples/observation_policies \
  --trusted-key ./demo-proof/public.key
```

Open http://127.0.0.1:8080 and enter the token. It is held only in page memory.
The browser receives no original payloads, identifiers, source names or free-form
policy values. Displayed identifier/version references are keyed pseudonyms;
use the private bundle to recover exact policy text and versions. No credentials
are preconfigured or included in this release.

## Python integration

```python
import json
from daconic_governance import Observer

policy = json.load(open("examples/observation_policies/pii.json"))
trace = json.load(open("examples/observation_traces/clean.json"))
with Observer("./client-state", [policy]) as governance:
    prospective = governance.check(trace)  # Pure evaluation, no authorization token.
    result = governance.observe(trace)     # Persists signed evidence, no dispatch.
    print(result["compliance"], result["evidence_id"])
```

`check` requires the same complete observation schema; it does not authorize a
later request or guarantee that an inspected payload is the one ultimately sent.
Use one owning Observer process per state directory. Do not open the same state
from a second CLI/process while the server owns it. Close the service before
offline exports, or invoke `observer.ledger.bundle(empty_directory)` inside the
owning trusted process. Export remains a privileged Python operation, not HTTP.

## HTTP interface

All API requests require `Authorization: Bearer <token>`. Static dashboard assets
contain no deployment data and can load before authentication.

| Method and path | Behavior |
| --- | --- |
| POST `/observations` | Validate, evaluate and persist one observation; return safe report |
| GET `/results` | Safe reports, counts and total; optional compliance/scenario/agent_id/severity/q filters |
| GET `/policies` | Pseudonymized policy references, check kinds and evidence requirements |
| GET `/health` | Service liveness only |
| POST `/verify` with `{}` | Verify a snapshot with the server-configured trusted public key |

```sh
curl -sS http://127.0.0.1:8080/observations \
  -H "Authorization: Bearer $DACONIC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/observation_traces/clean.json
```

Identical submissions return the same evidence record, including after restart.
Changed content under the same interaction ID returns 409. Use a new ID for a
different observation, and a common correlation ID to group scenarios. A retry
must preserve timestamps and the entire original envelope. Policy ID/version pairs
are immutable through the installation API; use a new version for changed policy.
Unknown policy versions return 422 instead of guessing. This is a single-client
deployment: use separate state and credentials for different clients.

HTTP returns 200 on accepted or duplicate observation, 401 for bad credentials,
409 for conflict or missing verifier trust configuration, 422 for invalid schema,
413 for over 1 MiB, 415 for non-JSON, and 503 for storage/evidence errors.
One Content-Length is required; chunked bodies and duplicate JSON keys are rejected.
A post-commit error can occur; retry the identical envelope, not a newly dated copy.

## Trace and policy contract

See `examples/observation_traces` and `examples/observation_policies`. Trace schema
version is `"1"`. Context records principal, delegated user, resource and destination;
null means unavailable. These are asserted facts, not authenticated identities.
An optional `transformation` object records the configured transformation `id`
and `version`. These are committed metadata, not proof that this code ran. The
relationship to input is recorded; only transformed/outbound equality is evaluated.
The `input`, `transformed` and `outbound` stages declare present, masked or unavailable,
a claimed source, observation timestamp and `canonical-json-v1` representation.
Unavailable stages omit `payload`; present/masked stages include it, even if null.
Masked observations cannot establish absence of sensitive data in the original.

| Predicate | Semantics |
| --- | --- |
| required | Selected field must exist and be non-null in a complete stage |
| forbidden | Selected field must be absent, including null-valued fields |
| no_categories | No configured detector categories in selected value |
| equals | Exact canonical JSON equality with configured value |
| in | Membership in a configured list using canonical equality |
| matches_transformed | Complete outbound JSON must equal complete transformed JSON |

Predicates use exact JSON Pointers, not globs; action names are exact configured
identifiers. No arbitrary code, eval, model judgment or permissive fallback is used.
Checks declare minimum evidence requirements. VIOLATION takes precedence over
UNKNOWN checks, which remain visible. With no violations, missing evidence gives
INSUFFICIENT_EVIDENCE; otherwise COMPLIANT. An unmatched action is NOT_APPLICABLE.
An empty JSON object is an available value; absence of the entire payload is not.

The detector covers email and international-style phone patterns, selected
credential patterns/fields, Luhn-valid payment cards and IBAN patterns, and selected
infrastructure values. It does not prove absence of names, addresses, all identifiers,
obfuscated/base64 content, images or every locale. Select a suitable detector for
client policy before claiming broader PII compliance. Policies can require explicit
structured fields independently of these heuristics. The example is synthetic and
is not a Plumbed policy or production compliance determination.

## Transformation and outbound binding

Within each signed observation, HMAC commitments bind each present stage to the
interaction, policy hash and destination. Equal transformed/outbound JSON values
produce equal commitments in that context; reuse in a different context does not.
This is additional local linkage, not a remote attestation protocol. The existing
salted field commitments and signed private-payload bindings protect the whole
observation. Raw payload hashes are not exposed through dashboard reports.

Comparison covers canonical JSON values, **not exact HTTP wire bytes**. Key order
and whitespace may differ. Streaming, batching, independent observer key exchange,
hardware attestation and receipt ingestion are not implemented. No arbitrary
caller-supplied signed receipt is accepted. Host capture must occur at the actual
client egress boundary; a submitted label saying `outbound` does not prove capture.

Two host integration helpers are included: structured snapshots and a correlated
stage-event assembler accepting complete snapshots in any arrival order. They are
tested equivalent, but are not two vendor-framework integrations. Missing events
stay unavailable and duplicate or cross-interaction stage events are rejected.

## Evidence, replay and trust

Compliance and integrity are independent. The dashboard starts at NOT_RUN and can
display PASS only for a verified snapshot matching its latest results head. Refresh
invalidates that display status. The immutable report's original integrity field
remains NOT_RUN: it describes issuance, not a later verification operation.
The `/verify` operation verifies locally with an explicitly configured trust key;
it is not an independent third-party observer. An external party can run the same
offline verifier using its independently authenticated key.

Full bundles contain sensitive local material. Normal dashboard/API reports omit
payloads entirely, even if a detector would miss sensitive information. Do not send
private bundles outside the customer's allowed boundary. Existing selective field
disclosure is a privileged operation using an authenticated commitment root.

Observation replay checks authenticated trace + policy against the archived
assessment with matching evaluator/detector implementation hashes. Source truth,
capture completeness and independent observation are not established by replay.
Different evaluator source produces INCOMPLETE, not silent reinterpretation.
Legacy broker events are integrity-checked but not replayed by this feature.

An administrator with signing-key access can fabricate evidence. An older complete
valid bundle can be substituted without an independently retained recent head.
Same-host checkpoints do not solve that. Keys and local payloads are not encrypted
by this POC. Use a private TLS gateway for remote access; the stdlib service has
shared authentication, no production identity partitions, rate limit or pagination.

## Docker

```sh
export DACONIC_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

The observation image runs as UID 10001 and uses a persistent named volume. Supply
your reviewed policies in the mounted policy directory. The sample policy is a
demonstration only. The dashboard initially has no records. Submit JSON samples
using curl. To enable dashboard verification, mount an independently authenticated
raw Ed25519 public-key file read-only and append `--trusted-key /path/to/key` to
the container command. Never treat a caller-uploaded key as the trust anchor.

`Dockerfile` remains the legacy broker image; `Dockerfile.observation` and Compose
select the new service. Docker was unavailable in the build environment; image
build/start must be verified on the deployment host. Python and HTTP tests do not
substitute for Docker validation.

## Development and release records

Run `python -m pytest -q`. See `reports/VALIDATION_v03.md`, `docs/ARCHITECTURE.md`,
`docs/CHANGELOG_v03.md` and `docs/LEGACY_README_v02.md`. Other legacy documents
describe broker v0.2; this README takes precedence for observation setup.
No patentability or novelty claim is made by this release.

## Plumbed payload examples

See [examples/plumbed/README.md](examples/plumbed/README.md) for four proposed policy profiles, sanitized paired payloads, an offline result matrix, and known detector limitations. Run `python examples/plumbed/demo.py` after installation. These examples do not establish actual LLM transmission.
