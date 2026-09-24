# 0.3.0

- Added standalone Observer and observation HTTP service; no dispatch surface.
- Added bounded generic policies, evidence requirements, explicit coverage outcomes.
- Added local contextual stage commitments and transformed/outbound equality checks.
- Added signed policy/trace assessments and evaluator-source-aware offline replay.
- Added durable observation ID conflicts and policy version pinning.
- Added static local dashboard, counts, filters, scenario comparison and safe JSON.
- Added two host integration styles and five synthetic examples.
- Extended evidence event enum with observation; legacy event construction unchanged.
- Preserved broker command/API behavior. Existing 0.2 verifiers do not recognize
  new observation events; use 0.3 for observation bundles. 0.3 accepts legacy bundles.
- Added Docker observation image/Compose; Docker execution remains unvalidated here.

Unchanged legacy limitations: generic JSON-valid adapter responses still represent
broker success; unknown outcomes have no resolution API; target idempotency/CAS
remain adapter responsibilities. These are not required for passive observation.

Use a fresh observation deployment. Do not share a state directory between two
running processes. Never overwrite keys or discard historical blobs to upgrade.
