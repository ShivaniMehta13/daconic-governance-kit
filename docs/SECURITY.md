# Security model and design decisions

## Cryptographic format

Canonical JSON format `v2` supports string-keyed maps, lists, strings, booleans, null and integers. Keys are sorted, whitespace omitted, UTF-8 retained. Floats, non-string map keys, custom objects and implicit `str()` conversion are rejected. This is a documented Python-oriented format, not a claim of RFC 8785 compliance. Money is integer minor units.

Merkle trees follow RFC 6962-style domain separation: SHA-256 of `0x00 || leaf` and SHA-256 of `0x01 || left || right`; split at the greatest power of two strictly smaller than subtree size. Empty roots are SHA-256 of empty bytes. JSON Pointer escaping distinguishes keys containing slashes/tilde; empty containers are committed explicitly.

Each payload gets a random 256-bit salt. For path P:

```
field_key = HMAC-SHA256(tenant_key, "daconic-field-v1\0" || salt || canonical(P))
leaf = HMAC-SHA256(field_key, canonical(P) || "\0" || canonical(value))
root = merkle(ordered leaves)
```

This differs intentionally from the earlier prompt's direct tenant-key leaf HMAC. Independent verification of a revealed value otherwise requires exposing the tenant key or an additional proof system. A disclosure reveals only that payload/path's derived key, value and sibling hashes; it does not expose the tenant key or keys for other fields. The verifier must use a root from previously authenticated evidence, not merely the root supplied with the disclosure. Per-payload salts prevent an authorized disclosure enabling cross-record value guessing with the disclosed field key.

Signatures bind the public record and, separately, the tuple of record hash and local blob hash. This allows offline payload-integrity verification without exporting raw payload digests or private payload locations. Public record roots remain keyed, mitigating low-entropy guessing. Selective disclosure validates the authorized field against the signed root; offline bundle verification does not recompute all keyed roots because it lacks the tenant key. It authenticates the recorded commitments and payload bindings instead.

## Evidence guarantees and limits

- Each chain record carries a contiguous sequence and previous hash. Verification re-derives hashes from content; it never follows an unverified stored hash.
- Checkpoints sign ranges, form their own chain, and cover the complete bundle. Heartbeat checkpoints cover empty ranges. Missing checkpoint ranges, deletion, reorder and root changes fail verification.
- A signed bundle manifest fixes record count, chain head, checkpoint head and export digest. This detects suffix deletion within that bundle. It does not prevent substituting an older complete valid bundle without an independently retained recent checkpoint/head.
- The public key must be authenticated separately. An attacker able to replace the bundle and the alleged public key can create their own internally valid evidence.
- Operator edits without the signing key are detectable. An administrator with key access can rewrite and re-sign history. Same-host checkpoints do not change this boundary.
- The evidence store is tamper-evident, not immutable. Database indexes, approval flags and queue state are not independent authorization trust roots against a compromised host administrator.
- A signed account is not proof that its author observed everything or told the truth. Independent post-action extracts improve corroboration only to the extent their producer is independent and trustworthy.

## Privacy boundary

The only intended outward evidence artifact is the output of `boundary.export_header`. Strict schema validation is independent of construction. It rejects unexpected fields, unknown enums, non-digest identifiers and oversized strings. Raw dynamic JSON paths may contain customer identifiers, so exported paths use keyed pseudonyms. Local findings retain actual structural paths. Arbitrary provider endpoints and model metadata can contain credentials or customer data and are committed locally, not copied to public headers.

The local verification bundle contains sensitive payloads by design. It is an on-premises artifact; never treat it as the public export. Authorized disclosures also reveal data intentionally and need a separate customer disclosure decision. Data classification is deterministic but not complete for every encoding, locale or obfuscation. Structural schema coverage is the primary control.

## Recovery and durability

One process owns a deployment. SQLite transactions serialize action/approval/evidence writes; payload blobs are fsynced before their references commit. A failed transaction may leave an unreferenced blob; no committed ledger record points to an unpersisted blob. There is no automated blob garbage collector in this POC.

Approval consumption and intent commit atomically. Dispatch is external and cannot be made atomic with SQLite. Any crash after intent and before committed outcome is conservatively unknown. Do not automatically redispatch. A production adapter must use target-side idempotency and concurrency preconditions; the in-memory fixture cannot provide these across its own restart.

Hardware/filesystem durability is still bounded by the host's fsync/storage guarantees. Keys and files use restrictive creation modes, but deployments should reside in a directory owned exclusively by the service account. Key management, encrypted backups, immutable archival and erasure are out of scope.

## Exposed surface

The stdlib HTTP service is a POC adapter. Use loopback or a customer-managed private TLS gateway, not direct internet exposure. It has one shared credential, size limits and bounded queue depth, but no production client identity, authorization partitions or rate limiting. Never hand its shared secret to untrusted agents with access to other cases. Run/case assignment and approval issuer authentication belong to trusted host integration.
