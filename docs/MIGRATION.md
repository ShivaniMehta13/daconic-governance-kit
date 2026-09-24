# Migration from the 0.1 prototype

0.2 is a breaking, separately stored release. Keep the previous archive and its database for reference. Do not open a 0.1 evidence database with 0.2.

| 0.1 concept | 0.2 replacement |
|---|---|
| `EvidenceLedger(path)` generating a new key by default | `Governance(state_directory, adapter)` with persisted keys and process ownership |
| `Action`, `RunContext` passed on every call | Trusted `start_run(agent_id, case_id)` returning opaque pinned handle |
| `execute(action, context, dispatch)` | `execute(run, action_name, arguments, transaction_id, approval_token=None)` with host-owned adapter |
| Generic top-priority predicate rule | Validated fixed domain rule registry, all deny violations, platform bounds |
| `GovernanceRefusal` default exception | Returned five-effect decision; dispatch only on allow/modify |
| Regex-only detector list | Context-sensitive scalar classification plus response schema restrictions |
| `verify_records(records, key)` | `verify_bundle(bundle, key, blob_reader)` and standalone CLI with signed manifest/checkpoints |
| Minimal export filter | Explicit nested public projection plus independent strict guard |

0.1 evidence is not silently upgraded or re-signed. No historic migration is implemented or claimed. Run the 0.2 demo in a new directory, integrate the adapter, define policies, and execute the acceptance suite on the actual customer fixtures.
