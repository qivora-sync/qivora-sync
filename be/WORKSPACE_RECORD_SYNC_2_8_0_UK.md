# QIVORA Workspace Record Sync — Phase 2.8 candidate

## Scope
- Dedicated workspace-scoped tables; personal `qivora_sync_*` tables remain unchanged.
- Every read/write checks active workspace membership.
- Writes use optimistic per-record versions, atomic batches, idempotency keys and tombstones.
- One shared cursor per workspace.
- Records preserve `created_by` and `updated_by`; change log records actor.
- PostgreSQL NOTIFY emits `workspaceId` as a wake-up signal; clients authenticate and pull changes.

## Not production-ready
- Server routes and SSE fan-out are not yet wired to this module.
- Existing personal data needs an explicit reviewed copy/merge flow.
- Role permissions and collection allowlists need final decisions.
- PostgreSQL integration, multi-device, Apple Pay, and frontend tests remain outstanding.
- Do not deploy or activate this migration in production.
