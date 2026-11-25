# QIVORA Backend 2.9.2.3 — Apple Pay workspace routing candidate

## Added
- Apple Pay setup accepts an explicit workspace target (`scopeType: "workspace"`, `workspaceId`, `accountId`).
- Setup verifies that the authenticated user is an active member of the specified shared space and that the account exists in the workspace `qv_accounts` collection.
- Apple Pay transaction handling re-checks active membership and account existence before writing the expense to the workspace `qv_records` collection.
- Workspace operation IDs are deterministic per user and Apple Pay event, so retries are idempotent at the workspace record store.
- Personal Apple Pay flow remains on the existing personal snapshot/record-sync path.

## Important limitations
- This is a backend-only candidate. The current frontend Apple Pay screen still creates personal-scope connections and does not yet expose workspace account selection.
- The shared workspace account must already exist in `qv_accounts`; automatic family-account provisioning and the full family account UI/runtime are separate unfinished work.
- The workspace record write and Apple Pay event marker are idempotent but are committed in separate database transactions. A retry can complete the event marker if a failure occurs after the workspace write; this is not a single cross-store atomic transaction.
- No live PostgreSQL, Render deployment, or two-device end-to-end test was performed.

## Verification
- `node --check server.js`
- `npm run test:all` — passed, including 10 Apple Pay workspace-routing contract assertions.

Do not deploy until frontend workspace selection/runtime and live PostgreSQL end-to-end tests are complete.
