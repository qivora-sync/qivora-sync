# QIVORA Backend 2.8.3 — Guarded workspace import

- Added `POST /workspace/import/commit` for owner-only copying of personal data into the active shared workspace.
- The commit recomputes the preview in a PostgreSQL `REPEATABLE READ` transaction and requires the exact `planHash` from the latest preview.
- Import is refused if the plan changed or the preview contains conflicts/warnings.
- Only new, non-conflicting records are copied; identical duplicates are skipped.
- Source personal rows and snapshots are preserved. Each imported record retains the original creator; the owner is recorded as the actor/editor who initiated the import.
- Imported records create workspace change-log entries, idempotency-operation records, advance the workspace cursor, and emit `pg_notify`.
- No production deployment or production data migration is performed by this candidate.

## Validation and limitations

- JavaScript syntax checks and repository test scripts are run for this candidate.
- Contract tests are static checks, not PostgreSQL integration tests. A staging database test and a reviewed backup are required before deployment.
- Import covers `qv_records`, `qv_accounts`, `qv_transfers`, `qv_recurring`, `qv_goals`, `qv_budgets`, and `qv_category_budgets` only.
