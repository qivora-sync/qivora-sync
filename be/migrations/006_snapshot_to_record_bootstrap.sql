-- QIVORA Phase 8: one-time, revision-guarded qv_records bootstrap.
-- Additive only; does not alter legacy snapshot data or enable record sync.
CREATE TABLE IF NOT EXISTS qivora_sync_migrations (
  user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
  migration_key TEXT NOT NULL,
  migration_id UUID NOT NULL,
  snapshot_revision BIGINT NOT NULL CHECK (snapshot_revision >= 0),
  record_count INTEGER NOT NULL DEFAULT 0 CHECK (record_count >= 0),
  cursor_start BIGINT NOT NULL DEFAULT 0 CHECK (cursor_start >= 0),
  cursor_end BIGINT NOT NULL DEFAULT 0 CHECK (cursor_end >= 0),
  baseline_records JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id,migration_key),
  UNIQUE(user_id,migration_id)
);
