-- QIVORA Phase 10: explicit per-user protocol gate for qv_records.
-- Existing users remain on snapshot mode until an explicit, post-migration activation.
CREATE TABLE IF NOT EXISTS qivora_sync_protocol (
  user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
  records_mode TEXT NOT NULL DEFAULT 'snapshot'
    CHECK (records_mode IN ('snapshot','record')),
  activated_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
