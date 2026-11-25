-- QIVORA Phase 5: additive record-level sync schema.
-- Safe to apply repeatedly. Does not drop, truncate, or rewrite legacy snapshot data.
CREATE TABLE IF NOT EXISTS qivora_sync_cursors (
  user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
  last_cursor BIGINT NOT NULL DEFAULT 0 CHECK (last_cursor >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS qivora_sync_records (
  user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
  collection TEXT NOT NULL,
  record_id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version >= 1),
  deleted BOOLEAN NOT NULL DEFAULT FALSE,
  data JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id,collection,record_id),
  CHECK ((deleted = TRUE AND data IS NULL) OR (deleted = FALSE AND data IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS qivora_sync_changes (
  user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
  cursor BIGINT NOT NULL CHECK (cursor >= 1),
  operation_id TEXT NOT NULL,
  collection TEXT NOT NULL,
  record_id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version >= 1),
  deleted BOOLEAN NOT NULL,
  data JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id,cursor),
  CHECK ((deleted = TRUE AND data IS NULL) OR (deleted = FALSE AND data IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS qivora_sync_operations (
  user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL,
  result JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id,operation_id)
);

CREATE INDEX IF NOT EXISTS qivora_sync_changes_created
  ON qivora_sync_changes(user_id,created_at);
CREATE INDEX IF NOT EXISTS qivora_sync_records_updated
  ON qivora_sync_records(user_id,updated_at);

INSERT INTO qivora_sync_cursors(user_id,last_cursor)
SELECT id,0 FROM qivora_users
ON CONFLICT(user_id) DO NOTHING;
