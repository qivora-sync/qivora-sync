-- QIVORA workspace record sync. Additive and isolated from personal sync tables.
-- Existing personal snapshots and qivora_sync_* rows are not changed.
CREATE TABLE IF NOT EXISTS qivora_workspace_sync_cursors (
  space_id UUID PRIMARY KEY REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
  last_cursor BIGINT NOT NULL DEFAULT 0 CHECK(last_cursor >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS qivora_workspace_sync_records (
  space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
  collection TEXT NOT NULL, record_id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK(version >= 1),
  deleted BOOLEAN NOT NULL DEFAULT FALSE, data JSONB,
  created_by UUID NOT NULL REFERENCES qivora_users(id),
  updated_by UUID NOT NULL REFERENCES qivora_users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(space_id,collection,record_id),
  CHECK((deleted=TRUE AND data IS NULL) OR (deleted=FALSE AND data IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS qivora_workspace_sync_changes (
  space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
  cursor BIGINT NOT NULL CHECK(cursor >= 1), operation_id TEXT NOT NULL,
  collection TEXT NOT NULL, record_id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK(version >= 1), deleted BOOLEAN NOT NULL, data JSONB,
  actor_id UUID NOT NULL REFERENCES qivora_users(id),
  created_by UUID NOT NULL REFERENCES qivora_users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(space_id,cursor),
  CHECK((deleted=TRUE AND data IS NULL) OR (deleted=FALSE AND data IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS qivora_workspace_sync_operations (
  space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
  operation_id TEXT NOT NULL, result JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(space_id,operation_id)
);
CREATE INDEX IF NOT EXISTS qivora_workspace_sync_changes_created ON qivora_workspace_sync_changes(space_id,created_at);
CREATE INDEX IF NOT EXISTS qivora_workspace_sync_records_updated ON qivora_workspace_sync_records(space_id,updated_at);
