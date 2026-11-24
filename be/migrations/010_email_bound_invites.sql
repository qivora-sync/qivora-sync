-- Email-bound family invitations. Additive migration; legacy invite codes remain intact.
CREATE TABLE IF NOT EXISTS qivora_shared_email_invites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
  created_by UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  accepted_by UUID REFERENCES qivora_users(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (email = lower(trim(email)))
);
CREATE INDEX IF NOT EXISTS qivora_shared_email_invites_owner ON qivora_shared_email_invites(space_id,created_at DESC);
CREATE INDEX IF NOT EXISTS qivora_shared_email_invites_pending ON qivora_shared_email_invites(space_id,email,expires_at) WHERE accepted_at IS NULL AND revoked_at IS NULL;
