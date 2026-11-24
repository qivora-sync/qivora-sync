# QIVORA Backend 2.9.0 — email-bound family invitations

## Зміни
- Additive migration `010_email_bound_invites.sql` creates email-bound invitation storage.
- Owner-only endpoint creates a random 256-bit token, stores only SHA-256 hash and sends invitation through Brevo.
- Invite is bound to normalized target email, expires after 24 hours and is single-use.
- Authenticated accept endpoint compares token account email with invitation email before membership insertion.
- Owner can list and revoke pending invitations.
- Undeliverable invitation is revoked; no valid token is returned to client.
- Existing code-based invitation endpoints remain for backward compatibility.

## API
- `POST /shared-access/invites` `{email}`
- `GET /shared-access/invites`
- `POST /shared-access/invites/revoke` `{inviteId}`
- `POST /shared-access/invites/accept` `{token}`

## Configuration
- Existing `BREVO_API_KEY` and `QIVORA_EMAIL_FROM` required for delivery.
- Optional `QIVORA_APP_URL`; default `https://qivora-semolina-8700b2.netlify.app`.

## Verification
- `npm run test:all` passes, including 18 email-invite assertions.
- JavaScript syntax checks pass.
- No live PostgreSQL integration, Brevo delivery test, or production deployment performed.
