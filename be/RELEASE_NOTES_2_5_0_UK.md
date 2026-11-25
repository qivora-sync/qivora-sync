# QIVORA Sync Backend 2.5.0

- Replaced Resend delivery with Brevo Transactional Email API.
- Kept `/auth/email-otp/request` and `/auth/email-otp/verify` contracts unchanged.
- Added PostgreSQL-backed OTP rate-limit storage.
- Store OTP hash before delivery; remove that OTP if provider send fails.
- No existing user or financial-data tables are dropped or truncated.
- Required Render variables: `BREVO_API_KEY`, `QIVORA_EMAIL_FROM`.
- Deployment and live delivery are NOT verified by archive generation.
