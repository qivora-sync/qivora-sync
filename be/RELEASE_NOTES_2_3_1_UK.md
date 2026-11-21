# QIVORA Sync Backend 2.3.1

- Replaced wildcard CORS with an exact origin allowlist from QIVORA_WEB_ORIGINS / QIVORA_WEB_ORIGIN.
- Added per-process IP/email rate limits for OTP requests and verification.
- Added basic per-process IP limits for password registration and login.
- Kept financial snapshot sync revision checks unchanged.
- No account-skin synchronization added.
- Note: rate-limit counters are process-local; use shared storage before running multiple backend instances.
- Runtime checks: Node syntax check passed. Live Neon/Render/Resend tests are still required.
