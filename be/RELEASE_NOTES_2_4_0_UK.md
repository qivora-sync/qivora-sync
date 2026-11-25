# QIVORA Backend 2.4.0 — Google Sign-In

## Added
- `POST /auth/google` accepts a Google Identity Services ID token (`credential` or `idToken`).
- Backend verifies the ID token with Google's official `google-auth-library`, including audience validation against `GOOGLE_CLIENT_ID`.
- Only verified Google email addresses are accepted.
- Existing QIVORA accounts with the same verified email are reused; otherwise a new user and empty sync snapshot are created.
- Added IP rate limiting for Google sign-in.
- Existing Email OTP, password, Passkey, sync, and Apple Pay routes are retained.

## Configuration
Set `GOOGLE_CLIENT_ID` in Render to the Web OAuth Client ID ending in `.apps.googleusercontent.com`.

The current flow posts the ID token directly to the backend; it does not require a redirect URI or Client Secret. Keep the Netlify URL as the Authorized JavaScript origin. Do not place Client Secret in frontend code.

## Limitations / not yet completed
- Frontend Google button integration is not included in this backend archive.
- No live Render, Google Cloud, database, or iPhone end-to-end test was performed.
- Guest local data migration is not performed by this endpoint.
