# QIVORA Sync 2.3.1 — Neon + Email OTP + Passkeys

## Що є у цій версії
- PostgreSQL sync API: `/auth/register`, `/auth/login`, `/sync/push`, `/sync/pull`.
- Apple Pay bridge: `/applepay/status`, `/applepay/setup` (POST/DELETE), `/applepay/transactions`.
- Реєстрація використовує одну PostgreSQL-транзакцію через `pool.connect()`.
- Ідемпотентність Apple Pay за `eventId`.
- Ключ Apple Pay зберігається у БД лише як SHA-256 хеш.
- `password_salt` додається до наявної `qivora_users` без видалення таблиці.
- Створюються таблиці синхронізації та Apple Pay, якщо їх ще немає.
- CORS дозволяє DELETE для відкликання ключа.

## Render
Поточні налаштування залишити:
- Build Command: `yarn install`
- Start Command: `yarn start`
- Root Directory: порожній

Environment:
- `DATABASE_URL` — новий Neon pooled connection string.
- `QIVORA_JWT_SECRET` — випадковий секрет мінімум 32 символи.
- `PORT` задає Render автоматично.

## Встановлення через GitHub
Замінити в корені репозиторію тільки `server.js` і `package.json` файлами з цього архіву. Не змінювати Render налаштування команд. Оскільки Auto-Deploy увімкнено, commit у `main` автоматично запустить deployment.

## Перевірка
1. `GET https://qivora-sync.onrender.com/health` → `{"ok":true,"database":"connected"}`.
2. Створити новий тестовий акаунт через QIVORA.
3. Перевірити, що `/sync/pull` повертає порожній стан з revision 0.
4. Перевірити створення Apple Pay ключа в налаштуваннях.
5. Не робити реальну оплату, доки не буде перевірено підтримку Wallet automation на конкретному iPhone/iOS.

## Важливо про Apple Pay
Сервер приймає подію від iPhone Shortcuts. Він не читає Apple Wallet напряму і не гарантує, що iOS або банк нададуть автоматизації кожну оплату. Номер картки, CVV, PIN і банківські паролі не передавати.


## QIVORA 2.2 — видалення акаунта та Face ID / Passkeys

Додано API:
- `DELETE /account` — видаляє користувача транзакційно; дочірні дані синхронізації, Apple Pay, passkeys та challenges видаляються через `ON DELETE CASCADE`.
- `POST /webauthn/register/options` і `POST /webauthn/register/verify` — реєстрація платформного passkey з обов’язковою user verification.
- `POST /webauthn/auth/options` і `POST /webauthn/auth/verify` — перевірка Face ID / системної біометрії через WebAuthn.
- `GET /webauthn/status` — стан зареєстрованого passkey.

Додаткові змінні Render:
- `QIVORA_RP_ID=qivora-semolina-8700b2.netlify.app`
- `QIVORA_WEB_ORIGIN=https://qivora-semolina-8700b2.netlify.app`

Якщо буде власний домен, онови обидва значення відповідно. `QIVORA_WEB_ORIGINS` і `QIVORA_RP_IDS` можуть містити список через кому. Не вказуй повний URL у RP ID — це лише hostname.

Потрібен Node.js 20 або новіший. Існуючі таблиці/дані не видаляються під час міграції; нові таблиці створюються через `CREATE TABLE IF NOT EXISTS`.


## Email OTP (QIVORA 0.1.46 / API 2.3.0)

Для надсилання кодів входу задай у Render Environment:
- `RESEND_API_KEY` — API key сервісу Resend.
- `QIVORA_EMAIL_FROM` — підтверджена адреса відправника, наприклад `QIVORA <login@your-domain>` (домен має бути підтверджений у Resend).

Код діє 10 хвилин; повторне надсилання обмежене 1 разом на хвилину; після 5 неправильних спроб код блокується. Нові OTP-акаунти створюються без пароля. Існуючі password-акаунти залишаються сумісними.

Гостьовий режим є локальним і не створює серверного акаунта. Автоматичне об'єднання гостьових даних з уже існуючим акаунтом ще не реалізоване.


## QIVORA Sync 2.3.1 — захист запитів та CORS
- CORS більше не використовує `Access-Control-Allow-Origin: *`; браузерні запити дозволяються лише з `QIVORA_WEB_ORIGINS` / `QIVORA_WEB_ORIGIN`.
- Додано обмеження частоти запитів за IP та email для Email OTP.
- Додано базові обмеження за IP для реєстрації та входу за паролем.
- Ліміти реалізовані в пам'яті одного процесу. Перед горизонтальним масштабуванням потрібно перенести лічильники в спільне сховище.
- Уточнено версію документації відповідно до `package.json`.

Збережи в Render `QIVORA_WEB_ORIGIN` або задай `QIVORA_WEB_ORIGINS` зі списком точних дозволених HTTPS-origin. Не додавай шлях або кінцевий `/`; вказується лише origin, наприклад `https://example.netlify.app`.


## Google Sign-In (2.4.0)

Google login uses Google Identity Services in the browser: the frontend receives a Google ID token (credential) and sends it to `POST /auth/google`. The backend verifies the token signature, issuer, expiry and audience with `google-auth-library`, and requires `email_verified=true`.

Required Render environment variable:
- `GOOGLE_CLIENT_ID` — the Web application OAuth Client ID from Google Cloud.

Frontend request:
```json
{ "credential": "<Google ID token>" }
```
Endpoint response follows the existing QIVORA auth shape:
```json
{ "token": "<QIVORA token>", "userId": "<uuid>", "email": "user@example.com", "provider": "google" }
```

This credential-post flow does not use an OAuth redirect URI, so the Google Cloud OAuth web client can leave "Authorized redirect URIs" empty. Keep the QIVORA Netlify origin in "Authorized JavaScript origins". Do not expose a Google Client Secret in frontend code; this flow does not require one.

Existing accounts with the same verified email are signed into the same QIVORA user record. New Google users receive a QIVORA user record and an empty sync snapshot. This does not merge a separate guest/local snapshot automatically; guest-data migration remains a separate frontend workflow.
