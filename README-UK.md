# QIVORA Sync 2.2.0 — Neon + Apple Pay + Passkeys

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
