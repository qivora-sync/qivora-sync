# QIVORA Sync 2.1.2 — Neon + Apple Pay

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
