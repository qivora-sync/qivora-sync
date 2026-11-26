# QIVORA Backend 2.9.2.6 — тестове розгортання

- Render Root Directory: `be/`.
- Runtime: Node.js 20 або новіший.
- Build Command: `npm install`.
- Start Command: `npm start`.
- Environment Variables: див. `.env.example`; реальні значення задаються лише в Render.
- Потрібна PostgreSQL база даних.
- Перевірити `/health` після запуску.
- Міграції та поведінку на реальній базі перевіряти спочатку на staging із резервною копією.

Повний `npm run test:all` очікує release-структуру, де каталоги `be/` і `fe/` розташовані поруч.
