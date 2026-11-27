# Безпека та надійність (бекенд)
- IP клієнта береться з X-Forwarded-For справа (QIVORA_TRUSTED_PROXY_HOPS, за замовчуванням 1): підробка IP більше не обходить ліміти.
- Ліміти OCR, Google, логіну, реєстрації, Apple Pay тепер у PostgreSQL (спільні для інстансів, переживають перезапуск); fallback у пам'ять, якщо база недоступна.
- TLS до бази: QIVORA_DB_CA або QIVORA_DB_SSL_STRICT=1 вмикають перевірку сертифіката. Без них — попередження в логах (щоб не зламати поточний деплой).
- Заголовки безпеки на всіх відповідях API, таймаути запитів, pool.on('error'), statement_timeout 30 с, пул 10 з'єднань (QIVORA_DB_POOL_MAX).
- Коректні 4xx (наприклад body-too-large замість server-error), graceful shutdown (SIGTERM/SIGINT), обробка unhandledRejection.
