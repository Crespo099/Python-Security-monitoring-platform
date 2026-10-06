# Security and privacy notes

## Trust boundaries

The API treats each authenticated account as its own tenant. Event and alert queries include the authenticated user ID, and acknowledgement verifies ownership. Tokens are short-lived signed JWTs. Passwords use Argon2 through `pwdlib`; raw passwords are never stored.

## Deployment

The production deployment must use a unique secret key and TLS. Restrict the published network path to a reverse proxy or private network. The Compose service binds to loopback, runs as an unprivileged user, drops Linux capabilities, uses a read-only root filesystem, and persists only `/data`. Configure forwarded headers only at a trusted proxy boundary.

## Data handling

The ingestion endpoint removes URL query strings and fragments and rejects non-HTTP(S) URLs. Keep event metadata small and non-sensitive. Source IP and user agent are collected only when supplied by the authorized collector. Choose and document a retention duration; `DELETE /api/events` deletes the signed-in user's events older than `RETENTION_DAYS`. Configure a shorter period where feasible and align collection with applicable notice and consent requirements.

## Known limits

- The included SQLite database is suitable for a single-instance demonstration and small deployment. Use PostgreSQL with backups for production concurrency.
- Registration is public while `ALLOW_REGISTRATION=true`; turn it off after initial provisioning. This starter does not include roles, password reset, MFA, or invite workflows.
- Login throttling is not implemented in-process; use a trusted reverse proxy or identity provider with rate limiting before production exposure.
- The anomaly model is intentionally lightweight and runs per event. It can produce false positives and is not a security verdict.
- Apply schema migrations before making model changes in a persistent production database; the starter creates initial tables but does not bundle Alembic migrations.
