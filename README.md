# Secure Web Activity Monitor

A self-hostable Python service for collecting authorized web activity events, detecting suspicious patterns, and reviewing alerts in a small dashboard. It includes account authentication, an ingestion API, SQLite/PostgreSQL support, security rules, optional Isolation Forest scoring, Docker deployment, and privacy controls.

> Use only on systems and accounts you own or are authorized to monitor. Collect the minimum data needed, publish an appropriate notice, and set a retention period before production use. The collector endpoint accepts events; this project does not covertly inspect browser traffic.

## Quick start

Requires Python 3.11+.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1
```

Open <http://127.0.0.1:8000>. Create the first account from the dashboard. Use the API docs at `/docs` for interactive API exploration. Set `SECRET_KEY` in `.env` before exposing the service. Create additional accounts with `python -m app.admin create-user user@example.com "Display Name"` after setting `ALLOW_REGISTRATION=false`.

In VS Code, open **Terminal → Run Task… → Start Secure Web Activity Monitor**. This creates a local virtual environment, installs the listed dependencies, copies `.env.example` to `.env` when needed, and starts the site. The Python extension and debugger launch configuration are included under `.vscode/`.

## Docker

```sh
cp .env.example .env
# Set SECRET_KEY to a long random value in .env
docker compose up --build -d
```

The container listens on port 8000 and stores SQLite data in the `monitor-data` volume by default. Put it behind a TLS-enabled reverse proxy before external access. For a managed PostgreSQL database, add `DATABASE_URL=postgresql+psycopg://user:password@host:5432/monitor` to `.env`; the PostgreSQL driver is included in `requirements.txt`.

## API flow

1. `POST /api/auth/register` with `email`, `password` (12+ characters), and `display_name` to create the first user.
2. `POST /api/auth/login` as form data with `username` (the email) and `password`. Use the returned bearer token in `Authorization: Bearer <token>`.
3. `POST /api/events` with one event or a list of events. Example:

```json
{
  "occurred_at": "2026-10-05T12:00:00Z",
  "event_type": "login_failed",
  "url": "https://example.org/account",
  "domain": "example.org",
  "source_ip": "203.0.113.10",
  "user_agent": "Example collector/1.0",
  "metadata": {"reason": "invalid_credentials"}
}
```

4. Review `GET /api/events`, `GET /api/alerts`, and `GET /api/health`. The dashboard is available at `/` after signing in.

Event fields are bounded and URLs are reduced to their origin/path with query strings and fragments removed. Avoid putting credentials or sensitive personal data in `metadata`.

## Detection

Built-in rules flag bursts of failed logins, visits to locally configurable sensitive path patterns, and rapid activity volume. Thresholds and retention are set through environment variables in `.env.example`. The optional Isolation Forest scores numeric event features once sufficient history exists; it is a triage signal, not a determination of malicious intent. Alerts are deduplicated per rule and event window.

## Production checklist

- Use a unique strong `SECRET_KEY`; keep `.env` out of source control.
- Serve behind HTTPS; restrict network access and configure trusted proxy headers at the proxy.
- Use PostgreSQL and a managed backup strategy for multi-user production deployments.
- Set `ALLOW_REGISTRATION=false` after provisioning accounts; create later accounts through an authenticated administrator workflow or database administration.
- Configure `RETENTION_DAYS`, review alert thresholds, monitor logs, and test restore procedures.
- Keep dependency versions reviewed and updated. The app uses secure password hashing, token expiry, request size limits, and security response headers.

## Project layout

`app/` contains the API, data models, auth, detection, templates, and static dashboard assets. `Dockerfile` and `docker-compose.yml` provide a container deployment. `docs/` describes the API and operational security choices.
