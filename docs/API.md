# API reference

All routes use JSON except the dashboard and static assets. Authentication uses `Authorization: Bearer <access_token>`.

| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/api/health` | Liveness check | No |
| POST | `/api/auth/register` | Create first account (or accounts while allowed) | No |
| POST | `/api/auth/login` | Get access token; form fields `username` (email) and `password` | No |
| GET | `/api/auth/me` | Current account | Yes |
| POST | `/api/events` | Ingest one event or a batch | Yes |
| GET | `/api/events?limit=50&offset=0` | List own events | Yes |
| GET | `/api/alerts?limit=100` | List own alerts | Yes |
| POST | `/api/alerts/{id}/acknowledge` | Acknowledge own alert | Yes |
| GET | `/api/summary` | Seven-day event count and open-alert count | Yes |
| DELETE | `/api/events` | Delete own events and alerts past configured retention | Yes |

Interactive OpenAPI documentation is available at `/docs` outside production mode.
