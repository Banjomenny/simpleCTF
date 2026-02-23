# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Layout

```
bankingai-ctf/
├── README.md
├── .gitignore
├── challenge/        ← Docker-based CTF challenge (what players solve)
│   ├── docker-compose.yaml
│   ├── web/          ← PHP 8.2 Apache container
│   │   ├── Dockerfile
│   │   └── src/      ← Web root (live-mounted into container)
│   ├── db/           ← MySQL 8.0 init scripts
│   │   ├── bankingai.sql       ← Clean MySQL 8.0 schema + seed data
│   │   └── init_flags.sh       ← Injects FLAG_SQL_INJECTION into users table at DB init
│   └── scripts/      ← Manual multi-team bash helpers
└── manager/          ← Flask web app for team registration + instance management
    ├── docker-compose.yaml
    ├── Dockerfile
    ├── app.py
    ├── requirements.txt
    └── templates/
```

## Running the CTF Challenge (challenge/)

```bash
cd challenge

# Start single instance (first run takes ~30s for DB to init)
docker compose up --build -d

# Stop
docker compose down

# Full reset (wipes DB volume)
docker compose down -v && docker compose up --build -d

# Multi-team: each team gets its own containers on a separate port
bash scripts/add_team.sh <name> [port]   # auto-assigns port from 8000 if omitted
bash scripts/remove_team.sh <name>       # tears down + wipes DB volume
bash scripts/list_teams.sh              # show running teams and ports
```

The single-instance default is at **http://localhost** (port 80). Multi-team instances are at the auto-assigned port. The port is controlled by the `PORT` env var in `docker-compose.yaml` (`${PORT:-80}:80`).

## Running the Manager (manager/)

```bash
# 1. Build challenge image first (one-time)
cd challenge && docker compose build

# 2. Edit manager/docker-compose.yaml — fill in:
#    CTF_COMPOSE_FILE  ← HOST path to challenge/docker-compose.yaml
#    HOST_IP           ← LAN IP teams connect to
#    SECRET_KEY        ← random string
#    ADMIN_TOKEN       ← admin panel password

# 3. Start manager
cd manager && docker compose up --build -d
# Browse to http://localhost
```

## Challenge Architecture

The CTF is a PHP employee portal ("BankingAI Cloud") backed by MySQL. Only port 80 is exposed.

**Flag locations and how they are set:**
| Flag env var | Where it appears |
|---|---|
| `FLAG_INSPECTED` | HTML comment in `products.php` (view source) |
| `FLAG_LOGIN` | Shown on `dashboard.php` after login |
| `FLAG_SQL_INJECTION` | Written as a `username` in the `users` DB table by `init_flags.sh` |
| `FLAG_USER_ESCALATION` | Rendered in `admin_subnav.php` nav link |
| `FLAG_FILE_UPLOAD` | Written to `/flag.txt` at container start (via `web/Dockerfile` CMD) |

**Intended exploit chain:**
1. `robots.txt` → `/staff-resources/new-employee-guide.txt` → credentials `ajohnson:Welcome2026`
2. Login → `dashboard.php` shows `FLAG_LOGIN`
3. `lookup.php` SQL injection (unsanitised `WHERE full_name LIKE '%$search%'`) → dump `users` table → get `FLAG_SQL_INJECTION` and admin password hash
4. Login as admin → `admin_subnav.php` shows `FLAG_USER_ESCALATION`
5. `admin_uploads.php` (no file type validation) → upload PHP webshell → execute → read `/flag.txt` = `FLAG_FILE_UPLOAD`
6. `FLAG_INSPECTED` is in the HTML source of `products.php` (can be found at any point)

## Customising Flags

Edit environment variables in `challenge/docker-compose.yaml` then rebuild. The `FLAG_SQL_INJECTION` value is picked up by `db/init_flags.sh` at DB initialisation — no SQL edits needed.

## Key Implementation Notes

- `web/src/` is bind-mounted into the container, so PHP file edits take effect immediately without rebuild.
- `web/src/login.php` uses a prepared statement (intentional — login bypass is via credential discovery, not SQLi).
- `web/src/lookup.php` is intentionally vulnerable to SQL injection (the main exploitation step).
- All admin pages (`admin.php`, `admin_users.php`, `admin_logs.php`, `admin_uploads.php`) must call `session_start()` before the role check — the role check runs before `internal_theme.php` is included.
- `internal_theme.php` guards `session_start()` with `if (session_status() === PHP_SESSION_NONE)` to prevent double-call warnings.
- `db/bankingai.sql` is a clean MySQL 8.0 file (no `@OLD_*` compatibility headers from mysqldump). Do not replace it with a raw mysqldump output from MySQL 5.7.
- Admin passwords: `ewright` = `Welcome1`, `msmith` = `admin123` (both in rockyou.txt; MD5 hashed in SQL).
- The `uploads/` directory is gitignored and world-writable; PHP files placed there execute.

## Manager Implementation Notes

- `manager/app.py` — all routes, bcrypt hashing, SQLite DB, background thread that polls until team's web container is reachable.
- `CTF_COMPOSE_FILE` in `manager/docker-compose.yaml` must be the **host** filesystem path — Docker resolves bind-mount paths relative to the host, not the manager container.
- Status polling hits `http://HOST_IP:PORT` from inside the manager container, so `HOST_IP` must be a LAN IP or hostname reachable from inside Docker (not `127.0.0.1` unless testing locally with host networking).
- `manager/data/manager.db` is gitignored; it is created automatically on first run.
