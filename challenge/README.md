# BankingAI CTF — Challenge

## The Story

BankingAI Cloud is a fast-growing fintech startup that markets itself as the future of AI-driven banking infrastructure. Behind the polished landing page, a whistleblower has tipped off your team that the company is quietly exfiltrating customer financial data and routing it through shell accounts.

Your job is to get inside their internal employee portal, escalate your access, and prove you were there. The company's security team is confident their platform is locked down. Prove them wrong.

**Get in. Get the flags. Get out.**

---

## Description

A multi-stage web challenge built around a PHP employee portal backed by MySQL. Players work through a chain of vulnerabilities, each rewarding a flag. No CVEs, no guessing — just enumeration, exploitation, and escalation.

The final objective is to read `/flag.txt` from the server — you'll need to find a way to execute code to get there.

- **Difficulty:** Medium
- **Category:** Web
- **Flags:** 5

---

## Running Standalone (single instance)

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) with Compose plugin

### Start

```bash
cd challenge
docker compose up --build -d
```

Available at **http://localhost** once both containers are healthy. The database takes ~30 seconds to initialise on first run.

### Stop

```bash
docker compose down
```

### Reset (wipe DB and start fresh)

```bash
docker compose down -v
docker compose up --build -d
```

---

## Running Multi-Team (with manager)

> **Recommended:** use `setup.sh` at the repo root — it pulls the pre-built image from GHCR, generates secrets, and configures the manager automatically. See the root `README.md`.

For manual control without the manager, scripts are in `scripts/`.

**Add a team** (auto-assigns port from 8000 upward):
```bash
bash scripts/add_team.sh alpha
# or specify a port:
bash scripts/add_team.sh bravo 8001
```

**Remove a team** (stops containers and wipes DB volume):
```bash
bash scripts/remove_team.sh alpha
```

**List running teams:**
```bash
bash scripts/list_teams.sh
```

---

## Flags

| Env var | Location | Points |
|---------|----------|--------|
| `FLAG_INSPECTED` | HTML comment in `products.php` (view source) | 75 |
| `FLAG_LOGIN` | Shown on `dashboard.php` after login | 100 |
| `FLAG_SQL_INJECTION` | Written as a `username` row in the `users` table | 150 |
| `FLAG_USER_ESCALATION` | Rendered in `admin_subnav.php` nav link | 125 |
| `FLAG_FILE_UPLOAD` | Written to `/flag.txt` at container start | 200 |

When deployed via the manager, flag values are generated automatically per team from `FLAG_SECRET` + team name (HMAC-SHA256). When running standalone, the defaults from `docker-compose.yaml` are used.

**Customising flags for standalone testing:**

Edit the environment variables in `docker-compose.yaml` before starting:

```yaml
web:
  environment:
    FLAG_LOGIN:           "CTF{your_flag}"
    FLAG_INSPECTED:       "CTF{your_flag}"
    FLAG_USER_ESCALATION: "CTF{your_flag}"
    FLAG_FILE_UPLOAD:     "CTF{your_flag}"

db:
  environment:
    FLAG_SQL_INJECTION: "CTF{your_flag}"
```

Then restart:
```bash
docker compose down && docker compose up --build -d
```

---

## Author

SWOCTS
