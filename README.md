# simpleCTF

A self-hosted Capture the Flag platform. Each team gets their own isolated Docker challenge instance, automatically provisioned through a web registration portal.

Two challenges are available — select one at deploy time via `setup.sh`:

| Challenge | Stack | Flags | Max pts |
|-----------|-------|-------|---------|
| **BankingAI CTF** | PHP + MySQL | 5 | 650 |
| **SWOCTS — Task 1** | Python Flask | 3 | 425 |

```
ctf/
├── setup.sh        ← interactive setup wizard (start here)
├── challenge/      ← BankingAI CTF (PHP + MySQL)
├── task-1/         ← SWOCTS Task 1 (Python Flask)
└── manager/        ← web portal: registration, scoring, admin panel
```

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start — Multi-Team with Manager](#quick-start--multi-team-with-manager)
3. [Option A — Single Instance (no manager)](#option-a--single-instance-no-manager)
4. [How the Manager Works](#how-the-manager-works)
5. [Scoring & First Blood](#scoring--first-blood)
6. [Admin Panel](#admin-panel)
7. [Switching Challenges](#switching-challenges)
8. [Customising Flags](#customising-flags)
9. [Stopping & Resetting](#stopping--resetting)
10. [Troubleshooting](#troubleshooting)
11. [Repository Layout](#repository-layout)

---

## Prerequisites

- **Docker** with the Compose plugin — [install guide](https://docs.docker.com/get-docker/)
  - Docker Desktop includes both on Windows/macOS
  - On Linux: `sudo apt install docker.io docker-compose-plugin`
- **Linux or macOS host** for the manager (it mounts `/var/run/docker.sock`)
- `openssl` in PATH (used by `setup.sh` to generate secrets)
- Git

Verify:
```bash
docker --version          # Docker 24+
docker compose version    # Compose v2+
openssl version
```

---

## Quick Start — Multi-Team with Manager

### 1. Clone the repo

```bash
git clone <repo-url> ctf
cd ctf
```

### 2. Run the setup wizard

```bash
bash setup.sh
```

The wizard will:
1. Ask which CTF to run (BankingAI or SWOCTS Task 1)
2. Ask for the `HOST_IP` players will connect to
3. Generate random `SECRET_KEY`, `ADMIN_TOKEN`, and `FLAG_SECRET`
4. Pull the pre-built challenge image from `ghcr.io` and tag it locally
5. Write `manager/.env` with all settings

> **Finding your HOST_IP:**
> ```bash
> # Linux
> hostname -I | awk '{print $1}'
> # macOS
> ipconfig getifaddr en0
> # Windows (PowerShell)
> (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object -First 1).IPAddress
> ```

### 3. Start the manager

```bash
cd manager
docker compose up -d
```

The manager is now running at **http://HOST_IP** (port 80).

Players visit that URL, register a team name and password, and receive their own challenge instance. Their dashboard shows the instance URL as soon as it is ready (typically 5–30 seconds depending on the challenge).

---

## Option A — Single Instance (no manager)

For solo testing or a single-team run — no manager needed.

**BankingAI CTF:**
```bash
cd challenge
docker compose up --build -d
# Visit http://localhost
# MySQL takes ~30s to initialise on first run
```

**SWOCTS Task 1:**
```bash
cd task-1
docker compose up --build -d
# Visit http://localhost:5000
```

**Stop:**
```bash
docker compose down
```

**Full reset** (wipe DB/volumes and start fresh):
```bash
docker compose down -v && docker compose up --build -d
```

---

## How the Manager Works

When a team registers:

1. Manager creates a DB entry and assigns the next free port (starting from `PORT_RANGE_START`, default 8000)
2. Calls `docker compose up -d` via the Docker socket, injecting per-team flag values as environment variables
3. Team dashboard shows **Starting…** and auto-refreshes every 5 seconds
4. Manager polls the Docker socket until the web container is `running`
5. Status flips to **Ready** — the dashboard shows a clickable link: `http://HOST_IP:PORT`

**Per-team flags:** Every team's flag values are unique, derived from `FLAG_SECRET` + team name via HMAC-SHA256. Players cannot share answers between instances. Flags survive Stop/Restart — they are deterministic and always the same for a given team name + secret.

```
CTF{<slug>_<8-char hmac>}

# Example for team "alpha":
CTF{source_3a7f9c21}
CTF{ssh_creds_b4d82f10}
CTF{bash_history_cc482b6f}
```

To compute a team's flag value manually (e.g. for an answer sheet):
```bash
python3 -c "
import hmac, hashlib
secret  = 'your-FLAG_SECRET'
team    = 'teamname'
flag_id = 'FLAG_SOURCE'
slug    = flag_id.replace('FLAG_', '').lower()
token   = hmac.new(secret.encode(), f'{flag_id}:{team}'.encode(), hashlib.sha256).hexdigest()[:8]
print(f'CTF{{{slug}_{token}}}')
"
```

---

## Scoring & First Blood

The **first team** to capture a flag earns a 1.2× bonus. Subsequent captures earn the base point value (positions 2–3), dropping by 1 pt per position from 4th onward (floor: 1 pt).

**BankingAI CTF:**

| Flag | Base pts | First Blood |
|------|----------|-------------|
| Inspect the Source | 75 | 90 |
| Initial Access | 100 | 120 |
| SQL Injection | 150 | 180 |
| User Escalation | 125 | 150 |
| File Upload RCE | 200 | 240 |
| **Total** | **650** | **780** |

**SWOCTS — Task 1:**

| Flag | Base pts | First Blood |
|------|----------|-------------|
| Source Code | 75 | 90 |
| SSH Credentials | 150 | 180 |
| Bash History | 200 | 240 |
| **Total** | **425** | **510** |

Hints are available at a point cost (unlocked sequentially per flag). The admin panel can enable/disable hints globally. Purchasing hints deducts points from the team's score.

The scoreboard includes a **score-over-time graph** showing each team's cumulative score. Timestamps use the timezone configured by `TZ_NAME` in `manager/.env` (default: `America/New_York`).

---

## Admin Panel

Browse to **http://HOST_IP/admin** and enter your `ADMIN_TOKEN`.

The admin panel shows every registered team with their port, status, score, and flag captures. Actions per team:

- **Stop** — runs `docker compose down -v` (destroys containers + volumes)
- **Restart** — runs `docker compose up -d` and begins polling again
- **Reset PW** — sets a new password for the team
- **Delete** — removes the team from the DB and destroys their containers

> Stop wipes any DB volumes. On Restart the containers are re-initialised with the **same flag values** — flags are deterministic.

---

## Switching Challenges

To change the active challenge, re-run `setup.sh` and choose the other option, then restart the manager:

```bash
bash setup.sh
cd manager && docker compose down && docker compose up -d
```

Or edit `manager/.env` directly — see `manager/.env.example` for all variables. The key ones:

```ini
# BankingAI CTF
CTF_COMPOSE_HOST_PATH=../challenge/docker-compose.yaml
CTF_CHALLENGE_DIR=/absolute/path/to/ctf/challenge
CTF_CONFIG_FILE=/ctf/config/bankingai.json
CTF_NAME=BankingAI CTF
STARTUP_TIMEOUT=180

# SWOCTS Task 1
CTF_COMPOSE_HOST_PATH=../task-1/docker-compose.yml
CTF_CHALLENGE_DIR=/absolute/path/to/ctf/task-1
CTF_CONFIG_FILE=/ctf/config/task1.json
CTF_NAME=SWOCTS — Task 1
STARTUP_TIMEOUT=30
```

Restart the manager after any `.env` change.

> **Note:** Switching challenges does not wipe the manager's team database. Existing team registrations remain. If you want a clean slate, wipe `manager/data/` before restarting.

---

## Customising Flags

Flag names, point values, and hints are defined in JSON files in `manager/config/`:

- `manager/config/bankingai.json` — BankingAI flags + hints
- `manager/config/task1.json` — SWOCTS Task 1 flags + hints

Edit the JSON and restart the manager container to pick up changes. Per-team flag *values* are always derived from `FLAG_SECRET` + team name regardless of config — the JSON controls what flags exist and how they're scored.

To change the flag format entirely, change `FLAG_SECRET` in `manager/.env` and restart everything (including all running team instances from the admin panel).

---

## Stopping & Resetting

**Stop the manager** (team instances keep running):
```bash
cd manager && docker compose down
```

**Stop the manager and wipe all manager data** (team registrations, scores):
```bash
cd manager && docker compose down -v
rm -rf manager/data/
```

**Stop a single team's instance manually:**
```bash
docker compose -p ctf_<teamname> -f challenge/docker-compose.yaml down -v
```

**Stop all team instances at once:**
```bash
docker ps --filter name=ctf_ -q | xargs -r docker stop
docker ps -a --filter name=ctf_ -q | xargs -r docker rm
docker volume ls --filter name=ctf_ -q | xargs -r docker volume rm
```

**Full reset** (wipe all state, pull latest code + image, restart manager):
```bash
bash reset.sh
```

`reset.sh` is the go-to command between test runs when changes have been pushed to GitHub. It:
1. Removes all team containers, volumes, and stale networks
2. Wipes `manager/data/` (registrations + scores)
3. Runs `git pull` to get the latest code
4. Pulls the active challenge image from GHCR and retags it locally (reads `CTF_CONFIG_FILE` from `manager/.env` to determine which image)
5. Rebuilds and restarts the manager container

Prompts for confirmation before doing anything.

---

## Troubleshooting

**Challenge page won't load (BankingAI)**

MySQL takes ~30 seconds to initialise on first run. Wait and refresh. To watch:
```bash
docker compose -p ctf_<teamname> -f challenge/docker-compose.yaml logs db --follow
# Wait for: "ready for connections"
```

**Team stuck on "starting" indefinitely**

Check containers are actually running:
```bash
docker ps | grep ctf_<teamname>
```

If containers are missing, check manager logs:
```bash
docker logs ctf_manager
```

Common causes:
- `CTF_CHALLENGE_DIR` in `manager/.env` is wrong or not set
- Challenge image was never pulled/built (re-run `setup.sh`)
- Docker socket permissions

**"Image not found" when a team registers**

The challenge image must exist locally. Run `setup.sh` to pull it from GHCR, or build it manually:
```bash
# BankingAI
cd challenge && docker compose build

# Task 1
docker pull ghcr.io/banjomenny/simplectf/task1-web:latest
docker tag ghcr.io/banjomenny/simplectf/task1-web:latest task-1-web:latest
```

**Teams can't reach their instance URL**

- `HOST_IP` in `manager/.env` is probably `127.0.0.1` — change it to your LAN IP
- Check firewall allows inbound TCP on your port range: `sudo ufw allow 8000:8100/tcp`

**View logs for a specific team's container:**
```bash
docker compose -p ctf_<teamname> -f challenge/docker-compose.yaml logs web
```

---

## Repository Layout

```
ctf/
├── setup.sh                        ← interactive setup wizard
├── .gitignore
│
├── challenge/                      ← BankingAI CTF (PHP + MySQL, 5 flags)
│   ├── docker-compose.yaml
│   ├── web/
│   │   ├── Dockerfile
│   │   └── src/                    ← PHP web root (bind-mounted; live edits)
│   ├── db/
│   │   ├── bankingai.sql           ← MySQL schema + seed data
│   │   └── init_flags.sh           ← injects FLAG_SQL_INJECTION at DB init
│   └── scripts/                    ← manual multi-team bash helpers
│
├── task-1/                         ← SWOCTS Task 1 (Python Flask, 3 flags)
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── app.py
│   ├── generate_artifacts.py       ← builds static/files.zip (run before build)
│   ├── requirements.txt
│   ├── static/
│   └── templates/
│
├── manager/                        ← team management web app
│   ├── docker-compose.yaml
│   ├── .env.example                ← copy to .env and fill in values
│   ├── Dockerfile
│   ├── app.py                      ← Flask: all routes, Docker helpers, scoring
│   ├── requirements.txt
│   ├── config/
│   │   ├── bankingai.json          ← BankingAI flags + hints config
│   │   └── task1.json              ← SWOCTS Task 1 flags + hints config
│   └── templates/
│       ├── base.html
│       ├── index.html              ← register / login
│       ├── dashboard.html          ← instance URL, flag grid, score
│       ├── hints.html              ← sequential hints (purchasable)
│       ├── scoreboard.html         ← public ranked scoreboard + time graph
│       ├── admin.html              ← team management table
│       └── admin_login.html
│
└── .github/
    └── workflows/
        ├── publish-bankingai.yml   ← auto-publishes bankingai-web:latest to GHCR
        └── publish-task1.yml       ← auto-publishes task1-web:latest to GHCR
```

---

*For authorised testing and CTF events only.*
