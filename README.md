# BankingAI CTF

A self-hosted Capture the Flag platform. Players solve a multi-stage PHP web challenge — each team gets their own isolated Docker instance, automatically provisioned through a web registration portal.

```
bankingai-ctf/
├── challenge/   ← the CTF challenge players solve (PHP + MySQL)
└── manager/     ← web portal: team registration, instance management, admin panel
```

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Option A — Single Instance (quick test)](#option-a--single-instance-quick-test)
3. [Option B — Multi-Team with Manager](#option-b--multi-team-with-manager)
   - [Step 1: Clone the repo](#step-1-clone-the-repo)
   - [Step 2: Build the challenge image](#step-2-build-the-challenge-image)
   - [Step 3: Configure the manager](#step-3-configure-the-manager)
   - [Step 4: Start the manager](#step-4-start-the-manager)
   - [Step 5: Admin panel](#step-5-admin-panel)
4. [Managing Teams Manually (no manager)](#managing-teams-manually-no-manager)
5. [Customising Flags](#customising-flags)
6. [Stopping & Resetting](#stopping--resetting)
7. [Troubleshooting](#troubleshooting)
8. [Repository Layout](#repository-layout)

---

## Prerequisites

- **Docker** with the Compose plugin — [install guide](https://docs.docker.com/get-docker/)
  - Docker Desktop includes both on Windows/macOS
  - On Linux: `sudo apt install docker.io docker-compose-plugin`
- **Linux or macOS host** for the manager (it mounts `/var/run/docker.sock`)
- Git

Verify your install:

```bash
docker --version          # Docker version 24+
docker compose version    # Docker Compose version v2+
```

---

## Option A — Single Instance (quick test)

Runs one challenge instance for testing or solo play. No manager needed.

```bash
git clone <repo-url> bankingai-ctf
cd bankingai-ctf/challenge
docker compose up --build -d
```

Open **http://localhost** in your browser.

> **Note:** The MySQL database takes ~30 seconds to initialise on first run. If the page doesn't load immediately, wait and refresh.

**Stop:**
```bash
docker compose down
```

**Full reset** (wipes the database and starts fresh):
```bash
docker compose down -v
docker compose up --build -d
```

---

## Option B — Multi-Team with Manager

Teams self-register at the manager portal. Each team gets their own isolated challenge instance on a unique port, provisioned automatically.

### Step 1: Clone the repo

```bash
git clone <repo-url> bankingai-ctf
cd bankingai-ctf
```

### Step 2: Build the challenge image

This is a **one-time step**. The manager reuses this image for every team — it does not rebuild per team.

```bash
cd challenge
docker compose build
cd ..
```

You should see output ending in `=> => naming to docker.io/library/ctf-web:latest`. If you don't see that image name, re-run the build.

### Step 3: Configure the manager

Open `manager/docker-compose.yaml` in a text editor. Fill in the required values:

```yaml
environment:
  SECRET_KEY:       "replace-with-a-random-string"
  ADMIN_TOKEN:      "replace-with-your-admin-password"
  CTF_COMPOSE_FILE: "/ctf/challenge/docker-compose.yaml"   # leave exactly as-is
  CHALLENGE_DIR:    "/absolute/host/path/to/bankingai-ctf/challenge"
  HOST_IP:          "192.168.x.x"
  PORT_RANGE_START: "8000"
  FLAG_SECRET:      "replace-with-a-random-string"
```

**`SECRET_KEY`** — any random string, used to sign Flask session cookies. Generate one:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**`ADMIN_TOKEN`** — the password you'll use to log in to `/admin`. Pick anything secure.

**`CTF_COMPOSE_FILE`** — leave this as `/ctf/challenge/docker-compose.yaml`. The compose file is bind-mounted into the manager container at that path. Do not change it.

**`CHALLENGE_DIR`** — the **absolute path on the host machine** to the `challenge/` directory. The manager passes this to `docker compose --project-directory` so the Docker daemon resolves relative bind mounts (`./web/src` etc.) against the correct host paths.

```
# Example: if you cloned to /home/alice/bankingai-ctf
CHALLENGE_DIR: "/home/alice/bankingai-ctf/challenge"
```

To find the correct value, run from the repo root:
```bash
realpath challenge
```

**`HOST_IP`** — the IP address or hostname shown to players in their dashboard URL (`http://HOST_IP:PORT`). Must be reachable from players' machines.

> Use your LAN IP, not `127.0.0.1` — players would just get a link to their own machine.

Find your LAN IP:
```bash
# Linux
hostname -I | awk '{print $1}'

# macOS
ipconfig getifaddr en0

# Windows (PowerShell)
(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object -First 1).IPAddress
```

**`PORT_RANGE_START`** — first port assigned to teams. Ports are assigned sequentially: team 1 gets 8000, team 2 gets 8001, etc. Make sure this range is open in your firewall.

**`FLAG_SECRET`** — a random string used to generate all flags. Each team's flags are derived from this secret and their team name — so every team gets unique flags and players cannot share answers. Generate one the same way as `SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

> Keep `FLAG_SECRET` private. Anyone who knows it can compute every team's flags.

### Step 4: Start the manager

```bash
cd manager
docker compose up --build -d
```

The manager is now running at **http://localhost** (port 80).

**What happens when a team registers:**
1. Manager creates a DB entry and assigns a port
2. Manager calls `docker compose up -d` on the host (via the Docker socket)
3. Team's dashboard shows "Starting…" and auto-refreshes every 5 seconds
4. Manager polls via the Docker socket until the web container is `running`
5. Status flips to "Ready" and the dashboard shows a clickable link: `http://HOST_IP:PORT`

> The DB init (~30s) is the main source of startup delay. The auto-refresh will catch it.

### Step 5: Admin panel

Browse to **http://localhost/admin** and enter your `ADMIN_TOKEN`.

The admin panel shows every registered team with:
- Their assigned port and instance URL
- Current status (starting / ready / stopped / error)
- **Stop** — runs `docker compose down -v` (destroys containers + DB volume)
- **Restart** — runs `docker compose up -d` and begins polling again

---

## Managing Teams Manually (no manager)

If you prefer bash scripts instead of the web portal, use the helpers in `challenge/scripts/`.
Run all commands from the **`challenge/`** directory.

**Add a team** (auto-assigns port from 8000 upward):
```bash
bash scripts/add_team.sh alpha
```

**Add a team on a specific port:**
```bash
bash scripts/add_team.sh bravo 8002
```

**Remove a team** (stops containers + wipes DB volume):
```bash
bash scripts/remove_team.sh alpha
```

**List all running team instances:**
```bash
bash scripts/list_teams.sh
```

---

## Customising Flags

Flag values are generated automatically — you do **not** edit `challenge/docker-compose.yaml`.

Each flag is derived from `FLAG_SECRET` (set in `manager/docker-compose.yaml`) and the team's name:

```
CTF{<slug>_<8-char hmac>}
```

Examples for a team named `teamalpha`:
```
CTF{inspected_3a7f9c21}
CTF{login_b4d82f10}
CTF{credential_harvester_77c1e5aa}
CTF{admin_access_091f3c88}
CTF{file_upload_cc482b6f}
```

Every team gets different flag values — players cannot share answers between instances.

To compute any team's flag value manually (e.g. for the answer sheet):
```bash
python3 -c "
import hmac, hashlib
secret = 'your-FLAG_SECRET-value'
team   = 'teamname'
flag_id = 'FLAG_LOGIN'
slug   = flag_id.replace('FLAG_', '').lower()
token  = hmac.new(secret.encode(), f'{flag_id}:{team}'.encode(), hashlib.sha256).hexdigest()[:8]
print(f'CTF{{{slug}_{token}}}')
"
```

To change the flag format, change `FLAG_SECRET` in `manager/docker-compose.yaml` and restart the manager. All existing team instances must also be restarted from the admin panel so their containers pick up the new values.

---

## Stopping & Resetting

**Stop the manager:**
```bash
cd manager
docker compose down
```
Team instances keep running. The SQLite database persists in `manager/data/`.

**Stop the manager and wipe all manager data:**
```bash
cd manager
docker compose down -v
```

**Stop a single team's instance (manual):**
```bash
cd challenge
docker compose -p ctf_<teamname> down -v
```

**Stop all team instances at once:**
```bash
docker ps --filter name=ctf_ -q | xargs docker stop
docker ps -a --filter name=ctf_ -q | xargs docker rm
docker volume ls --filter name=ctf_ -q | xargs docker volume rm
```

---

## Troubleshooting

**Challenge page won't load after `docker compose up`**

The MySQL database takes up to 30 seconds to initialise on first run. Wait and refresh. Check progress:
```bash
docker compose logs db --follow
# wait for: "ready for connections"
```

**Manager shows a team as "starting" indefinitely**

Check the team's containers are actually running:
```bash
docker ps | grep ctf_<teamname>
```

If containers aren't there, check manager logs:
```bash
cd manager && docker compose logs manager --follow
```

Common causes:
- `CHALLENGE_DIR` is not set or points to the wrong host path
- The challenge image wasn't built (`cd challenge && docker compose build`)
- Check manager logs: `docker logs ctf_manager`

**`docker compose up` in the manager fails with "image not found"**

The challenge image must be built on the host before the manager can use it:
```bash
cd challenge && docker compose build
```

**Port already in use**

Another process or team instance is on that port. Either stop it or change `PORT_RANGE_START`.

**Teams can't reach their instance URL**

- `HOST_IP` is probably set to `127.0.0.1` — change it to your LAN IP
- Check that your firewall allows inbound TCP on the port range (default 8000+)
- On Linux: `sudo ufw allow 8000:8100/tcp`

**View logs for any container:**
```bash
docker compose -p ctf_<teamname> -f challenge/docker-compose.yaml logs web
docker compose -p ctf_<teamname> -f challenge/docker-compose.yaml logs db
```

---

## Repository Layout

```
bankingai-ctf/
│
├── README.md                            ← you are here
├── .gitignore
│
├── challenge/                           ← CTF challenge (what players solve)
│   ├── docker-compose.yaml              ← orchestrates web + db containers
│   ├── .gitignore
│   │
│   ├── web/
│   │   ├── Dockerfile                   ← PHP 8.2 + Apache image
│   │   └── src/                         ← web root (bind-mounted; live edits)
│   │       ├── index.php
│   │       ├── login.php                ← prepared statement (intentional)
│   │       ├── lookup.php               ← SQLi vulnerability (intentional)
│   │       ├── dashboard.php            ← shows FLAG_LOGIN after login
│   │       ├── products.php             ← FLAG_INSPECTED in HTML comment
│   │       ├── admin_uploads.php        ← unrestricted upload (intentional)
│   │       ├── admin_subnav.php         ← shows FLAG_ADMIN_ACCESS
│   │       ├── robots.txt               ← hints at credential location
│   │       └── staff-resources/
│   │           └── new-employee-guide.txt  ← contains login credentials
│   │
│   ├── db/
│   │   ├── bankingai.sql                ← MySQL 8.0 schema + seed data
│   │   └── init_flags.sh                ← injects FLAG_CREDENTIAL_HARVESTER
│   │
│   └── scripts/                         ← manual multi-team bash helpers
│       ├── add_team.sh
│       ├── remove_team.sh
│       └── list_teams.sh
│
└── manager/                             ← team management web app
    ├── docker-compose.yaml              ← runs the manager container
    ├── Dockerfile                       ← Python 3.12 + Docker CLI
    ├── app.py                           ← Flask app: all routes + Docker logic
    ├── requirements.txt                 ← flask, bcrypt
    ├── .gitignore
    └── templates/
        ├── base.html                    ← dark terminal theme + shared CSS
        ├── index.html                   ← register (left) + login (right)
        ├── dashboard.html               ← team's instance URL, flag grid, score
        ├── scoreboard.html              ← public ranked scoreboard
        ├── admin.html                   ← all teams table with stop/restart
        └── admin_login.html             ← token prompt
```

---

*For authorised testing and CTF events only.*
