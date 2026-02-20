"""
CTF Manager — Flask web app that manages per-team Docker CTF instances.

Environment variables (set in manager/docker-compose.yaml):
  ADMIN_TOKEN       — token required to access /admin routes
  CTF_COMPOSE_FILE  — compose file path inside the manager container
  CHALLENGE_DIR     — absolute host path to challenge/ (for --project-directory)
  SECRET_KEY        — Flask session signing key
  PORT_RANGE_START  — first port to assign to teams (default 8000)
  HOST_IP           — IP / hostname shown to teams in their dashboard URL
  FLAG_INSPECTED, FLAG_LOGIN, FLAG_CREDENTIAL_HARVESTER,
  FLAG_ADMIN_ACCESS, FLAG_FILE_UPLOAD — correct flag values for submission scoring
"""

import hashlib
import hmac
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

import bcrypt
from flask import (Flask, flash, redirect, render_template,
                   request, session, url_for)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

ADMIN_TOKEN      = os.environ.get('ADMIN_TOKEN', '')
# Path the compose CLIENT reads (inside the container)
CTF_COMPOSE_FILE = os.environ.get('CTF_COMPOSE_FILE', '/ctf/challenge/docker-compose.yaml')
# Host filesystem path to challenge/ — passed as --project-directory so the
# Docker daemon resolves relative bind mounts (./web/src etc.) to the right host paths
CHALLENGE_DIR    = os.environ.get('CHALLENGE_DIR', '')
PORT_RANGE_START = int(os.environ.get('PORT_RANGE_START', '8000'))
HOST_IP          = os.environ.get('HOST_IP', '127.0.0.1')
# Single secret used to derive all per-team flags
FLAG_SECRET      = os.environ.get('FLAG_SECRET', 'change-me-flag-secret')

TZ = ZoneInfo('America/New_York')


def _ts_to_ms(ts_str: str) -> int:
    """Convert a UTC SQLite timestamp string to Unix milliseconds."""
    return int(datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc).timestamp() * 1000)


def _ts_to_est(ts_str: str) -> str:
    """Convert a UTC SQLite timestamp string to an EST/EDT display string."""
    dt = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc).astimezone(TZ)
    return dt.strftime('%Y-%m-%d %H:%M %Z')

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'manager.db')

# ---------------------------------------------------------------------------
# Flag config
# ---------------------------------------------------------------------------

FLAGS = [
    # Points reflect difficulty (75–200). fb_multiplier applied to first capture only.
    {'id': 'FLAG_INSPECTED',            'name': 'Inspect the Source',   'points':  75, 'fb_multiplier': 1.2},
    {'id': 'FLAG_LOGIN',                'name': 'Initial Access',        'points': 100, 'fb_multiplier': 1.2},
    {'id': 'FLAG_CREDENTIAL_HARVESTER', 'name': 'Credential Harvester',  'points': 150, 'fb_multiplier': 1.2},
    {'id': 'FLAG_ADMIN_ACCESS',         'name': 'Admin Access',          'points': 125, 'fb_multiplier': 1.2},
    {'id': 'FLAG_FILE_UPLOAD',          'name': 'File Upload RCE',       'points': 200, 'fb_multiplier': 1.2},
]
# Base total (no first blood bonuses). MAX_POSSIBLE includes all first blood bonuses.
MAX_SCORE    = sum(f['points'] for f in FLAGS)
MAX_POSSIBLE = sum(int(f['points'] * f['fb_multiplier']) for f in FLAGS)


def _team_flag(flag_id: str, team_name: str) -> str:
    """Generate a deterministic per-team flag.
    Format: CTF{<slug>_<8-char hmac>}
    e.g.  CTF{login_3a7f9c21}
    """
    slug  = flag_id.replace('FLAG_', '').lower()
    token = hmac.new(
        FLAG_SECRET.encode(),
        f'{flag_id}:{team_name}'.encode(),
        hashlib.sha256,
    ).hexdigest()[:8]
    return f'CTF{{{slug}_{token}}}'

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS teams (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                port          INTEGER UNIQUE NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status        TEXT DEFAULT 'starting'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                team_name    TEXT NOT NULL,
                flag_id      TEXT NOT NULL,
                captured_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(team_name, flag_id)
            )
        """)
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def get_team_by_name(name: str):
    with get_db() as db:
        row = db.execute('SELECT * FROM teams WHERE name = ?', (name,)).fetchone()
        return dict(row) if row else None


def get_all_teams():
    with get_db() as db:
        rows = db.execute('SELECT * FROM teams ORDER BY id').fetchall()
        return [dict(r) for r in rows]


def set_team_status(name: str, status: str):
    with get_db() as db:
        db.execute('UPDATE teams SET status = ? WHERE name = ?', (status, name))
        db.commit()


def next_free_port() -> int:
    with get_db() as db:
        used = {r[0] for r in db.execute('SELECT port FROM teams').fetchall()}
    port = PORT_RANGE_START
    while port in used:
        port += 1
    return port


def get_team_submissions(team_name: str) -> set:
    """Return the set of flag_ids already captured by this team."""
    with get_db() as db:
        rows = db.execute(
            'SELECT flag_id FROM submissions WHERE team_name = ?', (team_name,)
        ).fetchall()
    return {r['flag_id'] for r in rows}


def record_submission(team_name: str, flag_id: str) -> bool:
    """Insert a submission. Returns True on success, False if already captured."""
    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO submissions (team_name, flag_id) VALUES (?, ?)',
                (team_name, flag_id)
            )
            db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_first_bloods() -> dict:
    """Return {flag_id: team_name} for the first capture of each flag."""
    with get_db() as db:
        rows = db.execute(
            'SELECT flag_id, team_name FROM submissions ORDER BY id'
        ).fetchall()
    seen: dict = {}
    for r in rows:
        if r['flag_id'] not in seen:
            seen[r['flag_id']] = r['team_name']
    return seen


def _calc_score(team_name: str, flag_ids: set, first_bloods: dict) -> int:
    """Sum points for captured flags, applying first-blood multiplier where earned."""
    score = 0
    for f in FLAGS:
        if f['id'] in flag_ids:
            pts = f['points']
            if first_bloods.get(f['id']) == team_name:
                pts = int(pts * f['fb_multiplier'])
            score += pts
    return score


def get_scoreboard() -> list:
    """Return all teams ranked by score desc, last capture asc."""
    first_bloods = get_first_bloods()
    with get_db() as db:
        team_rows = db.execute('SELECT name, status FROM teams ORDER BY name').fetchall()
        sub_rows  = db.execute(
            'SELECT team_name, flag_id, captured_at FROM submissions'
        ).fetchall()

    subs: dict = defaultdict(list)
    for s in sub_rows:
        subs[s['team_name']].append(s)

    board = []
    for t in team_rows:
        team_subs    = subs[t['name']]
        flag_ids     = {s['flag_id'] for s in team_subs}
        last_cap_utc = max((s['captured_at'] for s in team_subs), default=None)
        score        = _calc_score(t['name'], flag_ids, first_bloods)
        fb_flags     = {fid for fid, tname in first_bloods.items() if tname == t['name']}
        board.append({
            'name':         t['name'],
            'status':       t['status'],
            'score':        score,
            'flag_ids':     flag_ids,
            'fb_flags':     fb_flags,
            'last_capture': _ts_to_est(last_cap_utc) if last_cap_utc else None,
            '_sort_key':    last_cap_utc or '9999-99-99',
        })

    board.sort(key=lambda r: (-r['score'], r['_sort_key']))
    return board

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _compose_env(port: int, team_name: str) -> dict:
    env = {**os.environ, 'PORT': str(port)}
    for f in FLAGS:
        env[f['id']] = _team_flag(f['id'], team_name)
    return env


def _compose_cmd(team_name: str) -> list:
    """Build the base `docker compose` command with correct file + project-directory."""
    cmd = ['docker', 'compose', '-p', f'ctf_{team_name.lower()}', '-f', CTF_COMPOSE_FILE]
    if CHALLENGE_DIR:
        cmd += ['--project-directory', CHALLENGE_DIR]
    return cmd


# Serialize docker compose up calls — concurrent MySQL inits can deadlock health checks
_compose_lock = threading.Lock()


def docker_up(team_name: str, port: int):
    """Start CTF containers for a team (serialized to prevent concurrent init races)."""
    with _compose_lock:
        result = subprocess.run(
            _compose_cmd(team_name) + ['up', '-d'],
            env=_compose_env(port, team_name),
            capture_output=True, text=True,
        )
    if result.returncode != 0:
        logging.error('docker_up failed for %s (port %s):\nSTDOUT: %s\nSTDERR: %s',
                      team_name, port, result.stdout, result.stderr)
    else:
        logging.info('docker_up started containers for team %s on port %s', team_name, port)


def docker_down(team_name: str, port: int):
    """Stop and wipe CTF containers + volumes for a team."""
    subprocess.run(
        _compose_cmd(team_name) + ['down', '-v'],
        env=_compose_env(port, team_name),
        check=False,
    )


def _web_container_state(team_name: str) -> str:
    """Return the Docker state of the web container: 'running', 'created', 'exited', or ''."""
    project = f'ctf_{team_name.lower()}'
    result = subprocess.run(
        ['docker', 'ps', '-a',
         '--filter', f'name={project}-web',
         '--format', '{{.State}}'],
        capture_output=True, text=True, timeout=10,
    )
    output = result.stdout.strip().lower()
    if 'running' in output:
        return 'running'
    if 'created' in output:
        return 'created'
    if 'exited' in output:
        return 'exited'
    return ''


def _poll_until_ready(team_name: str, port: int, timeout: int = 180):
    """Background thread: poll via Docker socket until the web container is running.

    If the web container is stuck in 'created' state (db health check raced with
    a concurrent compose up), we start it explicitly rather than waiting for compose.
    """
    project  = f'ctf_{team_name.lower()}'
    deadline = time.time() + timeout
    logging.info('Polling started for team %s (timeout %ss)', team_name, timeout)
    while time.time() < deadline:
        try:
            state = _web_container_state(team_name)
            if state == 'running':
                time.sleep(2)
                set_team_status(team_name, 'ready')
                logging.info('Team %s is ready', team_name)
                return
            elif state == 'created':
                # Compose left the container in Created — db health check wasn't
                # done when compose exited. Start the container directly.
                logging.info('Web container for %s is Created; starting it now', team_name)
                subprocess.run(
                    ['docker', 'start', f'{project}-web-1'],
                    capture_output=True, timeout=15,
                )
        except Exception as exc:
            logging.warning('Poll check error for %s: %s', team_name, exc)
        time.sleep(5)
    logging.error('Team %s timed out waiting for web container', team_name)
    set_team_status(team_name, 'error')


def launch_and_poll(team_name: str, port: int):
    """Start containers then poll in a background thread."""
    docker_up(team_name, port)
    t = threading.Thread(target=_poll_until_ready, args=(team_name, port), daemon=True)
    t.start()

# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'team' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Routes — public
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'team' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    name      = request.form.get('name', '').strip()
    password  = request.form.get('password', '')
    password2 = request.form.get('password2', '')

    if not re.fullmatch(r'[a-z0-9_-]{1,32}', name):
        flash('Team name must be 1–32 chars: lowercase letters, numbers, _ or -.', 'error')
        return redirect(url_for('index'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('index'))
    if password != password2:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('index'))

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    port    = next_free_port()

    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO teams (name, password_hash, port, status) VALUES (?,?,?,?)',
                (name, pw_hash, port, 'starting')
            )
            db.commit()
    except sqlite3.IntegrityError:
        flash('Team name already taken — please log in instead.', 'error')
        return redirect(url_for('index'))

    threading.Thread(target=launch_and_poll, args=(name, port), daemon=True).start()

    session['team'] = name
    flash(f'Instance for "{name}" is starting up — this takes ~30 seconds.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['POST'])
def login():
    name     = request.form.get('name', '').strip()
    password = request.form.get('password', '').encode()

    team = get_team_by_name(name)
    if not team or not bcrypt.checkpw(password, team['password_hash'].encode()):
        flash('Invalid team name or password.', 'error')
        return redirect(url_for('index'))

    session['team'] = name
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ---------------------------------------------------------------------------
# Routes — team dashboard + flag submission
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    team = get_team_by_name(session['team'])
    if not team:
        session.clear()
        return redirect(url_for('index'))
    first_bloods = get_first_bloods()
    captured     = get_team_submissions(session['team'])
    fb_flags     = {fid for fid, tname in first_bloods.items() if tname == session['team']}
    score        = _calc_score(session['team'], captured, first_bloods)
    instance_url = f'http://{HOST_IP}:{team["port"]}'
    return render_template('dashboard.html',
                           team=team,
                           instance_url=instance_url,
                           flags=FLAGS,
                           captured=captured,
                           fb_flags=fb_flags,
                           score=score,
                           max_score=MAX_SCORE)


@app.route('/submit', methods=['POST'])
@login_required
def submit_flag():
    team_name = session['team']
    submitted = request.form.get('flag', '').strip()

    matched_flag = None
    for f in FLAGS:
        if submitted == _team_flag(f['id'], team_name):
            matched_flag = f
            break

    if matched_flag is None:
        flash('Incorrect flag.', 'error')
        return redirect(url_for('dashboard'))

    captured = get_team_submissions(team_name)
    if matched_flag['id'] in captured:
        flash('You already captured that flag!', 'info')
        return redirect(url_for('dashboard'))

    first_bloods   = get_first_bloods()
    is_first_blood = matched_flag['id'] not in first_bloods
    record_submission(team_name, matched_flag['id'])

    pts = int(matched_flag['points'] * matched_flag['fb_multiplier']) if is_first_blood \
          else matched_flag['points']

    if is_first_blood:
        flash(f'FIRST BLOOD! "{matched_flag["name"]}" — +{pts} pts '
              f'({matched_flag["points"]} x {matched_flag["fb_multiplier"]})', 'success')
    else:
        flash(f'Correct! "{matched_flag["name"]}" captured — +{pts} pts', 'success')
    return redirect(url_for('dashboard'))


@app.route('/scoreboard')
def scoreboard():
    board = get_scoreboard()

    # Build per-team cumulative score time series for the graph
    with get_db() as db:
        team_rows = db.execute('SELECT name, created_at FROM teams').fetchall()
        sub_rows  = db.execute(
            'SELECT team_name, flag_id, captured_at FROM submissions ORDER BY captured_at'
        ).fetchall()

    created = {r['name']: r['created_at'] for r in team_rows}
    subs_by_team: dict = defaultdict(list)
    for s in sub_rows:
        subs_by_team[s['team_name']].append(s)

    first_bloods = get_first_bloods()
    graph_data = {}
    for team_name, subs in subs_by_team.items():
        start_ms = _ts_to_ms(created.get(team_name) or subs[0]['captured_at'])
        series = [{'x': start_ms, 'y': 0}]
        running_ids: set = set()
        for s in subs:
            running_ids.add(s['flag_id'])
            score = _calc_score(team_name, running_ids, first_bloods)
            series.append({'x': _ts_to_ms(s['captured_at']), 'y': score})
        graph_data[team_name] = series

    return render_template('scoreboard.html', board=board, flags=FLAGS,
                           max_score=MAX_SCORE, max_possible=MAX_POSSIBLE,
                           graph_data=graph_data)

# ---------------------------------------------------------------------------
# Routes — admin
# ---------------------------------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_page():
    if session.get('is_admin'):
        return redirect(url_for('admin'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and ADMIN_TOKEN and password == ADMIN_TOKEN:
            session['is_admin'] = True
            return redirect(url_for('admin'))
        flash('Invalid username or password.', 'error')
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login_page'))


@app.route('/admin')
@admin_required
def admin():
    teams        = get_all_teams()
    first_bloods = get_first_bloods()
    for t in teams:
        captured      = get_team_submissions(t['name'])
        t['score']    = _calc_score(t['name'], captured, first_bloods)
        t['captures'] = len(captured)
    return render_template('admin.html', teams=teams, max_score=MAX_SCORE)


@app.route('/admin/stop/<team_name>', methods=['POST'])
@admin_required
def admin_stop(team_name):
    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    threading.Thread(
        target=lambda: (docker_down(team_name, team['port']),
                        set_team_status(team_name, 'stopped')),
        daemon=True
    ).start()
    flash(f'Stopping "{team_name}"…', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/restart/<team_name>', methods=['POST'])
@admin_required
def admin_restart(team_name):
    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    set_team_status(team_name, 'starting')
    threading.Thread(
        target=launch_and_poll, args=(team_name, team['port']), daemon=True
    ).start()
    flash(f'Restarting "{team_name}"…', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/delete/<team_name>', methods=['POST'])
@admin_required
def admin_delete(team_name):
    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    # Best-effort Docker cleanup (may already be gone if remove_team.sh was used)
    threading.Thread(
        target=lambda: docker_down(team_name, team['port']),
        daemon=True
    ).start()

    with get_db() as db:
        db.execute('DELETE FROM submissions WHERE team_name = ?', (team_name,))
        db.execute('DELETE FROM teams WHERE name = ?', (team_name,))
        db.commit()

    flash(f'Team "{team_name}" deleted.', 'info')
    return redirect(url_for('admin'))

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
