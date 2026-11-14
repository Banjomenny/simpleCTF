"""MediVault Patient Portal — simpleCTF challenge.

Intended chain (see README.md / ANSWER_SHEET for details):
  1. FLAG_IDOR — register, notice records are fetched from /api/records/<id>,
     enumerate IDs and read another patient's record.
  2. FLAG_JWT  — the session is an HS256 JWT signed with a weak key (in rockyou).
     Crack it, forge role=admin, open /admin.
  3. FLAG_SSTI — the admin "Letter templates" preview renders user input with
     render_template_string. {{ config }} leaks the flag.
  4. FLAG_RCE  — escalate the SSTI to command execution and read the flag file.

Everything outside the four vulnerable spots is ordinary filler so the site
reads like a real clinic portal: appointments, messages, billing, prescriptions
and a provider directory, all fake and generated deterministically per account.
"""

import datetime
import functools
import hashlib
import os
import random
import threading

import jwt
from flask import (Flask, abort, jsonify, make_response, redirect,
                   render_template, render_template_string, request, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

FLAG_IDOR = os.environ.get('FLAG_IDOR', 'CTF{1d0r_r3c0rds_l34k}')
FLAG_JWT  = os.environ.get('FLAG_JWT',  'CTF{w34k_jwt_s3cr3t}')
FLAG_SSTI = os.environ.get('FLAG_SSTI', 'CTF{t3mpl4t3_1nj3ct10n}')

# Weak signing key — must appear in rockyou.txt.
JWT_SECRET = os.environ.get('JWT_SECRET', 'sunshine')
JWT_ALG = 'HS256'
COOKIE_NAME = 'medivault_token'  # unique name: cookies are shared across ports on one host

# FLAG_SSTI lives in the Flask config so {{ config }} reveals it.
app.config['LETTERHEAD_SIGNING_KEY'] = FLAG_SSTI
app.config['SECRET_KEY'] = os.urandom(16).hex()

CLINIC = {
    'name': 'Riverside Family Clinic',
    'address': '2180 Riverside Drive, Suite 300, Columbus, OH 43215',
    'phone': '(614) 555-0147',
    'fax': '(614) 555-0162',
    'hours': 'Mon–Fri 8:00 AM – 6:00 PM · Sat 9:00 AM – 1:00 PM',
    'email': 'frontdesk@riversidefamilyclinic.example',
}

PROVIDERS = [
    {'name': 'Dr. Anika Patel', 'specialty': 'Family Medicine', 'accepting': True},
    {'name': 'Dr. Marcus Hale', 'specialty': 'Internal Medicine', 'accepting': True},
    {'name': 'Dr. Priya Rao', 'specialty': 'Pediatrics', 'accepting': False},
    {'name': 'Dr. Ellen Fischer', 'specialty': 'Cardiology', 'accepting': True},
    {'name': 'Dr. Samuel Boateng', 'specialty': 'Dermatology', 'accepting': True},
    {'name': 'Nurse Practitioner Dana Cole', 'specialty': 'Primary Care', 'accepting': True},
]

DEPARTMENTS = ['Family Medicine', 'Lab & Diagnostics', 'Cardiology',
               'Dermatology', 'Radiology', 'Physical Therapy']

# ---------------------------------------------------------------------------
# In-memory data (one instance per team, reset on restart)
# ---------------------------------------------------------------------------

_lock = threading.Lock()

USERS = {
    # username: {password_hash, role, record_id, name}
    'dr.patel': {
        'password_hash': generate_password_hash(os.urandom(12).hex()),
        'role': 'admin', 'record_id': None, 'name': 'Dr. Anika Patel',
    },
}

FIRST_NAMES = ['James', 'Maria', 'Robert', 'Linda', 'Michael', 'Susan', 'David',
               'Karen', 'Daniel', 'Nancy', 'Paul', 'Lisa', 'Mark', 'Betty',
               'Steven', 'Sandra', 'Kevin', 'Ashley', 'Brian', 'Donna',
               'George', 'Emily', 'Edward', 'Carol', 'Jason', 'Michelle']
LAST_NAMES = ['Garcia', 'Miller', 'Davis', 'Rodriguez', 'Wilson', 'Anderson',
              'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Thompson',
              'White', 'Harris', 'Clark', 'Lewis', 'Walker', 'Young', 'King',
              'Nguyen', 'Patel', 'Okafor', 'Rossi', 'Kim', 'Novak']
CONDITIONS = ['Seasonal allergies', 'Hypertension (controlled)', 'Type 2 diabetes',
              'Asthma', 'Sprained ankle (healing)', 'Annual physical — no findings',
              'Migraine', 'Vitamin D deficiency', 'High cholesterol', 'Back pain']
MEDS = ['Loratadine 10mg', 'Lisinopril 20mg', 'Metformin 500mg', 'Albuterol inhaler',
        'Ibuprofen 400mg', 'None', 'Sumatriptan 50mg', 'Vitamin D3 2000IU',
        'Atorvastatin 20mg', 'Naproxen 250mg']

RECORDS = {}
FIRST_RECORD_ID = 1001
SEEDED_COUNT = 64


def _seed_records():
    rng = random.Random(1337)
    for i in range(SEEDED_COUNT):
        rid = FIRST_RECORD_ID + i
        RECORDS[rid] = {
            'record_id': rid,
            'patient_name': f'{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}',
            'dob': f'{rng.randint(1950, 2004)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}',
            'blood_type': rng.choice(['A+', 'A-', 'B+', 'O+', 'O-', 'AB+']),
            'condition': rng.choice(CONDITIONS),
            'medication': rng.choice(MEDS),
            'physician': rng.choice([p['name'] for p in PROVIDERS[:4]]),
            'notes': 'Routine follow-up in 6 months.',
            'owner': None,
        }

    # The record players are hunting for.
    RECORDS[1001].update({
        'patient_name': 'TEST PATIENT (IT — do not delete)',
        'dob': '1970-01-01',
        'blood_type': 'N/A',
        'condition': 'N/A — integration test account',
        'medication': 'N/A',
        'physician': 'Dr. Anika Patel',
        'notes': (f'Integration test record. Verification code: {FLAG_IDOR}\n'
                  'IT ticket #4471: portal session tokens are still signed with the '
                  'vendor-default HS256 key from the install guide. Someone please '
                  'rotate it to something stronger than a dictionary word before go-live. '
                  'Admin console is at /admin.'),
    })


_seed_records()

# ---------------------------------------------------------------------------
# Deterministic per-account filler (appointments, messages, billing, meds)
# ---------------------------------------------------------------------------


def _rng_for(username):
    seed = int(hashlib.sha256(f'medivault:{username}'.encode()).hexdigest()[:8], 16)
    return random.Random(seed)


def _fake_appointments(username):
    rng = _rng_for(username)
    today = datetime.date.today()
    appts = []
    # a couple of past, a couple of upcoming
    for delta in sorted(rng.sample(range(-120, -3), 2) + rng.sample(range(4, 90), 2)):
        d = today + datetime.timedelta(days=delta)
        appts.append({
            'date': d.isoformat(),
            'time': rng.choice(['9:00 AM', '10:30 AM', '11:15 AM', '1:45 PM', '3:30 PM']),
            'provider': rng.choice([p['name'] for p in PROVIDERS]),
            'department': rng.choice(DEPARTMENTS),
            'reason': rng.choice(['Follow-up', 'Annual physical', 'Lab review',
                                  'Consultation', 'Vaccination', 'Blood pressure check']),
            'status': 'Completed' if delta < 0 else 'Upcoming',
        })
    return appts


def _fake_messages(username):
    rng = _rng_for(username)
    today = datetime.date.today()
    templates = [
        ('Riverside Family Clinic', 'Appointment reminder',
         'This is a reminder of your upcoming appointment. Please arrive 10 minutes early.'),
        ('Lab & Diagnostics', 'Your lab results are ready',
         'Your recent lab work has been reviewed. No urgent findings — details are in your chart.'),
        ('Billing Department', 'Statement available',
         'Your latest statement is now available to view under Billing.'),
        ('Dr. Anika Patel', 'Following up on your visit',
         'Thanks for coming in. Let us know if your symptoms change before our next appointment.'),
        ('Pharmacy', 'Prescription refill processed',
         'Your refill request has been processed and is ready for pickup.'),
    ]
    picks = rng.sample(templates, 3)
    msgs = []
    for i, (sender, subject, body) in enumerate(picks):
        msgs.append({
            'sender': sender, 'subject': subject, 'body': body,
            'date': (today - datetime.timedelta(days=rng.randint(0, 21))).isoformat(),
            'unread': i < rng.randint(1, 2),
        })
    msgs.sort(key=lambda m: m['date'], reverse=True)
    return msgs


def _fake_invoices(username):
    rng = _rng_for(username)
    today = datetime.date.today()
    descs = ['Office visit — copay', 'Lab panel (CBC)', 'X-ray — left ankle',
             'Vaccination — influenza', 'Specialist consultation', 'Physical therapy session']
    invs = []
    for i in range(rng.randint(3, 5)):
        amount = rng.choice([25.00, 40.00, 65.50, 120.00, 18.75, 210.00, 35.00])
        paid = rng.random() > 0.4
        invs.append({
            'id': f'INV-{rng.randint(10000, 99999)}',
            'date': (today - datetime.timedelta(days=rng.randint(5, 180))).isoformat(),
            'description': rng.choice(descs),
            'amount': amount,
            'status': 'Paid' if paid else 'Due',
        })
    invs.sort(key=lambda x: x['date'], reverse=True)
    return invs


def _fake_prescriptions(username, record):
    rng = _rng_for(username)
    rx = []
    primary = (record or {}).get('medication')
    if primary and primary != 'None':
        rx.append({'drug': primary, 'directions': 'Take one tablet daily as directed',
                   'refills': rng.randint(0, 3), 'prescriber': (record or {}).get('physician', 'Dr. Anika Patel')})
    extras = ['Amoxicillin 500mg', 'Cetirizine 10mg', 'Omeprazole 20mg', 'Multivitamin']
    for drug in rng.sample(extras, rng.randint(1, 2)):
        rx.append({'drug': drug, 'directions': rng.choice(
            ['Take one tablet daily', 'Take twice daily with food', 'As needed']),
            'refills': rng.randint(0, 5), 'prescriber': rng.choice([p['name'] for p in PROVIDERS])})
    return rx


def _dashboard_summary(username, record):
    appts = _fake_appointments(username)
    upcoming = [a for a in appts if a['status'] == 'Upcoming']
    msgs = _fake_messages(username)
    invs = _fake_invoices(username)
    balance = sum(i['amount'] for i in invs if i['status'] == 'Due')
    return {
        'next_appt': upcoming[0] if upcoming else None,
        'unread': sum(1 for m in msgs if m['unread']),
        'balance': balance,
        'rx_count': len(_fake_prescriptions(username, record)),
    }

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _issue_token(username):
    user = USERS[username]
    payload = {
        'sub': username,
        'role': user['role'],
        'rid': user['record_id'],
        'iat': int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def current_claims():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None


def _my_record(claims):
    rid = claims.get('rid')
    return RECORDS.get(rid) if rid else None


def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        claims = current_claims()
        if not claims:
            return redirect(url_for('login'))
        request.claims = claims
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    @functools.wraps(f)
    @login_required
    def wrapped(*args, **kwargs):
        if request.claims.get('role') != 'admin':
            return render_template('forbidden.html', claims=request.claims), 403
        return f(*args, **kwargs)
    return wrapped


def _login_response(username):
    resp = make_response(redirect(url_for('dashboard')))
    # Not HttpOnly on purpose: the token is easy to spot in dev tools.
    resp.set_cookie(COOKIE_NAME, _issue_token(username), samesite='Lax')
    return resp


@app.context_processor
def _inject_globals():
    return {'clinic': CLINIC}

# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------


@app.route('/')
def index():
    if current_claims():
        return redirect(url_for('dashboard'))
    return render_template('index.html', providers=PROVIDERS)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        user = USERS.get(username)
        if user and check_password_hash(user['password_hash'], password):
            return _login_response(username)
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()[:60] or username
        dob = request.form.get('dob', '').strip()[:10] or '2000-01-01'
        if not (3 <= len(username) <= 24) or not username.replace('.', '').replace('_', '').isalnum():
            error = 'Username must be 3–24 letters, numbers, dots or underscores.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            with _lock:
                if username in USERS:
                    error = 'That username is taken.'
                else:
                    rid = max(RECORDS) + 1
                    RECORDS[rid] = {
                        'record_id': rid,
                        'patient_name': full_name,
                        'dob': dob,
                        'blood_type': 'Pending lab work',
                        'condition': 'New patient intake',
                        'medication': 'None',
                        'physician': 'Dr. Anika Patel',
                        'notes': 'Welcome to MediVault! Please book your first appointment.',
                        'owner': username,
                    }
                    USERS[username] = {
                        'password_hash': generate_password_hash(password),
                        'role': 'patient', 'record_id': rid, 'name': full_name,
                    }
            if not error:
                return _login_response(username)
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.route('/providers')
def providers():
    return render_template('providers.html', claims=current_claims(), providers=PROVIDERS)


@app.route('/contact')
def contact():
    return render_template('contact.html', claims=current_claims(), departments=DEPARTMENTS)


@app.route('/robots.txt')
def robots():
    return app.response_class('User-agent: *\nDisallow: /admin\n', mimetype='text/plain')

# ---------------------------------------------------------------------------
# Patient routes
# ---------------------------------------------------------------------------


@app.route('/dashboard')
@login_required
def dashboard():
    record = _my_record(request.claims)
    summary = _dashboard_summary(request.claims['sub'], record)
    return render_template('dashboard.html', claims=request.claims, summary=summary,
                           messages=_fake_messages(request.claims['sub'])[:3])


@app.route('/records')
@login_required
def records():
    return render_template('records.html', claims=request.claims)


@app.route('/appointments')
@login_required
def appointments():
    return render_template('appointments.html', claims=request.claims,
                           appointments=_fake_appointments(request.claims['sub']),
                           providers=PROVIDERS, departments=DEPARTMENTS)


@app.route('/messages')
@login_required
def messages():
    return render_template('messages.html', claims=request.claims,
                           messages=_fake_messages(request.claims['sub']))


@app.route('/billing')
@login_required
def billing():
    invoices = _fake_invoices(request.claims['sub'])
    balance = sum(i['amount'] for i in invoices if i['status'] == 'Due')
    return render_template('billing.html', claims=request.claims,
                           invoices=invoices, balance=balance)


@app.route('/prescriptions')
@login_required
def prescriptions():
    record = _my_record(request.claims)
    return render_template('prescriptions.html', claims=request.claims,
                           prescriptions=_fake_prescriptions(request.claims['sub'], record))


@app.route('/api/records/<int:record_id>')
@login_required
def api_record(record_id):
    # VULNERABLE (intended): authenticates the caller but never checks
    # that the record belongs to them.
    record = RECORDS.get(record_id)
    if not record:
        return jsonify({'error': 'Record not found'}), 404
    return jsonify({k: v for k, v in record.items() if k != 'owner'})


@app.route('/api/me')
@login_required
def api_me():
    return jsonify(request.claims)

# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

DEFAULT_LETTER = (
    'Dear {{ patient.patient_name }},\n\n'
    'This is a reminder of your upcoming appointment with {{ patient.physician }} '
    'on {{ appointment }}.\n\n'
    'Kind regards,\nMediVault Clinic'
)


@app.route('/admin')
@admin_required
def admin():
    patients = sorted(RECORDS.values(), key=lambda r: r['record_id'])
    return render_template('admin.html', claims=request.claims,
                           flag=FLAG_JWT, patients=patients)


@app.route('/admin/letters', methods=['GET', 'POST'])
@admin_required
def admin_letters():
    template = DEFAULT_LETTER
    preview = None
    error = None
    record_id = FIRST_RECORD_ID + 1
    if request.method == 'POST':
        template = request.form.get('template', '')[:4000]
        try:
            record_id = int(request.form.get('record_id', record_id))
        except ValueError:
            pass
        patient = RECORDS.get(record_id) or RECORDS[FIRST_RECORD_ID + 1]
        try:
            # VULNERABLE (intended): user-controlled template rendered by Jinja2.
            preview = render_template_string(
                template, patient=patient,
                appointment=(datetime.date.today() + datetime.timedelta(days=7)).isoformat(),
            )
        except Exception as exc:  # show template errors so players can iterate
            error = f'{type(exc).__name__}: {exc}'
    return render_template('letters.html', claims=request.claims, template=template,
                           preview=preview, error=error, record_id=record_id,
                           patients=sorted(RECORDS.values(), key=lambda r: r['record_id']))


@app.errorhandler(404)
def not_found(_):
    return render_template('404.html', claims=current_claims()), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
