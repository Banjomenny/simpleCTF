from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
import functools
import os

app = Flask(__name__)
app.secret_key = 'super_secret_ctf_key'

WEB_USER = "webadmin"
WEB_PASS = "dev123"

SSH_USER = "sysadmin"
SSH_PASS = "super_secure_p@ssw0rd"

FLAG_SOURCE      = os.environ.get('FLAG_SOURCE',      'CTF{s0urc3_c0d3_r3v34l5_s3cr3ts}')
FLAG_SSH_CREDS   = os.environ.get('FLAG_SSH_CREDS',   'CTF{m3t4d4t4_4nd_b4s364_ftw}')
FINAL_FLAG       = os.environ.get('FLAG_BASH_HISTORY', 'CTF{bash_h1st0ry_is_n0t_s3cur3}')

MOCK_FS = {
    "~": ["notes.txt", "script.sh", "todo.list"],
    "/var/www": ["index.html", "style.css"],
    "/tmp": ["socket.sock"]
}

BASH_HISTORY = [
    "sudo apt update",
    "cd /var/www/html",
    "vim config.php",
    "ls -la",
    "whoami",
    f"echo '{FINAL_FLAG}' > /root/flag.txt",
    "rm /root/flag.txt",
    "exit"
]

def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapped

@app.route('/packages')
@login_required
def packages():
    return render_template('packages.html')

@app.route('/users')
@login_required
def users():
    return render_template('users.html')

@app.route('/backups')
@login_required
def backups():
    return render_template('backups.html')

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':
        if request.form['username'] == WEB_USER and request.form['password'] == WEB_PASS:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials"
    return render_template('index.html', error=error, flag_source=FLAG_SOURCE)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/download')
@login_required
def download_file():
    return send_from_directory('static', 'files.zip', as_attachment=True)

@app.route('/ssh_client')
@login_required
def ssh_client():
    return render_template('ssh.html')

@app.route('/api/ssh/auth', methods=['POST'])
def ssh_auth():
    data = request.json
    if data.get('username') == SSH_USER and data.get('password') == SSH_PASS:
        session['ssh_active'] = True
        session['cwd'] = "~"
        motd = (
            "Last login: Mon Feb 09 09:05:12 2026 from 192.168.1.5\n"
            f"Session token: {FLAG_SSH_CREDS}"
        )
        return jsonify({"status": "success", "token": "dummy_token", "motd": motd})
    return jsonify({"status": "error", "message": "Access Denied"})

@app.route('/api/ssh/command', methods=['POST'])
def ssh_command():
    if not session.get('ssh_active'):
        return jsonify({"output": "Connection closed."})
    
    cmd = request.json.get('command', '').strip()
    cwd = session.get('cwd', '~')
    
    parts = cmd.split()
    if not parts:
        return jsonify({"output": ""})

    base_cmd = parts[0]

    if base_cmd == "ls":
        files = MOCK_FS.get(cwd, [])
        return jsonify({"output": "  ".join(files)})
    
    elif base_cmd == "pwd":
        return jsonify({"output": f"/home/{SSH_USER}" if cwd == "~" else cwd})
    
    elif base_cmd == "whoami":
        return jsonify({"output": SSH_USER})
    
    elif base_cmd == "id":
        return jsonify({"output": f"uid=1000({SSH_USER}) gid=1000({SSH_USER}) groups=1000({SSH_USER})"})
    
    elif base_cmd == "cd":
        if len(parts) > 1:
            target = parts[1]
            if target in MOCK_FS:
                session['cwd'] = target
                return jsonify({"output": ""})
            elif target == "~":
                session['cwd'] = "~"
                return jsonify({"output": ""})
            else:
                return jsonify({"output": f"bash: cd: {target}: No such file or directory"})
        return jsonify({"output": ""})

    elif base_cmd == "cat":
        if len(parts) > 1:
            if parts[1] == ".bash_history":
                 return jsonify({"output": "\n".join(BASH_HISTORY)})
            elif parts[1] in MOCK_FS.get(cwd, []):
                 return jsonify({"output": "[Binary garbage or meaningless text]"})
            else:
                 return jsonify({"output": f"cat: {parts[1]}: No such file or directory"})
        return jsonify({"output": ""})
    
    elif base_cmd == "history":
        output = []
        for i, hcmd in enumerate(BASH_HISTORY, 1):
            output.append(f" {i}  {hcmd}")
        return jsonify({"output": "\n".join(output)})

    elif base_cmd == "help":
        return jsonify({"output": "Available commands: ls, cd, cat, whoami, id, pwd, history"})

    else:
        return jsonify({"output": f"bash: {base_cmd}: command not found"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)