"""No-Docker local runner for Windows/macOS/Linux.

Writes FLAG_RCE to ./flag.txt (so the SSTI->RCE step has something to read),
then serves the app on http://127.0.0.1:5001 with Flask's built-in server.
On Windows the RCE payload reads it with `type flag.txt`; on *nix `cat flag.txt`.
"""
import os

os.environ.setdefault('FLAG_IDOR', 'CTF{1d0r_r3c0rds_l34k}')
os.environ.setdefault('FLAG_JWT',  'CTF{w34k_jwt_s3cr3t}')
os.environ.setdefault('FLAG_SSTI', 'CTF{t3mpl4t3_1nj3ct10n}')
os.environ.setdefault('FLAG_RCE',  'CTF{r3m0t3_c0d3_v14_sst1}')

with open('flag.txt', 'w') as fh:
    fh.write(os.environ['FLAG_RCE'] + '\n')

import app  # noqa: E402
print('MediVault running at http://127.0.0.1:5001  (Ctrl+C to stop)')
app.app.run(host='127.0.0.1', port=5001, debug=False)
