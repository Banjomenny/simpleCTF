#!/bin/sh
# Runs as root: write the RCE flag to /flag.txt, then drop privileges and
# strip FLAG_RCE from the environment so it can only be read from the file.
set -e
printf '%s\n' "${FLAG_RCE:-CTF{r3m0t3_c0d3_v14_sst1}}" > /flag.txt
chmod 444 /flag.txt
exec setpriv --reuid=ctfuser --regid=ctfuser --init-groups \
    env -u FLAG_RCE \
    gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 8 app:app
