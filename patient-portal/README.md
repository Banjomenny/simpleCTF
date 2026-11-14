# MediVault Patient Portal

## The Story

Riverside Family Clinic just moved their records online with a portal built by
the lowest bidder. You've been given a routine patient login. See how far a
patient account can really go.

---

## Description

A Python Flask patient-records portal. Players chain four web vulnerabilities to
go from an ordinary patient account to command execution on the server.

- **Difficulty:** Medium–Hard
- **Category:** Web
- **Flags:** 4

| Flag | Name | Technique |
|------|------|-----------|
| `FLAG_IDOR` | Someone Else's Records | Insecure direct object reference on the records API |
| `FLAG_JWT`  | Forged Credentials | Weak HS256 secret, forge an admin session token |
| `FLAG_SSTI` | Template Trouble | Server-side template injection in the letter editor |
| `FLAG_RCE`  | Root of the Problem | Escalate SSTI to RCE and read `/flag.txt` |

The intended path is IDOR -> JWT -> SSTI -> RCE, but the first three flags can be
taken in any order once you have admin.

---

## Running Standalone (single instance)

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) with the Compose plugin

### Start
```bash
cd patient-portal
docker compose up --build -d
```
Available at **http://localhost:5001**.

### Stop
```bash
docker compose down
```

---

## Flags

In a managed deployment the manager injects unique per-team flags as the
`FLAG_IDOR`, `FLAG_JWT`, `FLAG_SSTI` and `FLAG_RCE` environment variables.
Standalone, the defaults in `docker-compose.yml` are used.

## Notes for operators

- One Gunicorn worker per instance: patient data is held in memory and reset on
  restart, so flags are stable for a given instance but state is not shared.
- `FLAG_RCE` is written to `/flag.txt` at container start and removed from the
  environment, so it can only be obtained through the RCE, not by dumping env.
- The JWT signing key defaults to a rockyou word (`sunshine`); override it with
  the `JWT_SECRET` env var for a different crack target.
