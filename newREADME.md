# BankingAI Cloud — CTF Challenge

## The Story

BankingAI Cloud is a fast-growing fintech startup that markets itself as the future of AI-driven banking infrastructure. Behind the polished landing page, a whistleblower has tipped off your team that the company is quietly exfiltrating customer financial data and routing it through shell accounts.

Your job is to get inside their internal employee portal, escalate your access, and prove you were there. The company's security team is confident their platform is locked down. **Prove them wrong.**

**Get in. Get the flags. Get out.**

---

## Description

A multi-stage web challenge built around a PHP employee portal backed by MySQL. Players work through a chain of vulnerabilities across the application, each rewarding a flag. No CVEs, no guessing — just enumeration, exploitation, and escalation.

- **Difficulty:** Medium  
- **Category:** Web  
- **Flags:** 5  

The challenge is fully containerized and supports per-team isolation for classroom environments. Teams can be added, removed, and reset dynamically.

---

## Running the Challenge

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)  
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop)  
- Ubuntu 24.04 or similar Linux host recommended  

---

### Deploy Multiple Teams at Once

```bash
./deploy_teams.sh <number_of_teams> [starting_port]


Author

SWOCTS
