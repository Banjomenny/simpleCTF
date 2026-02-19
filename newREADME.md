BankingAI Cloud — CTF Challenge
The Story

BankingAI Cloud is a fast-growing fintech startup marketing itself as the future of AI-driven banking infrastructure. Behind the polished landing page, a whistleblower has tipped off your team that the company is quietly exfiltrating customer financial data and routing it through shell accounts.

Your mission: get inside their internal employee portal, escalate your access, and prove you were there. The company's security team is confident their platform is locked down — prove them wrong.

Get in. Get the flags. Get out.

Description

A multi-stage web challenge built around a PHP employee portal backed by MySQL. Players progress through a chain of vulnerabilities across the application, each rewarding a flag.

Difficulty: Medium

Category: Web

Flags: 5

The challenge is fully containerized for classroom environments, with per-team isolation and auto-deployable instances.

Prerequisites

Docker

Docker Compose
 (included with Docker Desktop)

Ubuntu 24.04 or similar Linux host recommended

Classroom Deployment

Instead of manually using docker-compose, the challenge now uses dynamic team scripts:

deploy_teams.sh → deploy multiple team instances at once

add_team.sh → add a single team dynamically

remove_team.sh → remove a single team completely

reset_all_teams.sh → wipe and remove all teams

1️⃣ Deploy Multiple Teams at Once

Deploy, for example, 10 teams starting from port 8101:

./deploy_teams.sh 10


Teams will automatically get ports 8101–8110

Each team has isolated web and database containers

All flags remain the same for each instance

2️⃣ Add a Single Team

Deploy a single team dynamically (e.g., Team 11):

./add_team.sh 11


Accessible at http://<host-ip>:8111

Fully isolated containers and network

3️⃣ Remove a Single Team

Remove a specific team completely:

./remove_team.sh 11


Stops containers

Removes network and database volume

Deletes the override file for that team

4️⃣ Reset All Teams

Completely stop and remove all teams:

./reset_all_teams.sh


Cleans all containers, networks, volumes, and team override files

Ideal for starting a fresh classroom session

5️⃣ Accessing the Challenge

Once deployed, the web portal is available at:

http://<host-ip>:<team-port>


Example for Team 1:

http://192.168.1.50:8101


Check container status:

docker ps | grep team

Customising Flags

All flags are already set and remain intact. You can customize them if needed by editing docker-compose.yml environment variables before deploying:

web:
  environment:
    FLAG_LOGIN:        "CTF{your_flag}"
    FLAG_INSPECTED:    "CTF{your_flag}"
    FLAG_ADMIN_ACCESS: "CTF{your_flag}"
    FLAG_FILE_UPLOAD:  "CTF{your_flag}"

db:
  environment:
    FLAG_CREDENTIAL_HARVESTER: "CTF{your_flag}"


Then run:

./reset_all_teams.sh
./deploy_teams.sh <number_of_teams>

Notes

Each team is fully isolated: separate web container, database container, network, and volume

The scripts allow flexible scaling: add/remove teams as needed

Firewall rules may be required on the host for the ports (8100–8200 by default)

Author

SWOCTS
