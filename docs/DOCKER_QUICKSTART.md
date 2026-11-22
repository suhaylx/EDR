# TuranSec EDR — Docker dashboard in 5 steps

**Ubuntu 24.04 / Linux local lab only.** The Docker stack contains the React SOC,
Go mTLS backend and PostgreSQL 16. Windows and Linux endpoint agents are native
programs, **not Docker services**. This is a convenient lab, not an enterprise
deployment. Don't run on a shared, publicly exposed or production host.

## 1 — Install Docker

```bash
sudo apt-get update
sudo apt-get install -y git curl openssl docker.io docker-compose-v2
sudo systemctl enable --now docker
```

Use an installation of Docker with the Compose v2 plugin; on systems that use
Docker's upstream apt repository, install `docker-compose-plugin` instead.
Confirm with `sudo docker compose version`.

## 2 — Clone the repository

```bash
git clone https://github.com/suhaylx/EDR.git
cd EDR
```

Private GitHub repository access is required. Check that the host has no other
services listening on TCP 55432, 9443 or 9444.

## 3 — Generate isolated lab credentials

```bash
bash deploy/docker/init-lab.sh
```

This creates short-lived disposable CAs, operator identities and separate
PostgreSQL passwords in ignored `.docker-local/`. It will **not** overwrite
existing lab secrets. Don't commit, upload or reuse these credentials. The
browser's analyst identity is `.docker-local/operator/analyst.p12` and its
import password is in `.docker-local/operator/p12-password.txt`.

## 4 — Start the dashboard

```bash
sudo docker compose up -d --build --wait
```

The first start creates and migrates the dedicated database, installs restricted
roles, and enrolls only the two sample SOC operators. It does **not** enroll
endpoint agents. The existing backend requires loopback for both TLS listeners
and database connections, so Compose uses **Linux host networking**. TCP 55432,
9443 and 9444 remain bound to 127.0.0.1; never change these binds to
`0.0.0.0`. The database uses a persistent Docker volume.

## 5 — Open and verify

Import `.docker-local/operator/analyst.p12` into the browser's client
certificate store using the password file; trust
`.docker-local/operator/server-ca.pem` as a **local lab-only** server CA.
Open **https://127.0.0.1:9444/** and select the analyst certificate.

Or verify the authenticated endpoint from the Ubuntu shell:

```bash
curl --fail --show-error --silent --cacert .docker-local/operator/server-ca.pem \
  --cert .docker-local/operator/viewer.pem \
  --key .docker-local/operator/viewer.key \
  https://127.0.0.1:9444/soc/v1/session
```

Expected JSON identifies tenant `lab`, operator `health-viewer`, role `viewer`.
The human `analyst` certificate is registered with role `scanner`.
No certificate, an untrusted CA or a mismatched identity must **not** work.

### Agents and maintenance

Linux endpoints use the [native systemd/ClamAV instructions](INSTALLATION.md#linux-endpoint-installation).
Windows endpoints use the [portable EXE/ClamAV instructions](INSTALLATION.md#windows-endpoint-installation).
Both require the separate [issuer-controlled enrollment procedure](INSTALLATION.md#endpoint-enrollment).
For remote authorized lab endpoints, forward agent port 9443 over approved SSH
and keep end-to-end mTLS. Docker does not issue or enroll agent identities.

```bash
sudo docker compose ps
sudo docker compose logs --tail 50 dashboard
sudo docker compose down            # stop; keep database
# CAUTION: "down -v" permanently destroys the disposable database
```

An existing persistent database is **not** automatically migrated when image
code changes. Back up the database, stop the stack, apply reviewed migrations
and restricted-role bootstrap, then start the compatible image. The automatic
init script is explicitly **first boot only**. Never delete a production volume
to repair migration errors.

This lab does not establish Windows service installation, package signatures,
live endpoint signature evidence, installed rollback or production approval.
