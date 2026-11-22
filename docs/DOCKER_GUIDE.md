# TuranSec EDR — Docker dashboard in 5 steps

**Ubuntu 24.04 / Linux local lab only.** The Docker stack contains the React SOC,
Go mTLS backend and PostgreSQL 16. Windows and Linux endpoint agents are native
programs, **not Docker services**. This is a convenient lab, not an enterprise
deployment. Don't run on a shared, publicly exposed or production host.

## 1 — Install Docker

```bash
sudo apt-get update
sudo apt-get install -y git curl openssl python3 docker.io docker-compose-v2
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

This creates short-lived disposable server/operator CAs, three randomly
generated password accounts (admin, analyst, viewer), and separate PostgreSQL
credentials in ignored `.docker-local/`. It refuses to overwrite existing lab
secrets. Review passwords locally with `cat .docker-local/operator/passwords.txt`.
Never upload this file, the database secrets, or CA private keys.

## 4 — Start the dashboard

```bash
sudo docker compose up -d --build --wait
```

The first start creates and migrates the dedicated database, installs restricted
roles, and registers admin, analyst, viewer and the legacy health-viewer identities. It does **not** enroll
endpoint agents. The existing backend requires loopback for both TLS listeners
and database connections, so Compose uses **Linux host networking**. TCP 55432,
9443, 9444 and the internal 9445 remain bound to 127.0.0.1; never change these binds to
`0.0.0.0`. The database uses a persistent Docker volume.

## 5 — Open and verify

Open **https://127.0.0.1:9444/** and sign in with `admin`, `analyst`,
or `viewer` and the account's generated password shown by:

```bash
cat .docker-local/operator/passwords.txt
```

**No browser client certificate or private key is required.** HTTPS remains
enabled. Trust `.docker-local/operator/server-ca.pem` as a **local lab-only**
server CA in a dedicated browser profile, or use the browser's one-time
self-signed-certificate exception for local testing. Never expose port 9444
publicly; use an SSH tunnel from your desktop.

For an existing Docker lab already running the old certificate-only dashboard,
update without deleting the database volume:
```bash
git pull --ff-only
bash deploy/docker/provision-passwords.sh --upgrade
sudo docker compose up -d --build --wait
cat .docker-local/operator/passwords.txt
```
Run provisioning as the original lab-file owner with Docker access. If your
shell needs `sudo` for Docker, grant access only through your approved
administration procedure; don't loosen the password-file permissions.

For backward-compatibility tests, the original certificate-only operator service
is now internal-only at **https://127.0.0.1:9445/**. Verify it on the server:

```bash
curl --fail --show-error --silent --cacert .docker-local/operator/server-ca.pem \
  --cert .docker-local/operator/viewer.pem \
  --key .docker-local/operator/viewer.key \
  https://127.0.0.1:9445/soc/v1/session
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


### Generate a per-endpoint package (admin)

The admin account can request a Windows or Ubuntu endpoint bootstrap ZIP from
the SOC dashboard. Generation requires **three approved offline payloads** in
the host's ignored `.docker-local/payloads/<platform>/` directory.

Windows requires `TuranSec-Agent-Setup.exe`, `ClamAV.zip`, `Sysmon64.exe`.
Linux requires `TuranSec-Agent-Setup`, `ClamAV.deb`, `SysmonForLinux.deb`.
Each directory must contain `approved.json` with a separately reviewed
SHA-256 pin for every exact filename, for example:

```json
{"files":[
  {"name":"TuranSec-Agent-Setup.exe","sha256":"APPROVED_SHA256"},
  {"name":"ClamAV.zip","sha256":"APPROVED_SHA256"},
  {"name":"Sysmon64.exe","sha256":"APPROVED_SHA256"}
]}
```

Until the required payloads are reviewed and staged, the button remains
disabled. Generated ZIPs contain public enrollment metadata and approved
payloads, **not client certificates, CA private keys or automatic enrollment**.
The supplied third-party components have separate license and vendor signature
review requirements. A generated ZIP is not yet a signed, fully self-installing
3-in-1 EDR package.
