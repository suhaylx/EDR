# TuranSec EDR — Docker quickstart (5 steps)

**Ubuntu 24.04 local lab.** Installs the dashboard, Go backend, login gateway and PostgreSQL. Windows/Linux agents run **on the endpoints**, not in Docker.

## 1. Install Docker

```bash
sudo apt update
sudo apt install -y git openssl python3 docker.io docker-compose-v2
sudo systemctl enable --now docker
```

If your Ubuntu Docker repository uses `docker-compose-plugin` instead, install that package.

## 2. Clone

```bash
git clone https://github.com/suhaylx/EDR.git
cd EDR
```

## 3. Configure passwords (choose **one**)

**First installation:**
```bash
bash deploy/docker/init-lab.sh
```

**Already running the old certificate-login Docker lab:** preserve the database and existing credentials:
```bash
git pull --ff-only
bash deploy/docker/provision-passwords.sh --upgrade
```

Do not rerun `init-lab.sh` on an existing installation. Run provisioning as the same user who created `.docker-local`; avoid `sudo` for this script.

## 4. Start

```bash
sudo docker compose up -d --build --wait
sudo docker compose ps
```

## 5. Log in

Read your locally generated passwords (never paste or upload them):

```bash
cat .docker-local/operator/passwords.txt
```

From the server, visit **https://127.0.0.1:9444/**; from your laptop, first run `ssh -N -L 9444:127.0.0.1:9444 USER@SERVER_IP`, then open the same URL. Your lab uses a self-signed HTTPS certificate; trust its **server** CA for this lab in a dedicated browser profile. **No browser client certificate or private key import needed.**

- **admin** — dashboard and endpoint package generation
- **analyst** — triage and scans
- **viewer** — read-only access

## Generate a 3-component endpoint ZIP (admin)

Open **Admin → Generate endpoint agent package**. Select Windows or Linux, enter the endpoint ID, then generate the ZIP.

**Prerequisite:** Stage **approved** vendor components plus their SHA-256 manifest under `.docker-local/payloads/windows/` or `.docker-local/payloads/linux/`. Windows requires `TuranSec-Agent-Setup.exe`, `ClamAV.zip`, `Sysmon64.exe`. Linux requires `TuranSec-Agent-Setup`, `ClamAV.deb`, `SysmonForLinux.deb`. The button remains disabled until all three approved files match `approved.json`.

**Important:** This is a **3-component ZIP generator, not yet a one-click 3-in-1 installer**. Endpoint enrollment, approved vendor signatures, actual installation and host QA are separate. Endpoint mTLS remains enabled; the browser uses password login over HTTPS.

For exact manifest format, troubleshooting, native agents, agent enrollment, and rollback, see the [full Docker guide](DOCKER_GUIDE.md), [endpoint installer notes](ONE_AGENT_INSTALLER.md), and [complete installation manual](INSTALLATION.md). Keep ports 9443/9444/9445 bound to **127.0.0.1**. Never run `docker compose down -v` unless you intend to **delete the database volume**.
