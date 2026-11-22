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

Open **Admin → Agent packages**, select Windows or Linux, and enter an endpoint ID.

- **Download preparation kit** works immediately, even on a fresh Docker lab. It contains `enrollment.json`, the appropriate setup script, and a list of missing components. **This is not an installable TuranSec agent.** No executable, vendor payload, or private enrollment credential is embedded.
- **Download complete 3-in-1 agent** becomes available after all three approved binaries and their SHA-256 manifest have been staged. Use **Recheck files** in the dashboard to refresh availability without restarting Docker.

**To enable the complete bundle:** Place **independently approved** vendor and TuranSec artifacts in `.docker-local/payloads/windows/` or `.docker-local/payloads/linux/`. Windows requires `TuranSec-Agent-Setup.exe`, `ClamAV.zip`, `Sysmon64.exe`; Linux requires `TuranSec-Agent-Setup`, `ClamAV.deb`, `SysmonForLinux.deb`. Each platform also requires `approved.json` with exactly three `{"name":"...","sha256":"..."}` records in a `files` array. Verify official publisher/download signatures before approving those hashes. Use the helper documented in [three-component deployment](THREE_IN_ONE_DEPLOYMENT.md) to avoid accidental ownership and file-permission problems.

The dashboard now shows **exactly which files are missing**, or whether the SHA-256 approval check failed. The complete bundle **does not** bypass vendor licensing or device enrollment.

**Important:** The ZIP now includes an integrity-checking **single-command platform installer** (`install-turansec.sh` for Linux, `Install-TuranSec.ps1` for Windows), plus all three staged components. It still requires independently issued/enrolled agent credentials, approved vendor signatures/EULA, and internet for signature updates. Native installed-host QA, telemetry ingestion, code signing and rollback are not complete. This is an **engineering pilot**, not an approved EDR production release. Endpoint mTLS remains enabled; browser operators use password login over HTTPS. See [three-component deployment](THREE_IN_ONE_DEPLOYMENT.md).

For exact manifest format, troubleshooting, native agents, agent enrollment, and rollback, see the [full Docker guide](DOCKER_GUIDE.md), [endpoint installer notes](ONE_AGENT_INSTALLER.md), and [complete installation manual](INSTALLATION.md). Keep ports 9443/9444/9445 bound to **127.0.0.1**. Never run `docker compose down -v` unless you intend to **delete the database volume**.
