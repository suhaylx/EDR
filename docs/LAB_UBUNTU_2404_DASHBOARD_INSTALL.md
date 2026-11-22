# TuranSec EDR: Ubuntu 24.04 dashboard/backend lab installation

**Status:** development lab only; not an enterprise-ready EDR deployment. Updated 2026-11-21.

**Target:** Ubuntu Server 24.04, as little as **8 GiB RAM**, separate Windows Server 2022 test endpoint. This manual installs the existing **Go HTTP backend plus the built-in plain-JavaScript SOC dashboard**. No Docker, ClickHouse, PostgreSQL, React build, AV daemon or Windows agent is needed on this Ubuntu host for the first smoke test. Backend events and jobs are **in-memory** and vanish on restart.

**Repository:** private `suhaylx/EDR`. **Dashboard/incident graph branch:** `feat/process-incident-graph-20261121` (draft PR #13, dependent on PR #8 / #5). Do not mistake `main` for this branch; the changes are not merged.

## Network security: requested `0.0.0.0` binding

The user has chosen `EDR_ADDR=0.0.0.0:8080`. This means Go listens on **all IPv4 interfaces**; it does **not** make the API safe to publish. The application currently has only a shared **development bearer token**, with no HTTPS, mTLS device identity, tenant isolation or durable audit. A remote browser on ordinary `http://SERVER_PUBLIC_IP:8080` would transmit its token in cleartext. **Do not do this.**

1. **Before changing the bind address**, configure the **cloud/provider firewall** to block inbound TCP **8080 from all public sources**. Verify no conflicting cloud-security rule allows it. Inbound TCP 3310 (ClamAV) must also remain blocked. Prefer restricting SSH/22 to the administrator's trusted IP or VPN.
2. On Ubuntu, inspect `sudo ufw status verbose`. If UFW is **active**, add a deny rule *before* starting the server: `sudo ufw insert 1 deny 8080/tcp`. Confirm `sudo ufw status numbered` and any higher-priority existing allow rules. If UFW is **inactive**, do not blindly enable it over an SSH session: first permit SSH from your trusted admin/VPN IP and verify provider console recovery; then enable it with an explicit maintenance procedure. Cloud firewall deny is still required.
3. Access the dashboard using an **SSH local port-forward** from your admin/Windows PC (step 6), or later a properly configured HTTPS reverse proxy and tested access controls. An SSH tunnel works even though Go is bound to `0.0.0.0` because the tunnel terminates at Ubuntu loopback.
4. Rotate any host credentials previously copied into chats, use verified SSH host keys and least-privilege GitHub deploy keys. **Never commit** development tokens or credentials. Do not expose Windows RDP to arbitrary sources.

## 1. Check resources and install tools

Run in the Ubuntu terminal as an account with `sudo`:

```bash
uname -m
lsb_release -a
free -h
nproc
df -h /
sudo apt update
sudo apt install -y git curl ca-certificates openssl snapd build-essential
sudo snap install go --classic
export PATH="/snap/bin:$PATH"
go version
```

Require **Go 1.23 or newer** (`backend/go.mod` requires `go 1.23`). If `go` is already installed, confirm its version rather than installing another one. Budget about **512 MiB maximum** for the Go app, leave the remaining RAM for Ubuntu and tests; this is not a throughput guarantee.

## 2. Access the private GitHub repository

Configure an SSH **read-only deploy key**, unless you already have authorized read-only GitHub SSH credentials:

```bash
install -d -m 0700 ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/turansec_edr_deploy -N '' -C 'turansec-lab-ubuntu-readonly'
cat ~/.ssh/turansec_edr_deploy.pub
```

Add **the `.pub` key only** to the repo **Settings > Deploy keys**; leave **Allow write access** off. Verify the GitHub SSH host key against GitHub's published fingerprints before trusting the initial handshake:
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints

```bash
GIT_SSH_COMMAND="ssh -i $HOME/.ssh/turansec_edr_deploy -o IdentitiesOnly=yes" \
  git clone --depth 1 --branch feat/process-incident-graph-20261121 \
  git@github.com:suhaylx/EDR.git "$HOME/turansec-edr"
```

Do not re-clone over an existing checkout; inspect its branch (`git branch --show-current`) and local changes first.

## 3. Compile and test the exact branch

```bash
cd "$HOME/turansec-edr/backend"
go version
go test ./...
go vet ./...
go build -trimpath -o turansec-edr-api ./cmd/server
```

Stop on any failure. The dashboard is static files in `backend/web/`; there is no `npm install` or Node build for this branch.

## 4. Install a dedicated read-only systemd service

Install root-owned application files, separate from the source checkout:

```bash
sudo install -d -m 0755 /opt/turansec-edr/bin /opt/turansec-edr/web
sudo install -m 0755 "$HOME/turansec-edr/backend/turansec-edr-api" /opt/turansec-edr/bin/turansec-edr-api
sudo cp -a "$HOME/turansec-edr/backend/web/." /opt/turansec-edr/web/
sudo chown -R root:root /opt/turansec-edr
sudo chmod -R go-w /opt/turansec-edr
id turansec-edr >/dev/null 2>&1 || \
  sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin turansec-edr
```

**Before creating the environment file, complete the cloud/UFW deny for inbound TCP 8080 described above.** Then create a fresh token without printing or committing it:

```bash
sudo install -d -m 0700 /etc/turansec-edr
sudo bash -c 'umask 077; {
  printf "EDR_DEV_TOKEN=%s\n" "$(openssl rand -hex 32)"
  printf "EDR_ADDR=0.0.0.0:8080\n"
  printf "EDR_WEB_DIR=/opt/turansec-edr/web\n"
} > /etc/turansec-edr/backend.env'
sudo chmod 0600 /etc/turansec-edr/backend.env
```

Install a service that cannot write application code or read arbitrary home directories:

```bash
sudo tee /etc/systemd/system/turansec-edr-lab.service >/dev/null <<'UNIT'
[Unit]
Description=TuranSec EDR laboratory Go API and SOC dashboard
After=network.target

[Service]
Type=simple
User=turansec-edr
Group=turansec-edr
WorkingDirectory=/opt/turansec-edr
EnvironmentFile=/etc/turansec-edr/backend.env
ExecStart=/opt/turansec-edr/bin/turansec-edr-api
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
MemoryMax=512M

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now turansec-edr-lab
```

`systemd` reads the root-only environment file before it switches to `turansec-edr`; normal users should not read that file.

## 5. Verify on Ubuntu, with no public API access

```bash
sudo systemctl is-active turansec-edr-lab
curl --fail --silent --show-error http://127.0.0.1:8080/api/health
curl -I http://127.0.0.1:8080/
sudo ss -ltnp | grep ':8080'
sudo ufw status verbose
```

Expected: active service, JSON showing `status: ok` and `mode: development`, HTTP 200 on `/`, and a listener at **`0.0.0.0:8080`**. **A listener does not prove that external firewall restrictions are correct.** Validate externally from an authorized testing location that direct TCP 8080 is blocked. Do not use a public HTTP browser URL.

For failures, inspect *without copying secrets*:

```bash
sudo journalctl -u turansec-edr-lab -n 80 --no-pager
sudo systemctl cat turansec-edr-lab
```

## 6. Open the dashboard from Windows or your admin workstation

Install Windows OpenSSH Client if needed, verify the Linux server SSH host-key fingerprint, and open a local tunnel (replace placeholders with the **private address/VPN endpoint if available**, otherwise the firewalled SSH address):

```powershell
ssh -o ExitOnForwardFailure=yes -N `
  -L 127.0.0.1:18080:127.0.0.1:8080 `
  LINUX_SSH_USER@LINUX_SSH_HOST
```

Then open **http://127.0.0.1:18080/** on the *same machine as the tunnel*. The connection to Ubuntu is SSH-encrypted. The page prompts for its development API token; retrieve it **on Ubuntu in a trusted private terminal**, never put it in chat, a ticket, GitHub or a screenshot:

```bash
sudo sed -n 's/^EDR_DEV_TOKEN=//p' /etc/turansec-edr/backend.env
```

The local browser token input is a temporary lab affordance, not production SSO/RBAC. Restrict who has admin/SSH access.

## 7. Update and rollback

These GitHub branches are unmerged prototypes. Before upgrading, preserve the old binary and web directory and make note of the tested commit SHA. Do not rotate the token during an upgrade unless intentionally ending existing lab sessions.

```bash
cd "$HOME/turansec-edr"
git rev-parse HEAD
# Fetch and review intended branch changes before changing deployed files:
GIT_SSH_COMMAND="ssh -i $HOME/.ssh/turansec_edr_deploy -o IdentitiesOnly=yes" git fetch origin feat/process-incident-graph-20261121
# Explicitly review changes first; do not blindly reset a modified worktree.
```

For a simple rollback, restore the backup executable and `web/` as root, then `sudo systemctl restart turansec-edr-lab`; verify health. This in-memory backend loses all collected lab state on restart. In a controlled lab you may stop it using `sudo systemctl stop turansec-edr-lab`.

## Known limitations and acceptance evidence

- Backend Go and static JS are deployed together; **React/TypeScript production UI does not exist yet**.
- The agent has **not** been deployed and the Windows Sysmon collector is **not** implemented in this build; no real endpoint protection or live incident story is established.
- Scan jobs, events, agents and policies are **in-memory**, and development bearer tokens are shared rather than per-device identities.
- Displaying the dashboard or green Go tests is **not** evidence of production safety, real ClamAV signatures, Windows event ingestion or endpoint enrollment.
- Collect QA evidence: checked branch SHA; `go version`; `go test ./...`; `go vet ./...`; `systemctl is-active`; local API health; HTTP 200 on `/`; `ss -ltnp`; **confirmed deny** for external 8080; Windows SSH tunnel and browser render. Mark actual server checks `NOT RUN` until observed.

Next: [Windows Server 2022 test-agent manual](LAB_WINDOWS_SERVER_2022_AGENT_INSTALL.md); scan protocol details are in `docs/LAB_CLAMAV_JOB_WORKER.md` on the Rust-worker branch.
