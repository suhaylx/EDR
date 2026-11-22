# TuranSec EDR Linux agent — Ubuntu 24.04, quick lab test

**Status: development prototype.** This portable Rust binary does **not** install
a service, do real-time event capture, prevent malware, quarantine files, or
identify compromise. It polls a read-only, bounded sample of Linux **/proc**
and labels it **process_observed**, never process_create. It does not collect
command lines, credentials or environment contents.

## 1. Download and verify

From PR #49, download the **TuranSec-EDR-Lab-Ubuntu-2404-x64** artifact of a
**successful** linux-lab-agent-build GitHub Actions run. Extract to a
non-shared location on an **authorized lab-only Ubuntu 24.04 x64** machine.
Check the SHA-256 against SHA256SUMS.txt packaged by the build.

~~~bash
mkdir -p "$HOME/turansec-linux-lab"
# Place the downloaded artifact's extracted files in this directory.
cd "$HOME/turansec-linux-lab"
sha256sum -c SHA256SUMS.txt
./turansec-edr-agent
~~~

The no-argument command should print that background protection is NOT active.

## 2. Reach the Go lab backend securely

The Rust agent is deliberately restricted to **127.0.0.1**, not raw public HTTP.
If you are running this agent on the same Ubuntu server as the backend, verify:

~~~bash
curl -fsS http://127.0.0.1:8080/api/health
~~~

If running this agent on a *different* Linux host, first create an **SSH tunnel
on the agent host** to the Ubuntu backend. Use your freshly rebuilt server's
actual DNS name or authorized IP, not necessarily the previous one:

~~~bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18081:127.0.0.1:8080 uz-user@YOUR-UBUNTU-BACKEND-HOST
~~~

Run in a second shell:

~~~bash
curl -fsS http://127.0.0.1:18081/api/health
export TURANSEC_DEV_API_PORT=18081
~~~

Keep the tunnel shell running. For same-host execution use the default port
8080 and no port override. Do not expose TCP 8080 publicly; development token
authentication is **not** tenant/device identity, and raw HTTP is unsafe.

## 3. Send a genuine lab heartbeat and point-in-time process observations

In the shell where the executable is located:

~~~bash
cd "$HOME/turansec-linux-lab"
read -r -s -p 'Lab API token: ' EDR_DEV_TOKEN; printf '\n'
export EDR_DEV_TOKEN
./turansec-edr-agent --linux-telemetry-once linux-lab-01
# For 60-second polling, instead use:
./turansec-edr-agent --linux-telemetry-loop linux-lab-01
# Ctrl+C to exit the loop, then remove the token:
unset EDR_DEV_TOKEN TURANSEC_DEV_API_PORT
~~~

Open the securely tunneled SOC dashboard. In **Agents**, expect
linux-lab-01; in **Telemetry & triage**, inspect events with
source=procfs and type=process_observed. A single snapshot is *not* a complete
process history. It samples **up to 32** readable processes, may skip entries
that disappear or lack permissions, and does not preserve a restart-proof queue.
No endpoint is protected merely because it checked in.

## 4. Safe QA and removal

- On a disposable host, verify backend /api/health, heartbeat and events.
- Confirm no invented process GUID, process-create notification or infection.
- Confirm missing token and unreachable localhost backend fail clearly.
- Confirm the SSH tunnel and backend are reachable only by authorized admins.
- Stop with Ctrl+C, unset token variables and remove the extracted directory
  to uninstall this *portable, non-service* lab program.
- **Do not run as root**: the source intentionally reads only accessible /proc
  metadata and cannot guarantee endpoint-wide visibility.
- Linux ClamAV scan adapter is a separate, optional lab operation requiring
  an actual installed clamd socket. A verdict is not automatically attested.
- The PostgreSQL identity and queue code in PR #49 is a separate service
  prototype, **not yet wired** into the shared-token API used by this binary.

**Release gate:** CI passing proves build/test behavior in GitHub runners.
Real Linux/Windows endpoint collection and EICAR-only testing remain NOT RUN
until recorded on your freshly rebuilt isolated lab VMs.
