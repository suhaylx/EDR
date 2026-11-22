#!/usr/bin/env python3
"""TuranSec native endpoint single-entry installer (pilot, not release acceptance).

Runs from a one-file PyInstaller binary containing the reviewed Rust agent.
ClamAV comes from the OS distro (Linux) or an approved local installation
(Windows); Microsoft Sysmon must be supplied through an approved signed source.
The backend must already have enrolled the client certificate.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys

def run(argv, check=True):
    return subprocess.run(argv, check=check, capture_output=True, text=True)

def approved_identity(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", value)) and value not in (".", "..")

def real_file(path):
    p = Path(path)
    if not p.is_absolute() or p.is_symlink() or not p.is_file() or p.stat().st_size < 1:
        raise ValueError("Expected an absolute, regular, non-symlinked input file")
    if p.stat().st_size > 300 * 1024 * 1024:
        raise ValueError("Input exceeds package size limit")
    return p

def signed_windows(path, thumbprint=None, microsoft=False):
    script = (
        "$ErrorActionPreference='Stop';"
        "$s=Get-AuthenticodeSignature -LiteralPath $env:EDR_CHECK_BINARY;"
        "if($s.Status -ne 'Valid' -or !$s.SignerCertificate){exit 11};"
        "if($env:EDR_EXPECTED_THUMB -and $s.SignerCertificate.Thumbprint -ne $env:EDR_EXPECTED_THUMB){exit 12};"
        "if($env:EDR_EXPECT_MS -eq '1' -and $s.SignerCertificate.Subject -notmatch 'Microsoft'){exit 13}"
    )
    env = dict(os.environ, EDR_CHECK_BINARY=str(path),
               EDR_EXPECTED_THUMB=thumbprint or "", EDR_EXPECT_MS="1" if microsoft else "0")
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                   check=True, env=env, stdout=subprocess.DEVNULL)

def prepare(args):
    if not approved_identity(args.tenant) or not approved_identity(args.agent_id):
        raise ValueError("Invalid tenant or agent identifier")
    if args.origin != "https://127.0.0.1:9443":
        raise ValueError("Current agent supports only the approved local TLS tunnel")
    if platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("x64 endpoint required")
    if os.name == "nt" and platform.system() != "Windows":
        raise ValueError("Unsupported operating system")
    if os.name != "nt" and platform.system() != "Linux":
        raise ValueError("Unsupported operating system")
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    suffix = ".exe" if os.name == "nt" else ""
    agent = real_file(base / ("turansec-edr-agent" + suffix))
    version = run([str(agent), "--version"]).stdout.strip()
    if not re.search(r"source=[0-9a-f]{40}", version):
        raise ValueError("Agent binary is missing its full source identity")
    identity = Path(args.identity_dir)
    if not identity.is_absolute() or identity.is_symlink() or not identity.is_dir():
        raise ValueError("Provide an absolute enrolled identity directory")
    inputs = {name: real_file(identity / name) for name in
              ("server-ca.pem", "agent.pem", "agent.key")}
    if os.name != "nt" and stat.S_IMODE(inputs["agent.key"].stat().st_mode) & 0o077:
        raise ValueError("Private key must be owner-only")
    cert_details = run(["openssl", "x509", "-in", str(inputs["agent.pem"]),
                        "-noout", "-ext", "subjectAltName", "-checkend", "0"]).stdout
    required = "URI:spiffe://turansec.local/tenants/" + args.tenant + "/agents/" + args.agent_id
    if required not in cert_details:
        raise ValueError("Agent certificate does not match enrollment identity")
    if os.name == "nt":
        if not args.agent_signer:
            raise ValueError("Independent approved TuranSec publisher thumbprint required")
        if not re.fullmatch(r"[A-Fa-f0-9]{40,64}", args.agent_signer):
            raise ValueError("Invalid Windows publisher thumbprint")
        signed_windows(agent, thumbprint=args.agent_signer)
        sysmon = real_file(args.sysmon)
        signed_windows(sysmon, microsoft=True)
        if not args.accept_sysmon_eula:
            raise ValueError("Explicit Sysmon EULA acceptance required")
        if not args.clamav_dir or not Path(args.clamav_dir).is_dir():
            raise ValueError("Approved installed Windows ClamAV is required")
        real_file(Path(args.clamav_dir) / "clamd.exe")
        real_file(Path(args.clamav_dir) / "freshclam.exe")
    return agent, inputs, version

def require_admin():
    if os.name == "nt":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Run from an elevated administrator terminal")
    elif os.geteuid() != 0:
        raise PermissionError("Run with sudo")

def linux_install(args, agent, inputs):
    release = Path("/opt/turansec-endpoint")
    private = Path("/etc/turansec-endpoint")
    if (release / "agent").exists() or Path("/etc/systemd/system/turansec-endpoint.service").exists():
        raise ValueError("Existing installation; use a separately tested upgrade procedure")
    with open("/etc/os-release", encoding="utf-8") as f:
        os_release = f.read()
    if 'ID=ubuntu' not in os_release or 'VERSION_ID="24.04"' not in os_release:
        raise ValueError("Ubuntu 24.04 required")
    # Official Ubuntu packages, not scripts fetched as root from the internet.
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "--no-install-recommends",
         "clamav", "clamav-daemon", "clamav-freshclam", "openssl"])
    subprocess.run(["groupadd", "--system", "turansec-scan"], check=False, stdout=subprocess.DEVNULL)
    release.mkdir(parents=True, exist_ok=False)
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    dest = release / "agent"
    shutil.copyfile(agent, dest)
    dest.chmod(0o755)
    for name, source in inputs.items():
        target = private / name
        shutil.copyfile(source, target)
        target.chmod(0o600 if name == "agent.key" else 0o644)
    scan = Path("/var/lib/turansec/scan-root")
    scan.mkdir(parents=True, exist_ok=True)
    run(["chown", "root:turansec-scan", str(scan)])
    scan.chmod(0o2750)
    env = private / "identity.env"
    env.write_text("TURANSEC_MTLS_ORIGIN=https://127.0.0.1:9443\n"
                   "TURANSEC_MTLS_TENANT_ID=" + args.tenant + "\n"
                   "TURANSEC_MTLS_AGENT_ID=" + args.agent_id + "\n"
                   "TURANSEC_LAB_SCAN_ROOT=/var/lib/turansec/scan-root\n"
                   "TURANSEC_CLAMD_SOCKET=/run/clamav/clamd.ctl\n")
    env.chmod(0o600)
    unit = """[Unit]
Description=TuranSec bounded endpoint scan worker
After=network-online.target clamav-daemon.service
[Service]
Type=oneshot
DynamicUser=yes
User=turansec-endpoint
SupplementaryGroups=clamav turansec-scan
UMask=0077
EnvironmentFile=/etc/turansec-endpoint/identity.env
LoadCredential=server-ca.pem:/etc/turansec-endpoint/server-ca.pem
LoadCredential=agent.pem:/etc/turansec-endpoint/agent.pem
LoadCredential=agent.key:/etc/turansec-endpoint/agent.key
Environment=TURANSEC_MTLS_CA_PEM=%d/server-ca.pem
Environment=TURANSEC_MTLS_CERT_PEM=%d/agent.pem
Environment=TURANSEC_MTLS_KEY_PEM=%d/agent.key
ExecStart=/opt/turansec-endpoint/agent --heartbeat-mtls
ExecStart=/opt/turansec-endpoint/agent --clamav-health
ExecStart=/opt/turansec-endpoint/agent --scan-batch-mtls 5
TimeoutStartSec=15min
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
IPAddressDeny=any
IPAddressAllow=localhost
"""
    timer = """[Unit]
Description=TuranSec bounded scan timer
[Timer]
OnBootSec=30s
OnUnitInactiveSec=30s
RandomizedDelaySec=5s
Unit=turansec-endpoint.service
[Install]
WantedBy=timers.target
"""
    Path("/etc/systemd/system/turansec-endpoint.service").write_text(unit)
    Path("/etc/systemd/system/turansec-endpoint.timer").write_text(timer)
    run(["systemctl", "daemon-reload"])
    run(["systemd-analyze", "verify", "/etc/systemd/system/turansec-endpoint.service",
         "/etc/systemd/system/turansec-endpoint.timer"])
    if args.activate:
        run(["systemctl", "start", "clamav-daemon.service"])
        run(["systemctl", "start", "turansec-endpoint.service"])
        run(["systemctl", "enable", "--now", "turansec-endpoint.timer"])
    return "Linux agent/ClamAV installed; timer " + ("activated" if args.activate else "left disabled")

def windows_install(args, agent, inputs):
    # The Rust binary has no SCM service mode. A bounded task is not an EDR service.
    root = Path(os.environ["PROGRAMDATA"]) / "TuranSec" / "Endpoint"
    if root.exists():
        raise ValueError("Existing install; refusing overwrite")
    root.mkdir(parents=True)
    shutil.copyfile(agent, root / "agent.exe")
    pki = root / "pki"
    pki.mkdir()
    for name, source in inputs.items():
        shutil.copyfile(source, pki / name)
    run(["icacls.exe", str(root), "/inheritance:r", "/grant:r",
         "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F"])
    config = dict(origin=args.origin, tenant=args.tenant, agent=args.agent_id,
                  ca=str(pki / "server-ca.pem"), cert=str(pki / "agent.pem"),
                  key=str(pki / "agent.key"), scan=str(root / "scan"))
    (root / "scan").mkdir()
    (root / "agent.json").write_text(json.dumps(config))
    # Only run independently signed approved Microsoft Sysmon.
    run([str(args.sysmon), "-accepteula", "-i"])
    # The scanner is a separately trusted prerequisite; never expose 3310 on network.
    with socket.create_connection(("127.0.0.1", 3310), timeout=3):
        pass
    if args.activate:
        ps = root / "Run-Once.ps1"
        ps.write_text("""
$c=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'agent.json') -Raw | ConvertFrom-Json
$env:TURANSEC_MTLS_ORIGIN=$c.origin
$env:TURANSEC_MTLS_TENANT_ID=$c.tenant
$env:TURANSEC_MTLS_AGENT_ID=$c.agent
$env:TURANSEC_MTLS_CA_PEM=$c.ca
$env:TURANSEC_MTLS_CERT_PEM=$c.cert
$env:TURANSEC_MTLS_KEY_PEM=$c.key
$env:TURANSEC_LAB_SCAN_ROOT=$c.scan
& (Join-Path $PSScriptRoot 'agent.exe') --heartbeat-mtls
if($LASTEXITCODE -ne 0){exit 1}
& (Join-Path $PSScriptRoot 'agent.exe') --clamav-health
if($LASTEXITCODE -ne 0){exit 1}
& (Join-Path $PSScriptRoot 'agent.exe') --scan-batch-mtls 5
exit $LASTEXITCODE
""")
        run(["schtasks.exe", "/Create", "/TN", "TuranSec-BoundedEndpoint",
             "/TR", 'powershell.exe -NoProfile -NonInteractive -File "' + str(ps) + '"',
             "/SC", "MINUTE", "/MO", "1", "/RU", "SYSTEM", "/F"])
    return "Windows bounded agent staged; " + ("scheduled task enabled" if args.activate else "no background task activated")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-dir", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--origin", default="https://127.0.0.1:9443")
    parser.add_argument("--sysmon", help="approved Microsoft-signed Sysmon64.exe on Windows")
    parser.add_argument("--clamav-dir", help="approved existing Windows ClamAV directory")
    parser.add_argument("--agent-signer", help="independently approved Windows publisher fingerprint")
    parser.add_argument("--accept-sysmon-eula", action="store_true")
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        agent, inputs, version = prepare(args)
        if args.check_only:
            print("Preflight passed; no host changes made. " + version)
            return 0
        require_admin()
        print(linux_install(args, agent, inputs) if os.name != "nt"
              else windows_install(args, agent, inputs))
        return 0
    except (OSError, ValueError, PermissionError, subprocess.CalledProcessError) as exc:
        print("Installer refused unsafe/incomplete input: " + type(exc).__name__, file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
