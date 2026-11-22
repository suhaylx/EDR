#!/usr/bin/env bash
# Ubuntu 24.04: one operator command installs the verified three components.
# Endpoint private keys must be issued/enrolled separately and NEVER travel in this ZIP.
set -Eeuo pipefail
umask 077
cd "$(dirname "$(readlink -f "$0")")"
usage() { echo "Usage: sudo bash install-turansec.sh --identity-dir /absolute/issued-agent --accept-sysmon-eula [--activate] [--check-only]" >&2; exit 2; }
identity='' activate=0 check=0 accepted=0
while (($#)); do
  case "$1" in
    --identity-dir) (($#>=2)) || usage; identity="$2"; shift 2;;
    --activate) activate=1; shift;;
    --check-only) check=1; shift;;
    --accept-sysmon-eula) accepted=1; shift;;
    *) usage;;
  esac
done
[[ -n "$identity" && "$identity" = /* && "$identity" != *$'\n'* ]] || usage
((accepted)) || { echo "Explicit Microsoft Sysmon license acceptance required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "Python 3 required for bundle verification" >&2; exit 2; }
read -r tenant agent_id < <(python3 - <<'PY'
import hashlib, json, pathlib, re, sys
root=pathlib.Path.cwd()
required=('TuranSec-Agent-Setup','ClamAV.deb','SysmonForLinux.deb')
manifest=json.loads((root/'approved.json').read_text())
records=manifest.get('files',[])
if not isinstance(records,list) or len(records)!=3 or {e.get('name') for e in records}!=set(required):
    sys.exit('Invalid three-component approval manifest')
for record in records:
    name=record['name']
    path=root/name
    if not path.is_file() or path.is_symlink() or not (0<path.stat().st_size<=300*1024*1024):
        sys.exit('Missing or unsafe vendor payload')
    digest=record.get('sha256','')
    if not isinstance(digest,str) or not re.fullmatch('[0-9a-fA-F]{64}',digest):
        sys.exit('Invalid SHA-256 pin')
    with path.open('rb') as src:
        if hashlib.file_digest(src,'sha256').hexdigest().lower()!=digest.lower():
            sys.exit('Vendor payload checksum mismatch')
info=json.loads((root/'enrollment.json').read_text())
tenant,agent=info.get('tenant_id'),info.get('agent_id')
for value in (tenant,agent):
    if not isinstance(value,str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,96}',value) or value in ('.','..'):
        sys.exit('Invalid enrollment identity')
if tenant!='lab' or info.get('platform')!='linux' or info.get('credential_material_not_embedded') is not True:
    sys.exit('Invalid bundle platform or enrollment policy')
print(tenant,agent)
PY
)
[[ -n "$tenant" && -n "$agent_id" ]] || exit 2
[[ "$(uname -s)" = Linux && "$(uname -m)" = x86_64 ]] || { echo "Ubuntu x64 required" >&2; exit 2; }
[[ -d "$identity" && ! -L "$identity" ]] || { echo "Issuer-enrolled identity directory required" >&2; exit 2; }
# ZIP extraction may discard executable mode. Only chmod after checksum validation.
chmod 0755 ./TuranSec-Agent-Setup
# No vendor package install occurs before enrollment and agent preflight.
./TuranSec-Agent-Setup --identity-dir "$identity" --tenant "$tenant" --agent-id "$agent_id" --check-only
if ((check)); then
  echo "Preflight passed. Actual vendor authenticity still requires independent approval."
  exit 0
fi
((EUID==0)) || { echo "Run with sudo after successful preflight" >&2; exit 2; }
. /etc/os-release
[[ "$ID" = ubuntu && "$VERSION_ID" = 24.04 ]] || { echo "Ubuntu 24.04 required" >&2; exit 2; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ./ClamAV.deb ./SysmonForLinux.deb
command -v sysmon >/dev/null || { echo "Sysmon package did not install" >&2; exit 1; }
sysmon -accepteula -i
systemctl is-active --quiet sysmon || { echo "Sysmon service is not active" >&2; exit 1; }
if ((activate)); then
  ./TuranSec-Agent-Setup --identity-dir "$identity" --tenant "$tenant" --agent-id "$agent_id" --activate
else
  ./TuranSec-Agent-Setup --identity-dir "$identity" --tenant "$tenant" --agent-id "$agent_id"
fi
echo "TuranSec, ClamAV and Sysmon installed. Agent scan activation requires --activate."
echo "Sysmon event ingestion to the SOC is not implemented; verify independent telemetry and signatures."
