#!/usr/bin/env bash
# Add password-only browser accounts without replacing existing PKI/database.
# --fresh is called by init-lab.sh before first database boot.
# --upgrade adds the accounts to an existing running local Docker lab.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/../.."
case "${1:-}" in --fresh|--upgrade) mode="$1";; *) echo "usage: bash deploy/docker/provision-passwords.sh --fresh|--upgrade" >&2;exit 2;; esac
root="$PWD/.docker-local"
expected_uid="$(stat -c %u "$root/runtime/edrd.json" 2>/dev/null || echo -1)"
if [[ "$expected_uid" != "$(id -u)" ]]; then
  echo "Run as the owner who initialized this lab; do not use sudo to change secret ownership." >&2
  exit 1
fi
for name in operator-ca.key operator-ca.pem; do
  test -s "$root/private/$name" || { echo "Existing lab operator CA missing" >&2; exit 1; }
done
test -s "$root/runtime/edrd.json"
if [[ -e "$root/runtime/users.json" || -e "$root/operator/passwords.txt" ]]; then
  echo "Password accounts already provisioned: refusing to rotate or overwrite" >&2; exit 1
fi
command -v python3 >/dev/null
command -v openssl >/dev/null
mkdir -p "$root/runtime/operators" "$root/payloads/windows" "$root/payloads/linux"
chmod 700 "$root/runtime/operators"
# Keep existing analyst and viewer certificate identities intact.
for kind in admin viewer-login; do
  operator="$kind"
  if [[ "$kind" == viewer-login ]]; then operator=viewer; fi
  test ! -e "$root/private/$kind.pem"
  openssl req -new -newkey rsa:3072 -nodes -sha256 \
    -subj "/CN=TuranSec local $operator" \
    -keyout "$root/private/$kind.key" \
    -out "$root/private/$kind.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:spiffe://turansec.local/tenants/lab/operators/%s\n' "$operator" > "$root/private/$kind.ext"
  openssl x509 -req -in "$root/private/$kind.csr" \
    -CA "$root/private/operator-ca.pem" -CAkey "$root/private/operator-ca.key" \
    -CAcreateserial -days 7 -sha256 -extfile "$root/private/$kind.ext" \
    -out "$root/private/$kind.pem" >/dev/null 2>&1
  openssl x509 -in "$root/private/$kind.pem" -outform DER |
    openssl dgst -sha256 -r | awk '{print $1}' > "$root/fingerprints/$kind.sha256"
  chmod 644 "$root/fingerprints/$kind.sha256"
done
cp "$root/private/server-ca.pem" "$root/runtime/server-ca.pem"
for user in admin analyst viewer; do
  filename="$user"; if [[ "$user" == viewer ]]; then filename=viewer-login; fi
  install -m 0600 "$root/private/$filename.pem" "$root/runtime/operators/$user.pem"
  install -m 0600 "$root/private/$filename.key" "$root/runtime/operators/$user.key"
done
python3 - "$root" <<'PY'
import hashlib, json, pathlib, secrets, sys, os
root=pathlib.Path(sys.argv[1])
users=[]; passwords=[]
for role in ('admin','analyst','viewer'):
    password=secrets.token_urlsafe(24)
    salt=secrets.token_bytes(16)
    dk=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000)
    users.append({'username':role,'role':role,'salt':salt.hex(),'hash':dk.hex(),'iterations':600000})
    passwords.append(role+'='+password)
(root/'runtime/users.json').write_text(json.dumps({'users':users})+'\n')
(root/'operator/passwords.txt').write_text('\n'.join(passwords)+'\n')
os.chmod(root/'runtime/users.json',0o600)
os.chmod(root/'operator/passwords.txt',0o600)
config=root/'runtime/edrd.json'
data=json.loads(config.read_text())
if data.get('soc_listen')!='127.0.0.1:9444':
    raise SystemExit('Unexpected SOC port: refusing to change configuration')
data['soc_listen']='127.0.0.1:9445'
config.write_text(json.dumps(data,indent=2)+'\n')
os.chmod(config,0o600)
gateway={
 'listen':'127.0.0.1:9444', 'upstream':'https://127.0.0.1:9445',
 'server_cert':'/etc/turansec/server.pem', 'server_key':'/etc/turansec/server.key',
 'server_ca':'/etc/turansec/server-ca.pem',
 'operator_dir':'/etc/turansec/operators', 'users_file':'/etc/turansec/users.json',
 'payload_dir':'/opt/turansec/payloads'
}
(root/'runtime/gateway.json').write_text(json.dumps(gateway,indent=2)+'\n')
os.chmod(root/'runtime/gateway.json',0o600)
PY
if [[ "$mode" == --upgrade ]]; then
  if [[ -f .env ]]; then
    new_sha="$(git rev-parse HEAD)"
    sed -i "s/^EDR_SOURCE_SHA=.*/EDR_SOURCE_SHA=$new_sha/" .env
  fi
  command -v docker >/dev/null || { echo "Docker missing: cannot register new operators" >&2; exit 1; }
  docker compose exec -T database psql -X -v ON_ERROR_STOP=1 -U postgres -d edr \
    -v admin_fp="$(cat "$root/fingerprints/admin.sha256")" \
    -v viewer_fp="$(cat "$root/fingerprints/viewer-login.sha256")" <<'SQL'
BEGIN;
INSERT INTO edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role)
VALUES ('lab','admin',decode(:'admin_fp','hex'),'scanner'),
       ('lab','viewer',decode(:'viewer_fp','hex'),'viewer')
ON CONFLICT DO NOTHING;
SELECT 1 / CASE WHEN
 (SELECT encode(fingerprint_sha256,'hex') FROM edr_soc_operators
    WHERE tenant_id='lab' AND operator_id='admin')=:'admin_fp'
 AND
 (SELECT encode(fingerprint_sha256,'hex') FROM edr_soc_operators
    WHERE tenant_id='lab' AND operator_id='viewer')=:'viewer_fp'
 THEN 1 ELSE 0 END;

COMMIT;
SQL
fi
echo "Password login prepared: admin, analyst, viewer."
echo "Read newly generated credentials locally at .docker-local/operator/passwords.txt"
echo "Never upload the password file or your local CA private keys."
