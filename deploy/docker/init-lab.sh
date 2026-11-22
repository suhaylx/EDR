#!/usr/bin/env bash
# Initialize a NEW, disposable local-only Docker lab. Not a production issuer.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/../.."
command -v openssl >/dev/null || { echo "Install openssl first" >&2; exit 1; }
command -v git >/dev/null || { echo "Install git first" >&2; exit 1; }
test ! -e .docker-local && test ! -e .env || {
  echo "Existing lab configuration detected; refusing to replace credentials" >&2; exit 1;
}
mkdir -p .docker-local/private .docker-local/operator .docker-local/runtime .docker-local/fingerprints
root="$PWD/.docker-local"
# These local seven-day CAs are intentionally NOT enterprise PKI.
issue_ca() {
  local kind="$1"
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 7 \
    -subj "/CN=TuranSec disposable ${kind} CA" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$root/private/${kind}-ca.key" \
    -out "$root/private/${kind}-ca.pem" >/dev/null 2>&1
}
issue_leaf() {
  local name="$1" issuer="$2" usage="$3" san="$4"
  openssl req -new -newkey rsa:3072 -nodes -sha256 \
    -subj "/CN=TuranSec local ${name}" \
    -keyout "$root/private/${name}.key" \
    -out "$root/private/${name}.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$usage" "$san" > "$root/private/${name}.ext"
  openssl x509 -req -in "$root/private/${name}.csr" \
    -CA "$root/private/${issuer}-ca.pem" -CAkey "$root/private/${issuer}-ca.key" \
    -CAcreateserial -days 7 -sha256 -extfile "$root/private/${name}.ext" \
    -out "$root/private/${name}.pem" >/dev/null 2>&1
}
issue_ca server
issue_ca operator
issue_ca agent
issue_leaf server server serverAuth IP:127.0.0.1
issue_leaf analyst operator clientAuth URI:spiffe://turansec.local/tenants/lab/operators/analyst
issue_leaf viewer operator clientAuth URI:spiffe://turansec.local/tenants/lab/operators/health-viewer
cp "$root/private/server.pem" "$root/runtime/server.pem"
cp "$root/private/server.key" "$root/runtime/server.key"
cp "$root/private/agent-ca.pem" "$root/runtime/agent-ca.pem"
cp "$root/private/operator-ca.pem" "$root/runtime/operator-ca.pem"
cp "$root/private/server-ca.pem" "$root/operator/server-ca.pem"
for kind in analyst viewer; do
  cp "$root/private/${kind}.pem" "$root/operator/${kind}.pem"
  cp "$root/private/${kind}.key" "$root/operator/${kind}.key"
  openssl x509 -in "$root/operator/${kind}.pem" -outform DER |
    openssl dgst -sha256 -r | awk '{print $1}' > "$root/fingerprints/${kind}.sha256"
done
chmod 755 "$root/fingerprints"
chmod 644 "$root/fingerprints/"*.sha256
pw="$(openssl rand -hex 32)"
rt="$(openssl rand -hex 32)"
ro="$(openssl rand -hex 32)"
{
 printf 'POSTGRES_PASSWORD=%s\n' "$pw"
 printf 'EDR_RUNTIME_PASSWORD=%s\n' "$rt"
 printf 'EDR_REGISTRY_PASSWORD=%s\n' "$ro"
} > "$root/postgres.env"
printf 'postgresql://edr_service_runtime:%s@127.0.0.1:55432/edr?sslmode=disable\n' "$rt" > "$root/runtime/runtime.dsn"
printf 'postgresql://edr_service_registry:%s@127.0.0.1:55432/edr?sslmode=disable\n' "$ro" > "$root/runtime/registry.dsn"
cat > "$root/runtime/edrd.json" <<'JSON'
{
  "agent_listen": "127.0.0.1:9443",
  "soc_listen": "127.0.0.1:9444",
  "server_cert_file": "/etc/turansec/server.pem",
  "server_key_file": "/etc/turansec/server.key",
  "agent_ca_file": "/etc/turansec/agent-ca.pem",
  "operator_ca_file": "/etc/turansec/operator-ca.pem",
  "registry_dsn_file": "/etc/turansec/registry.dsn",
  "runtime_dsn_file": "/etc/turansec/runtime.dsn",
  "ui_dir": "/opt/turansec/web"
}
JSON
{
 printf 'EDR_SOURCE_SHA=%s\n' "$(git rev-parse HEAD)"
 printf 'EDR_HOST_UID=%s\n' "$(id -u)"
 printf 'EDR_HOST_GID=%s\n' "$(id -g)"
} > .env
openssl rand -hex 16 > "$root/operator/p12-password.txt"
openssl pkcs12 -export -inkey "$root/operator/analyst.key" \
  -in "$root/operator/analyst.pem" -certfile "$root/private/operator-ca.pem" \
  -out "$root/operator/analyst.p12" -passout "file:$root/operator/p12-password.txt" >/dev/null 2>&1
chmod 600 .env "$root/postgres.env" "$root/runtime/"* "$root/operator/"* "$root/private/"*
bash deploy/docker/provision-passwords.sh --fresh
echo "Open the HTTPS dashboard with admin, analyst or viewer username/password."
echo "Read credentials at .docker-local/operator/passwords.txt (owner-only)."
echo "These temporary identities are NOT approved production credentials."
