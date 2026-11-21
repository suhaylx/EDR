#!/usr/bin/env python3
"""Actual Go/PostgreSQL/Rust/React-assets integration; no browser/host claim.

All certificates/passwords are ephemeral fixtures in a private temporary dir.
This script never writes them or HTTP lease bodies to its evidence report.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit, quote

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / '.quality-evidence/integrated-candidate.json'
checks = []
source_sha = os.environ.get('EDR_CANDIDATE_SHA', '')

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def command(args, *, data=None, env=None, cwd=None):
    result = subprocess.run(args, input=data, env=env, cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        # Never echo command arguments, database DSNs, private PEM or SQL errors.
        raise RuntimeError('Required subprocess failed: ' + Path(args[0]).name)
    return result.stdout

def sql(statement):
    return command(['psql', dburl, '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1'], data=statement).strip()

def q(value):
    return "'" + str(value).replace("'", "''") + "'"

def mark(description):
    checks.append({'check': description, 'status': 'PASS'})

def key_cert(directory, name, *, ca=None, san=None, server=False):
    key, cert = directory / (name + '.key'), directory / (name + '.pem')
    base = ['openssl', 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(key), '-subj', '/CN=TuranSec-ephemeral-integration-' + name]
    if ca is None:
        command(base + ['-x509', '-days', '1', '-sha256', '-out', str(cert),
                       '-addext', 'basicConstraints=critical,CA:TRUE',
                       '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    else:
        csr, ext = directory / (name + '.csr'), directory / (name + '.ext')
        command(base + ['-out', str(csr)])
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                       'extendedKeyUsage=' + ('serverAuth' if server else 'clientAuth') +
                       '\nsubjectAltName=' + san + '\n')
        command(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca[0]), '-CAkey', str(ca[1]),
                 '-CAcreateserial', '-days', '1', '-sha256', '-extfile', str(ext), '-out', str(cert)])
    key.chmod(0o600)
    return cert, key

def fingerprint(cert):
    result = subprocess.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return hashlib.sha256(result.stdout).hexdigest()

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def context(cert=None, *, tls12=False):
    ctx = ssl.create_default_context(cafile=str(server_ca[0]))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
    if tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if cert:
        ctx.load_cert_chain(str(cert[0]), str(cert[1]))
    return ctx

def request(ctx, listener, method, path, payload=None, *, status=200, headers=None, connection=None):
    conn = connection or http.client.HTTPSConnection('127.0.0.1', listener, context=ctx, timeout=8)
    body = None if payload is None else json.dumps(payload).encode()
    hs = {'Content-Type': 'application/json'} if payload is not None else {}
    hs.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=hs)
        response = conn.getresponse()
        data = response.read(1048577)
        require(response.status == status, f'{method} {path}: unexpected HTTP {response.status}, expected {status}')
        require(len(data) <= 1048576, 'oversized integration response')
        require(response.getheader('Cache-Control') == 'no-store', 'missing no-store boundary')
        if response.getheader('Content-Type', '').startswith('application/json') and data:
            return json.loads(data)
        return data
    finally:
        if connection is None:
            conn.close()

def denied_tls(ctx, listener, path):
    try:
        request(ctx, listener, 'GET', path)
    except (ssl.SSLError, ConnectionResetError, http.client.RemoteDisconnected):
        return
    raise RuntimeError('TLS boundary accepted an invalid peer/protocol')

def run():
    global dburl, server_ca
    dburl = os.environ.get('EDR_TEST_DATABASE_URL', '')
    u = urlsplit(dburl)
    require(os.environ.get('EDR_QA_DISPOSABLE_DB') == 'yes' and
            u.scheme == 'postgresql' and u.hostname == '127.0.0.1' and u.port == 5432 and
            u.path == '/edr_integrated_test' and bool(u.username) and
            u.query in ('', 'sslmode=disable') and not u.fragment,
            'refusing a nonlocal or nondisposable integration database')
    require(sql("SELECT count(*) FROM pg_class WHERE relname LIKE 'edr_%' AND relkind='r'") == '0',
            'integration database is not empty')
    for migration in sorted((ROOT / 'backend/migrations').glob('*.up.sql')):
        command(['psql', dburl, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-f', str(migration)])
    runtime_pw, registry_pw = secrets.token_hex(24), secrets.token_hex(24)
    sql('CREATE ROLE edr_integrated_runtime LOGIN INHERIT PASSWORD ' + q(runtime_pw) + ';'
        'CREATE ROLE edr_integrated_registry LOGIN INHERIT PASSWORD ' + q(registry_pw) + ';')
    command(['psql', dburl, '-X', '-q', '-v', 'ON_ERROR_STOP=1',
             '-v', 'runtime_login=edr_integrated_runtime', '-v', 'registry_login=edr_integrated_registry',
             '-v', 'dedicated_edr_database=true', '-f', str(ROOT / 'backend/bootstrap/runtime_privileges.sql')])
    mark('Migrations and reviewed bootstrap applied to an empty disposable PostgreSQL database')
    with tempfile.TemporaryDirectory(prefix='turansec-integration-') as tmp:
        p = Path(tmp)
        p.chmod(0o700)
        server_ca = key_cert(p, 'server-ca')
        agent_ca, operator_ca = key_cert(p, 'agent-ca'), key_cert(p, 'operator-ca')
        server_cert = key_cert(p, 'server', ca=server_ca, san='IP:127.0.0.1', server=True)
        agent_cert = key_cert(p, 'agent', ca=agent_ca, san='URI:spiffe://turansec.local/tenants/e2e-a/agents/linux01')
        unregistered = key_cert(p, 'unregistered', ca=agent_ca, san='URI:spiffe://turansec.local/tenants/e2e-a/agents/linux01')
        operator = key_cert(p, 'operator', ca=operator_ca, san='URI:spiffe://turansec.local/tenants/e2e-a/operators/analyst')
        viewer = key_cert(p, 'viewer', ca=operator_ca, san='URI:spiffe://turansec.local/tenants/e2e-a/operators/viewer')
        sql("INSERT INTO edr_tenants VALUES ('e2e-a','Integration A',now(),NULL,false),('e2e-b','Integration B',now(),NULL,false);"
            "INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES ('e2e-a','linux01','linux'),('e2e-a','unseen01','windows'),('e2e-b','linux01','linux');"
            "INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after) VALUES "
            "('e2e-a','linux01',decode(" + q(fingerprint(agent_cert[0])) + ",'hex'),now()-interval '1 minute',now()+interval '1 hour');"
            "INSERT INTO edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role) VALUES "
            "('e2e-a','analyst',decode(" + q(fingerprint(operator[0])) + ",'hex'),'scanner'),"
            "('e2e-a','viewer',decode(" + q(fingerprint(viewer[0])) + ",'hex'),'viewer');")
        for role, password in [('runtime', runtime_pw), ('registry', registry_pw)]:
            (p / (role + '.dsn')).write_text('postgresql://edr_integrated_' + role + ':' + password +
                                          '@127.0.0.1:5432/edr_integrated_test?sslmode=disable')
            (p / (role + '.dsn')).chmod(0o600)
        agent_port, soc_port = port(), port()
        cfg = {'agent_listen': f'127.0.0.1:{agent_port}', 'soc_listen': f'127.0.0.1:{soc_port}',
               'server_cert_file': str(server_cert[0]), 'server_key_file': str(server_cert[1]),
               'agent_ca_file': str(agent_ca[0]), 'operator_ca_file': str(operator_ca[0]),
               'registry_dsn_file': str(p / 'registry.dsn'), 'runtime_dsn_file': str(p / 'runtime.dsn'),
               'ui_dir': str(ROOT / 'frontend/dist')}
        (p / 'config.json').write_text(json.dumps(cfg)); (p / 'config.json').chmod(0o600)
        child_env = dict(os.environ); child_env.pop('EDR_SOC_UI_DIR', None)
        with (p / 'server.log').open('w+') as log:
            service = subprocess.Popen([str(ROOT / 'build/edrd'), '--config', str(p / 'config.json')], env=child_env, stdout=log, stderr=log)
            try:
                soc, endpoint, view = context(operator), context(agent_cert), context(viewer)
                for _ in range(80):
                    if service.poll() is not None:
                        raise RuntimeError('edrd failed startup; inspect private fixture log during diagnosis')
                    try:
                        session = request(soc, soc_port, 'GET', '/soc/v1/session'); break
                    except (ConnectionRefusedError, OSError):
                        time.sleep(0.05)
                else:
                    raise RuntimeError('edrd did not become ready')
                require(session['tenant_id'] == 'e2e-a' and session['role'] == 'scanner', 'session identity mismatch')
                mark('Compiled edrd serves separate TLS1.3 listeners with actual registry/runtime logins')
                root_page = request(soc, soc_port, 'GET', '/')
                require(b'type="module"' in root_page, 'built React entry point not served')
                asset = re.search(rb'src="(/assets/[^"<>]+)"', root_page)
                require(asset is not None, 'built React asset reference missing')
                require(len(request(soc, soc_port, 'GET', asset.group(1).decode())) > 1000, 'React bundle not served')
                for path in ['/lab/', '/api/overview', '/private.json']:
                    request(soc, soc_port, 'GET', path, status=404)
                mark('Built original React SOC assets served on authenticated origin; lab/API fallback denied')
                denied_tls(context(), soc_port, '/')
                denied_tls(context(operator, tls12=True), soc_port, '/')
                denied_tls(context(operator), agent_port, '/agent/v1/tenants/e2e-a/agents/linux01/heartbeat')
                request(context(unregistered), agent_port, 'GET', '/agent/v1/tenants/e2e-a/agents/linux01/heartbeat', status=401)
                request(soc, soc_port, 'GET', '/soc/v1/tenants/e2e-b/endpoints', status=403)
                request(soc, soc_port, 'GET', '/soc/v1/session', status=403, headers={'Origin':'https://untrusted.invalid'})
                mark('Missing/wrong CA, TLS1.2, unregistered leaf, cross-tenant and cross-origin requests denied')
                env = dict(os.environ)
                env.update({'TURANSEC_MTLS_ORIGIN': f'https://127.0.0.1:{agent_port}',
                            'TURANSEC_MTLS_TENANT_ID': 'e2e-a', 'TURANSEC_MTLS_AGENT_ID': 'linux01',
                            'TURANSEC_MTLS_CA_PEM': str(server_ca[0]), 'TURANSEC_MTLS_CERT_PEM': str(agent_cert[0]),
                            'TURANSEC_MTLS_KEY_PEM': str(agent_cert[1])})
                rust = ROOT / 'agent/target/debug/turansec-edr-agent'
                if os.name == 'nt': rust = rust.with_suffix('.exe')
                command([str(rust), '--heartbeat-mtls'], env=env)
                command([str(rust), '--agent-status-mtls'], env=env)
                fleet = request(soc, soc_port, 'GET', '/soc/v1/tenants/e2e-a/endpoints')
                require(len(fleet['items']) == 2, 'cross-tenant inventory isolation failed')
                states = {e['agent_id']: e['health'] for e in fleet['items']}
                require(states['linux01'] == 'degraded' and states['unseen01'] == 'unseen', 'unavailable scanner or unseen host falsely healthy')
                mark('Real Rust mTLS heartbeat persisted and SOC shows degraded/unseen with tenant isolation')
                api = '/agent/v1/tenants/e2e-a/agents/linux01/'
                before = sql("SELECT received_count FROM edr_agent_heartbeats WHERE tenant_id='e2e-a'")
                for text in ['v1\u061c', 'v1\ufffd', 'v1\ufeff', '   ']:
                    request(endpoint, agent_port, 'POST', api+'heartbeat', {'platform':'linux','agent_version':text,'scan_ready':False},status=400)
                require(sql("SELECT received_count FROM edr_agent_heartbeats WHERE tenant_id='e2e-a'") == before, 'rejected heartbeat mutated stored status')
                mark('Malformed/display-poisoning heartbeat denied before PostgreSQL mutation')
                scan_root = p / 'scan'; scan_root.mkdir(mode=0o700)
                sample = scan_root / 'benign.txt'; sample.write_text('benign integration fixture')
                env['TURANSEC_LAB_SCAN_ROOT'] = str(scan_root)
                job_url = '/soc/v1/tenants/e2e-a/scan-jobs'
                request(view, soc_port, 'POST', job_url, {'agent_id':'linux01','request_id':'denied','scan_root':str(sample)},status=403)
                request(soc, soc_port, 'POST', job_url, {'agent_id':'linux01','request_id':'rust-e2e-1','scan_root':str(sample)},status=201)
                out = command([str(rust), '--scan-once-mtls'], env=env)
                require('classification=error' in out, 'absent scanner not represented as error')
                require(sql("SELECT verdict FROM edr_scan_job_results WHERE tenant_id='e2e-a'") == 'error', 'Rust scan result not persisted')
                mark('Real Rust claim/renew/error-result lifecycle persisted; absent clamd never reported clean')
                # Synthetic malware outcome tests storage/alert plumbing only. It is
                # deliberately not an EICAR/ClamAV detection or native-host pass.
                request(soc, soc_port, 'POST', job_url, {'agent_id':'linux01','request_id':'synthetic-e2e-2','scan_root':str(sample)},status=201)
                claim = request(endpoint, agent_port, 'POST', api+'scan-jobs/claim')
                result = {'job_id':claim['job_id'],'lease_token':claim['lease_token'],'verdict':'malicious',
                          'threat_name':'IntegrationFixture.Signature','detail':'Synthetic integration fixture; not a scanner detection'}
                request(endpoint, agent_port, 'POST', api+'scan-jobs/complete-result',result,status=204)
                request(endpoint, agent_port, 'POST', api+'scan-jobs/complete-result',result,status=409)
                alerts = request(soc, soc_port, 'GET', '/soc/v1/tenants/e2e-a/alerts')
                require(len(alerts['items'])==1, 'synthetic result/alert transaction failed')
                alert = alerts['items'][0]['alert_id']; alert_url='/soc/v1/tenants/e2e-a/alerts/'+alert
                request(soc,soc_port,'POST',alert_url+'/assign',{'operator_id':'analyst'},status=204)
                request(soc,soc_port,'POST',alert_url+'/notes',{'note':'Synthetic fixture reviewed'},status=201)
                request(soc,soc_port,'POST',alert_url+'/ack',status=204)
                activity=request(soc,soc_port,'GET',alert_url+'/activity')
                require(len(activity['items'])>=4,'append-only alert activity missing')
                mark('Synthetic result→alert→assignment/note/ack uses constrained DB functions; result replay denied')
                agent_connection=http.client.HTTPSConnection('127.0.0.1',agent_port,context=endpoint,timeout=8)
                request(endpoint,agent_port,'GET',api+'heartbeat',connection=agent_connection)
                sql("UPDATE edr_agent_certificates SET revoked_at=now(),revoke_reason='integration fixture' WHERE tenant_id='e2e-a'")
                request(endpoint,agent_port,'GET',api+'heartbeat',status=401,connection=agent_connection);agent_connection.close()
                operator_connection=http.client.HTTPSConnection('127.0.0.1',soc_port,context=soc,timeout=8)
                request(soc,soc_port,'GET','/soc/v1/session',connection=operator_connection)
                sql("UPDATE edr_soc_operators SET revoked_at=now() WHERE tenant_id='e2e-a' AND operator_id='analyst'")
                request(soc,soc_port,'GET','/soc/v1/session',status=401,connection=operator_connection);operator_connection.close()
                mark('Persisted agent/operator revocation enforced on reused authenticated TLS connections')
            finally:
                service.terminate()
                try: service.wait(timeout=12)
                except subprocess.TimeoutExpired: service.kill(); service.wait()
                require(service.returncode == 0, 'service did not shut down cleanly')
    mark('Service shutdown completed and ephemeral PKI/password files removed')

if __name__ == '__main__':
    os.umask(0o077)
    status, error = 'PASS', None
    try:
        run()
    except Exception as exc:
        status = 'FAIL'
        error = str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    REPORT.write_text(json.dumps({'status':status,'source_sha':source_sha,'checks':checks,'error':error,
       'limits':['Disposable local execution; not GitHub CI','React assets verified; browser accessibility not executed',
                 'No native Windows/Linux deployment-host acceptance','No real ClamAV/EICAR detection; explicit error and synthetic-result fixtures',
                 'No release signature or deployment authorization']},indent=2)+'\n')
    print(json.dumps({'status':status,'checks_passed':len(checks),'error':error,'report':str(REPORT)}))
    raise SystemExit(0 if status=='PASS' else 1)
