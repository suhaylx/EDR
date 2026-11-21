#!/usr/bin/env python3
"""Local disposable functional fixture for the actual compiled SOC API client."""
from pathlib import Path
import importlib.util
import json
import os
import secrets
import subprocess
import tempfile
import time

ROOT = Path(os.environ['QA_EDR_SOURCE'])
QA = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate_fixture_helpers', ROOT / 'scripts/test-integrated-candidate.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
h.dburl = os.environ['EDR_TEST_DATABASE_URL']

def main():
    for migration in sorted((ROOT / 'backend/migrations').glob('*.up.sql')):
        h.command(['psql', h.dburl, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-f', str(migration)])
    passwords = {name: secrets.token_hex(24) for name in ['runtime', 'registry']}
    for name, password in passwords.items():
        h.sql('CREATE ROLE qa_client_' + name + ' LOGIN INHERIT PASSWORD ' + h.q(password))
    h.command(['psql', h.dburl, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-v', 'runtime_login=qa_client_runtime',
               '-v', 'registry_login=qa_client_registry', '-v', 'dedicated_edr_database=true',
               '-f', str(ROOT / 'backend/bootstrap/runtime_privileges.sql')])
    with tempfile.TemporaryDirectory(prefix='edr-functional-client-') as temporary:
        p = Path(temporary)
        h.server_ca = h.key_cert(p, 'server-ca')
        agent_ca, operator_ca = h.key_cert(p, 'agent-ca'), h.key_cert(p, 'operator-ca')
        server = h.key_cert(p, 'server', ca=h.server_ca, san='IP:127.0.0.1', server=True)
        endpoint = h.key_cert(p, 'endpoint', ca=agent_ca, san='URI:spiffe://turansec.local/tenants/qa-functional/agents/linux.01')
        operator = h.key_cert(p, 'operator', ca=operator_ca, san='URI:spiffe://turansec.local/tenants/qa-functional/operators/analyst')
        h.sql("INSERT INTO edr_tenants(tenant_id,display_name) VALUES('qa-functional','Functional fixture');"
              "INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES('qa-functional','linux.01','linux');"
              "INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after) VALUES"
              "('qa-functional','linux.01',decode(" + h.q(h.fingerprint(endpoint[0])) + ",'hex'),now()-interval '1minute',now()+interval '1hour');"
              "INSERT INTO edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role) VALUES"
              "('qa-functional','analyst',decode(" + h.q(h.fingerprint(operator[0])) + ",'hex'),'scanner');")
        for name, password in passwords.items():
            path = p / (name + '.dsn')
            path.write_text('postgresql://qa_client_' + name + ':' + password + '@127.0.0.1:55439/edr_qa_soc_client?sslmode=disable')
            path.chmod(0o600)
        ui = p / 'web'; ui.mkdir(); (ui / 'index.html').write_text('<main>Functional API fixture; browser not exercised</main>')
        agent_port, soc_port = h.port(), h.port()
        config = {'agent_listen': f'127.0.0.1:{agent_port}', 'soc_listen': f'127.0.0.1:{soc_port}',
                  'server_cert_file': str(server[0]), 'server_key_file': str(server[1]),
                  'agent_ca_file': str(agent_ca[0]), 'operator_ca_file': str(operator_ca[0]),
                  'registry_dsn_file': str(p / 'registry.dsn'), 'runtime_dsn_file': str(p / 'runtime.dsn'), 'ui_dir': str(ui)}
        config_path = p / 'edrd.json'; config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
        env = dict(os.environ); env.pop('EDR_SOC_UI_DIR', None)
        with (p / 'private-service.log').open('w') as log:
            service = subprocess.Popen([str(QA / 'build/edrd'), '--config', str(config_path)], env=env, stdout=log, stderr=log)
            try:
                soc, agent = h.context(operator), h.context(endpoint)
                for _ in range(80):
                    if service.poll() is not None: raise RuntimeError('Functional service failed to start')
                    try:
                        h.request(soc, soc_port, 'GET', '/soc/v1/session'); break
                    except (OSError, ConnectionRefusedError): time.sleep(.05)
                else: raise RuntimeError('Functional service did not become ready')
                sample = p / 'benign.txt'; sample.write_text('benign functional fixture')
                base = '/soc/v1/tenants/qa-functional/'
                h.request(soc, soc_port, 'POST', base + 'scan-jobs',
                          {'agent_id': 'linux.01', 'request_id': 'qa-synthetic-seed', 'scan_root': str(sample)}, status=201)
                agent_base = '/agent/v1/tenants/qa-functional/agents/linux.01/'
                claim = h.request(agent, agent_port, 'POST', agent_base + 'scan-jobs/claim')
                h.request(agent, agent_port, 'POST', agent_base + 'scan-jobs/complete-result',
                          {'job_id': claim['job_id'], 'lease_token': claim['lease_token'], 'verdict': 'malicious',
                           'threat_name': 'FunctionalFixture.Signature', 'detail': 'Synthetic workflow seed; not a scanner detection'}, status=204)
                fixture = {'origin': f'https://127.0.0.1:{soc_port}', 'ca': str(h.server_ca[0]),
                           'cert': str(operator[0]), 'key': str(operator[1]), 'sample': str(sample)}
                fixture_path = p / 'node-fixture.json'; fixture_path.write_text(json.dumps(fixture)); fixture_path.chmod(0o600)
                client_env = dict(os.environ, QA_SOC_FIXTURE=str(fixture_path), QA_SOC_COMPILED=str(QA / 'soc-client/compiled'))
                result = subprocess.run(['node', str(QA / 'check_soc_client.mjs')], env=client_env, timeout=90)
                if result.returncode: raise RuntimeError('Compiled SOC client functional checks failed')
                assert h.sql("SELECT count(*) FROM edr_scan_jobs WHERE tenant_id='qa-functional'") == '2'
                assert h.sql("SELECT state FROM edr_scan_jobs WHERE tenant_id='qa-functional' AND request_key<>'qa-synthetic-seed'") == 'cancelled'
                print('PASS: independent administrator read confirms exactly two persisted jobs and the new job cancelled')
            finally:
                service.terminate()
                try: service.wait(timeout=12)
                except subprocess.TimeoutExpired: service.kill(); service.wait()
                if service.returncode != 0: raise RuntimeError('Functional service did not stop cleanly')
    print('LIMIT: synthetic detection seed; no real scanner, browser, service-manager or deployment-host acceptance')

if __name__ == '__main__':
    os.umask(0o077)
    main()
