#!/usr/bin/env python3
"""Collect bounded native-host evidence. Never install, restart, or deploy.

Optional active checks scan only a fixed benign fixture and the exact official
68-byte EICAR file. No raw process events, key contents, DSNs or tokens are saved.
This collector cannot grant release approval or infer an automatic rollback.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit

EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
CHECKS = []

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def check(name, status, detail, **evidence):
    CHECKS.append(dict(name=name, status=status, detail=detail, **evidence))

def run(argv, *, env=None, timeout=45):
    try:
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout[:65536], p.stderr[:65536]
    except (OSError, subprocess.TimeoutExpired):
        return -1, '', ''

def package_check(a):
    if not a.manifest or not a.package_root:
        check('candidate_files', 'NOT_RUN', 'Provide manifest and package root'); return
    data=json.loads(a.manifest.read_text(encoding='utf-8'))
    if data.get('schema')!=1 or data.get('source_sha')!=a.candidate_sha:
        check('candidate_files','FAIL','Manifest candidate identity mismatch');return
    root=a.package_root.resolve(strict=True)
    paths=set(); failures=[]; measured={}
    for item in data.get('files',[]):
        name=item.get('path','');rel=Path(name)
        if not name or rel.is_absolute() or '..' in rel.parts or '\\' in name or name in paths:
            failures.append('invalid manifest path');continue
        paths.add(name);p=root/rel
        if p.is_symlink() or not p.is_file() or root not in p.resolve().parents:
            failures.append('missing or escaping artifact');continue
        digest=sha(p);measured[name]=digest
        if digest!=item.get('sha256') or p.stat().st_size!=item.get('size'):
            failures.append('artifact hash or size mismatch')
    if not paths or not any(name.startswith('bin/turansec-edr-agent') for name in paths):
        failures.append('agent missing from manifest')
    check('candidate_files','FAIL' if failures else 'PASS',
          'Artifact bytes compared to manifest; signature is a separate check',
          manifest_sha256=sha(a.manifest),file_hashes=measured,mismatches=len(failures))
    if not a.manifest_signature or not a.trusted_release_key:
        check('release_signature','NOT_RUN','An independently provisioned release public key and detached signature are required');return
    if root==a.trusted_release_key.resolve() or root in a.trusted_release_key.resolve().parents:
        check('release_signature','FAIL','Trust root must be provisioned outside the downloaded package');return
    rc,_,_=run(['openssl','dgst','-sha256','-verify',str(a.trusted_release_key),
                '-signature',str(a.manifest_signature),str(a.manifest)])
    check('release_signature','PASS' if rc==0 else 'FAIL','Detached manifest signature verification',
          signature_sha256=sha(a.manifest_signature),trusted_key_file_sha256=sha(a.trusted_release_key))
    if platform.system()=='Windows':
        thumb=data.get('windows_publisher_thumbprint')
        if not isinstance(thumb,str) or not re.fullmatch('[A-Fa-f0-9]{40,64}',thumb):
            check('authenticode','NOT_RUN','Manifest lacks an approved Windows publisher');return
        shell=shutil.which('pwsh') or shutil.which('powershell')
        good=bool(shell)
        for name in paths:
            if name.startswith('bin/') and name.endswith('.exe') and shell:
                env=os.environ.copy();env['EDR_VERIFY_FILE']=str(root/name);env['EDR_EXPECTED_PUBLISHER']=thumb
                rc,_,_=run([shell,'-NoProfile','-NonInteractive','-Command',
                    "$s=Get-AuthenticodeSignature -LiteralPath $env:EDR_VERIFY_FILE; "
                    "if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $env:EDR_EXPECTED_PUBLISHER){exit 2}"],env=env)
                good=good and rc==0
        check('authenticode','PASS' if good else 'FAIL','Native publisher/certificate verification for packaged executables')

def api_check(a):
    values=[a.soc_origin,a.server_ca,a.operator_cert,a.operator_key]
    if not all(values):
        check('operator_mtls','NOT_RUN','Provide operator origin and protected certificate file paths');return
    u=urlsplit(a.soc_origin)
    if u.scheme!='https' or u.hostname not in ('127.0.0.1','::1') or not u.port or u.path not in ('','/') or u.query or u.fragment or u.username:
        check('operator_mtls','FAIL','Only a bare explicit HTTPS loopback origin is accepted');return
    ctx=ssl.create_default_context(cafile=str(a.server_ca));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(a.operator_cert),str(a.operator_key))
    conn=http.client.HTTPSConnection(u.hostname,u.port,context=ctx,timeout=8)
    try:
        conn.request('GET','/soc/v1/session',headers={'X-Tenant-ID':'forged-tenant','X-Operator-Role':'admin'})
        r=conn.getresponse();body=r.read(8193)
        good=r.status==200 and r.getheader('Cache-Control')=='no-store' and len(body)<=8192
        data=json.loads(body) if good else {}
        good=good and data.get('role') in ('viewer','scanner') and data.get('tenant_id')!='forged-tenant'
        check('operator_mtls','PASS' if good else 'FAIL','TLS1.3 session, registered operator and no-store response')
        if good:
            wrong='qa-denied-tenant' if data['tenant_id']!='qa-denied-tenant' else 'qa-other-tenant'
            conn.request('GET','/soc/v1/tenants/'+wrong+'/endpoints');r=conn.getresponse();r.read(65537)
            check('wrong_tenant','PASS' if r.status==403 else 'FAIL','Certificate tenant cannot read a different route tenant')
            conn.request('GET','/soc/v1/session',headers={'Origin':'https://untrusted.invalid'});r=conn.getresponse();r.read(8193)
            check('cross_origin','PASS' if r.status==403 else 'FAIL','Cross-origin ambient-client-certificate request denied')
    except (OSError,ValueError,http.client.HTTPException):
        check('operator_mtls','FAIL','Authenticated session could not be verified; no response body recorded')
    finally:conn.close()
    no_cert=ssl.create_default_context(cafile=str(a.server_ca));no_cert.minimum_version=ssl.TLSVersion.TLSv1_3
    denied=False;c=http.client.HTTPSConnection(u.hostname,u.port,context=no_cert,timeout=8)
    try:c.request('GET','/soc/v1/session');c.getresponse().read(8193)
    except (ssl.SSLError,ConnectionResetError,http.client.RemoteDisconnected):denied=True
    except OSError:pass
    finally:c.close()
    check('missing_client_certificate','PASS' if denied else 'FAIL','TLS peer without client identity denied')

def scanner_check(a):
    if not a.exercise_scanner:
        check('real_scanner','NOT_RUN','Explicit --exercise-scanner performs benign/EICAR-only scans');return
    if a.lab_confirmation!='isolated-lab' or not all([a.clamscan,a.sigtool,a.database_dir,a.cvd_certs_dir,a.eicar_file]):
        check('real_scanner','NOT_RUN','Missing isolated-lab confirmation or verified scanner/database/EICAR paths');return
    if not a.eicar_file.is_file() or a.eicar_file.stat().st_size!=68 or sha(a.eicar_file)!=EICAR_SHA256:
        check('eicar_fixture','FAIL','Refusing any file except the exact official 68-byte EICAR fixture');return
    env=os.environ.copy();env['CVD_CERTS_DIR']=str(a.cvd_certs_dir.resolve())
    rc,out,_=run([str(a.clamscan),'--version'],env=env)
    version=out.strip() if rc==0 and re.fullmatch(r'ClamAV [A-Za-z0-9. /:+-]{1,160}',out.strip()) else 'unavailable'
    check('scanner_binary','PASS' if version!='unavailable' else 'FAIL','Real scanner executable identity observed',
          version=version,clamscan_sha256=sha(a.clamscan),sigtool_sha256=sha(a.sigtool))
    db_complete=True
    for name in ('main','daily','bytecode'):
        choices=[a.database_dir/(name+'.cvd'),a.database_dir/(name+'.cld')]
        file=next((p for p in choices if p.is_file()),None)
        if file is None:
            check('database_'+name,'NOT_RUN','Required official database missing');db_complete=False;continue
        rc,out,err=run([str(a.sigtool),'--info='+str(file),'--cvdcertsdir='+str(a.cvd_certs_dir)],env=env)
        valid=rc==0 and 'Verification OK' in out+err
        fields={key:match.group(1) for key in ('Version','Signatures','Build time')
                if (match:=re.search(r'^'+re.escape(key)+r': (.{1,120})$',out,re.M))}
        check('database_'+name,'PASS' if valid else 'FAIL','Official CVD cryptographic verification',
              sha256=sha(file),metadata=fields)
        db_complete=db_complete and valid
    # Do not convert an incomplete database installation into an engine-health pass.
    check('complete_signature_set','PASS' if db_complete else 'FAIL','main, daily and bytecode must each verify')
    with tempfile.TemporaryDirectory(prefix='turansec-benign-scan-') as tmp:
        benign=Path(tmp)/'benign.txt';benign.write_text('TuranSec harmless acceptance fixture\n',encoding='utf-8')
        for label,file,expected in [('benign_signature_scan',benign,0),('eicar_signature_scan',a.eicar_file,1)]:
            rc,out,_=run([str(a.clamscan),'--official-db-only=yes','--no-summary',
                         '--database='+str(a.database_dir),'--cvdcertsdir='+str(a.cvd_certs_dir),str(file)],env=env,timeout=180)
            good=rc==expected and (label!='eicar_signature_scan' or bool(re.search(r'EICAR[^\r\n]* FOUND',out,re.I)))
            check(label,'PASS' if good else 'FAIL','Direct scanner fixture result; not Rust/daemon/backend integration',
                  exit_code=rc,database_complete=db_complete)

def service_check(a):
    if not a.service:
        check('service_snapshot','NOT_RUN','No installed service selected');return
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,96}',a.service):
        check('service_snapshot','FAIL','Invalid service identifier');return
    if platform.system()=='Linux':
        rc,out,_=run(['systemctl','show',a.service,'--property=ActiveState,SubState,MainPID,ExecMainStartTimestamp,InvocationID'])
        values=dict(line.split('=',1) for line in out.splitlines() if '=' in line)
        check('service_snapshot','OBSERVED' if rc==0 else 'NOT_RUN','Read-only service state; no restart performed',state=values if rc==0 else {})
    elif platform.system()=='Windows':
        shell=shutil.which('pwsh') or shutil.which('powershell')
        env=os.environ.copy();env['EDR_SERVICE_NAME']=a.service
        rc,out,_=run([shell or 'powershell','-NoProfile','-NonInteractive','-Command',
            "$s=Get-CimInstance Win32_Service -Filter (\"Name='\"+$env:EDR_SERVICE_NAME+\"'\"); "
            "$s | Select-Object Name,State,StartMode,ProcessId | ConvertTo-Json -Compress"],env=env)
        try: values=json.loads(out) if rc==0 else {}
        except ValueError: values={}
        check('service_snapshot','OBSERVED' if values else 'NOT_RUN','Read-only native SCM state; no restart performed',state=values)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate-sha',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--phase',choices=['baseline','candidate','restored'],default='candidate')
    p.add_argument('--package-root',type=Path);p.add_argument('--manifest',type=Path)
    p.add_argument('--manifest-signature',type=Path);p.add_argument('--trusted-release-key',type=Path)
    p.add_argument('--soc-origin');p.add_argument('--server-ca',type=Path)
    p.add_argument('--operator-cert',type=Path);p.add_argument('--operator-key',type=Path)
    p.add_argument('--exercise-scanner',action='store_true');p.add_argument('--lab-confirmation')
    for arg in ['clamscan','sigtool','database-dir','cvd-certs-dir','eicar-file']:p.add_argument('--'+arg,type=Path)
    p.add_argument('--service')
    a=p.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',a.candidate_sha):p.error('A full candidate SHA is required')
    if a.output.exists():p.error('Refusing to overwrite an existing evidence record')
    os.umask(0o077)
    for operation in [package_check,api_check,scanner_check,service_check]:
        try:operation(a)
        except Exception as exc:check(operation.__name__,'FAIL','Check failed; no sensitive exception details recorded',exception_type=type(exc).__name__)
    report={'schema':1,'candidate_sha':a.candidate_sha,'collected_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'candidate_identity_verified':all(any(c['name']==name and c['status']=='PASS' for c in CHECKS)
                for name in ('candidate_files','release_signature')),
            'phase':a.phase,'host_id_sha256':hashlib.sha256(socket.gethostname().lower().encode()).hexdigest(),
            'os':{'system':platform.system(),'release':platform.release(),'version':platform.version(),'machine':platform.machine()},
            'checks':CHECKS,'host_acceptance_complete':False,'deployment_authorization':'not-granted',
            'required_separate_evidence':['Exact-head GitHub CI','Rust-to-daemon-to-backend scan on this host',
                'Native Sysmon provider/channel/Event7 vs Event11 and authenticated ingestion on Windows',
                'Worker crash isolation and long-running resource/retention checks','Actual service and database rollback rehearsal',
                'Independent InfoSec and QA verdicts','Deployment authorization']}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as output:json.dump(report,output,indent=2);output.write('\n')
    print(json.dumps({'report':str(a.output),'checks':len(CHECKS),'host_acceptance_complete':False,'deployment_authorization':'not-granted'}))
    return 2 if any(c['status'] in ('FAIL','NOT_RUN') for c in CHECKS) else 0

if __name__=='__main__':raise SystemExit(main())
