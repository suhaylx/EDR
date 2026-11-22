#!/usr/bin/env python3
"""Security regressions for evidence attribution; fixture keys are not release keys."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('collector',Path(__file__).with_name('collect-host-acceptance.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class EvidenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.pkg=self.root/'package';(self.pkg/'bin').mkdir(parents=True)
        self.agent=self.pkg/'bin/turansec-edr-agent';self.agent.write_bytes(b'not executed test artifact')
        self.manifest=self.root/'manifest.json';self.sha='a'*40
        self.data={'schema':1,'source_sha':self.sha,'files':[{'path':'bin/turansec-edr-agent',
            'sha256':c.sha(self.agent),'size':self.agent.stat().st_size}]}
        self.manifest.write_text(json.dumps(self.data));c.CHECKS.clear()
        self.args=argparse.Namespace(package_root=self.pkg,manifest=self.manifest,candidate_sha=self.sha,
            manifest_signature=None,trusted_release_key=None)
    def status(self,name):return next(x['status'] for x in c.CHECKS if x['name']==name)
    def test_unsigned_hash_match_is_not_publisher_approval(self):
        c.package_check(self.args)
        self.assertEqual(self.status('candidate_files'),'PASS');self.assertEqual(self.status('release_signature'),'NOT_RUN')
    def test_tampered_artifact_rejected(self):
        self.agent.write_bytes(b'changed');c.package_check(self.args)
        self.assertEqual(self.status('candidate_files'),'FAIL')
    def test_wrong_sha_rejected(self):
        self.args.candidate_sha='b'*40;c.package_check(self.args);self.assertEqual(self.status('candidate_files'),'FAIL')
    def test_manifest_escape_rejected(self):
        self.data['files'].append({'path':'../secret','sha256':'0'*64,'size':1})
        self.manifest.write_text(json.dumps(self.data));c.package_check(self.args);self.assertEqual(self.status('candidate_files'),'FAIL')
    def test_symlink_artifact_rejected(self):
        self.agent.unlink();self.agent.symlink_to(self.manifest)
        c.package_check(self.args);self.assertEqual(self.status('candidate_files'),'FAIL')
    def test_supplied_trust_root_inside_archive_rejected(self):
        key=self.pkg/'public.pem';key.write_text('not a trust root');sig=self.root/'sig';sig.write_text('fixture')
        self.args.trusted_release_key=key;self.args.manifest_signature=sig
        c.package_check(self.args);self.assertEqual(self.status('release_signature'),'FAIL')
    def test_actual_crypto_valid_signature_then_tamper_rejected(self):
        private=self.root/'fixture.key';public=self.root/'public.pem';sig=self.root/'signature'
        for command in [
            ['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(private)],
            ['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],
            ['openssl','dgst','-sha256','-sign',str(private),'-out',str(sig),str(self.manifest)]]:
            subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.args.trusted_release_key=public;self.args.manifest_signature=sig
        c.package_check(self.args);self.assertEqual(self.status('release_signature'),'PASS')
        self.manifest.write_text(self.manifest.read_text()+' ');c.CHECKS.clear();c.package_check(self.args)
        self.assertEqual(self.status('release_signature'),'FAIL')
    def test_scanner_refuses_non_eicar_input_before_execution(self):
        fake=self.root/'arbitrary.txt';fake.write_text('not EICAR')
        a=argparse.Namespace(exercise_scanner=True,lab_confirmation='isolated-lab',clamscan=Path('/does/not/exist'),
            sigtool=Path('/does/not/exist'),database_dir=self.root,cvd_certs_dir=self.root,eicar_file=fake)
        c.scanner_check(a);self.assertEqual(self.status('eicar_fixture'),'FAIL')

if __name__=='__main__':unittest.main(verbosity=2)
