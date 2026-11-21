#!/usr/bin/env python3
"""Exercise ordinary installer CLI staging; no native service operations."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

SCRIPTS = Path(__file__).parent / 'installer-snapshot/scripts/release'
sys.path.insert(0, str(SCRIPTS))
from test_linux_service import InstallFixture

def main():
    fixture = InstallFixture()
    fixture.setUp()
    try:
        sha = 'c' * 40
        archive, manifest = fixture.bundle(sha)
        command = [sys.executable, str(SCRIPTS / 'linux_service.py'), '--prefix', str(fixture.prefix),
                   'stage', '--archive', str(archive), '--manifest', str(manifest),
                   '--expected-sha', sha, '--unsigned-lab', '--manifest-sha256',
                   hashlib.sha256(manifest.read_bytes()).hexdigest()]
        dry = subprocess.run(command + ['--dry-run'], text=True, capture_output=True)
        assert dry.returncode == 0, dry.stderr
        response = json.loads(dry.stdout)
        assert response['dry_run'] and not response['services_started']
        assert not fixture.prefix.exists()
        print('PASS: CLI stage dry-run validates the fixture and creates no installation directory')
        staged = subprocess.run(command, text=True, capture_output=True)
        assert staged.returncode == 0, staged.stderr
        response = json.loads(staged.stdout)
        assert response['source_sha'] == sha and not response['services_started']
        release = fixture.prefix / 'releases' / sha
        assert (release / 'bin/edrd').is_file() and (release / 'web/index.html').is_file()
        assert not (fixture.prefix / 'current').exists()
        print('PASS: CLI stage creates the complete versioned fixture without selecting or starting it')
        again = subprocess.run(command, text=True, capture_output=True)
        assert again.returncode == 0 and json.loads(again.stdout)['already_staged']
        print('PASS: CLI staging the same archive again reports already_staged')
        for executable in ('linux_service.py', 'systemd_launcher.py'):
            result = subprocess.run([sys.executable, str(SCRIPTS / executable), '--help'],
                                    capture_output=True, text=True)
            assert result.returncode == 0 and 'usage:' in result.stdout
        print('PASS: installer and launcher CLI help work from the packaged relative script layout')
    finally:
        fixture.doCleanups()
    print('LIMIT: synthetic archive, unprivileged temporary staging only; no systemd or deployment-host acceptance')

if __name__ == '__main__':
    main()
