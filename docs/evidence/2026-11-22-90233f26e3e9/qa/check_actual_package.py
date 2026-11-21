#!/usr/bin/env python3
"""Functional QA of a locally built Linux package; no host/service activation."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', required=True, type=Path)
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--source-sha', required=True)
    p.add_argument('--manifest-sha256', required=True)
    a = p.parse_args()
    assert digest(a.manifest) == a.manifest_sha256
    data = json.loads(a.manifest.read_text())
    assert data['source_sha'] == a.source_sha and data['target'] == 'linux-x86_64'
    assert data['archive']['name'] == a.archive.name
    assert data['archive']['size'] == a.archive.stat().st_size
    assert data['archive']['sha256'] == digest(a.archive)
    inventory = {row['path']: row for row in data['files']}
    required = {'bin/edrd', 'bin/turansec-edr-agent', 'web/index.html',
        'config/edrd.example.json', 'config/agent.example.json', 'config/service-health.example.json',
        'docs/INSTALLATION.md', 'docs/LINUX_SERVICE_INSTALLATION.md',
        'docs/backend/RUNTIME_DATABASE_ROLES.md', 'docs/release/BUILD_RELEASE_FILES.md',
        'scripts/release/linux_service.py', 'scripts/release/systemd_launcher.py',
        'scripts/release/release_switch.py', 'scripts/release/prepare-release.py',
        'packaging/linux/turansec-edrd.service.in', 'packaging/linux/turansec-agent.service.in',
        'packaging/linux/turansec-agent.timer.in', 'backend/bootstrap/runtime_privileges.sql',
        'backend/migrations/0013_scan_lease_wallclock.up.sql'}
    assert required <= set(inventory)
    with tempfile.TemporaryDirectory(prefix='edr-package-functional-') as temporary:
        root = Path(temporary)
        extracted = root / 'extracted'; extracted.mkdir()
        with tarfile.open(a.archive, 'r:gz') as archive:
            members = archive.getmembers()
            assert {m.name for m in members} == set(inventory)
            assert len(members) == len(inventory)
            for m in members:
                assert m.isfile() and not PurePosixPath(m.name).is_absolute() and '..' not in PurePosixPath(m.name).parts
            archive.extractall(extracted, filter='data')
        for name, row in inventory.items():
            path = extracted / name
            assert path.stat().st_size == row['size'] and digest(path) == row['sha256'], name
        print('PASS: actual Linux archive matches the independently pinned manifest and complete file inventory')
        assert len(list((extracted / 'backend/migrations').glob('*.up.sql'))) == 13
        for document in ['INSTALLATION.md', 'docs/INSTALLATION.md', 'docs/LINUX_SERVICE_INSTALLATION.md']:
            for link in re.findall(r'\]\(([^)]+)\)', (extracted / document).read_text()):
                if re.match(r'[a-z]+://', link) or link.startswith('#'): continue
                assert (extracted / document).parent.joinpath(link.split('#')[0]).is_file(), (document, link)
        print('PASS: installer, configuration templates, migrations and installation-manual links resolve inside the package')
        for binary in ['edrd', 'turansec-edr-agent']:
            result = subprocess.run([str(extracted / 'bin' / binary), '--version'], text=True, capture_output=True, timeout=10)
            assert result.returncode == 0 and a.source_sha in result.stdout
        print('PASS: both actual packaged executables report the requested complete source SHA')
        for script in ['linux_service.py', 'systemd_launcher.py', 'prepare-release.py', 'package-candidate.py']:
            result = subprocess.run([sys.executable, str(extracted / 'scripts/release' / script), '--help'], capture_output=True, text=True, timeout=10)
            assert result.returncode == 0 and 'usage:' in result.stdout, script
        print('PASS: packaged installer, launcher, release preparation and verifier CLIs resolve their imports')
        prefix = root / 'stage'
        command = [sys.executable, str(extracted / 'scripts/release/linux_service.py'), '--prefix', str(prefix),
            'stage', '--archive', str(a.archive), '--manifest', str(a.manifest), '--expected-sha', a.source_sha,
            '--unsigned-lab', '--manifest-sha256', a.manifest_sha256]
        dry = subprocess.run(command + ['--dry-run'], capture_output=True, text=True, timeout=30)
        assert dry.returncode == 0 and json.loads(dry.stdout)['dry_run'] and not prefix.exists()
        staged = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert staged.returncode == 0 and not json.loads(staged.stdout)['services_started'], staged.stderr
        assert not (prefix / 'current').exists()
        assert (prefix / 'releases' / a.source_sha / 'web/index.html').is_file()
        print('PASS: actual archive dry-run and temporary staging complete without selecting or starting a service')
        release_files = root / 'release files'; release_files.mkdir()
        shutil.copy2(a.archive, release_files / a.archive.name)
        shutil.copy2(a.manifest, release_files / a.manifest.name)
        result = subprocess.run([sys.executable, str(extracted / 'scripts/release/prepare-release.py'),
            '--directory', str(release_files), '--version', 'v0.1.0-rc.1', '--source-sha', a.source_sha,
            '--require-target', 'linux-x86_64'], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        record = json.loads(result.stdout)
        assert record['native_platforms_not_built'] == ['windows-x86_64']
        assert record['deployment_authorization'] == 'not-granted'
        check = subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=release_files, capture_output=True, text=True)
        assert check.returncode == 0
        print('PASS: packaged release helper creates valid checksums and leaves Windows explicitly absent')
    print('LIMIT: unsigned local engineering archive; no native service activation, signing or deployment-host acceptance')

if __name__ == '__main__':
    main()
