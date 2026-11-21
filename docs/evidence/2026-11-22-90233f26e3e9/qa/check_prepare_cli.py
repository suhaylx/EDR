#!/usr/bin/env python3
"""Independent ordinary CLI workflow check using explicitly synthetic archives."""
from pathlib import Path
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HELPER = Path(__file__).parent / 'release-helper-snapshot/scripts/release/prepare-release.py'
SHA = 'b' * 40

def bundle(directory, target):
    stem = f'turansec-edr-{SHA[:12]}-{target}-unsigned'
    archive = directory / (stem + ('.tar.gz' if target == 'linux-x86_64' else '.zip'))
    contents = b'Synthetic CLI workflow fixture. No native executable or host acceptance.\n'
    if target == 'linux-x86_64':
        with tarfile.open(archive, 'w:gz') as out:
            member = tarfile.TarInfo('FIXTURE.txt'); member.size = len(contents)
            out.addfile(member, io.BytesIO(contents))
    else:
        with zipfile.ZipFile(archive, 'w') as out:
            out.writestr('FIXTURE.txt', contents)
    manifest = directory / (stem + '.manifest.json')
    manifest.write_text(json.dumps({'schema': 1, 'source_sha': SHA, 'target': target,
        'archive': {'name': archive.name, 'size': archive.stat().st_size,
                    'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}}))

def main():
    with tempfile.TemporaryDirectory(prefix='edr release CLI fixture ') as temporary:
        directory = Path(temporary)
        args = [sys.executable, str(HELPER), '--directory', str(directory),
                '--version', 'v0.1.0-rc.2', '--source-sha', SHA,
                '--require-target', 'linux-x86_64', '--require-target', 'windows-x86_64']
        bundle(directory, 'linux-x86_64')
        result = subprocess.run(args, capture_output=True, text=True)
        assert result.returncode == 1 and 'Required native package target is missing' in result.stdout
        assert not (directory / 'release.json').exists()
        print('PASS: combined preparation reports the missing platform and leaves metadata absent')
        bundle(directory, 'windows-x86_64')
        result = subprocess.run(args, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        record = json.loads(result.stdout)
        assert record == json.loads((directory / 'release.json').read_text())
        assert record['version'] == 'v0.1.0-rc.2' and record['source_sha'] == SHA
        assert record['status'] == 'unsigned-engineering-candidate'
        assert record['deployment_authorization'] == 'not-granted'
        assert len(record['artifacts']) == 2 and record['native_platforms_not_built'] == []
        print('PASS: combined CLI workflow works in a directory with spaces and records both fixture targets')
        checksum = subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=directory,
                                  capture_output=True, text=True)
        assert checksum.returncode == 0, checksum.stderr
        assert checksum.stdout.count(': OK') == 4
        notes = (directory / 'RELEASE_NOTES.md').read_text()
        assert SHA in notes and 'unsigned engineering candidates' in notes
        print('PASS: generated checksums validate all four archive/manifest files and notes identify the source')
        original = {name: (directory / name).read_bytes() for name in ('release.json', 'SHA256SUMS', 'RELEASE_NOTES.md')}
        repeated = subprocess.run(args, capture_output=True, text=True)
        assert repeated.returncode == 1
        assert original == {name: (directory / name).read_bytes() for name in original}
        print('PASS: a repeated invocation preserves the existing release record')
        assert subprocess.run([sys.executable, str(HELPER), '--help'], stdout=subprocess.DEVNULL).returncode == 0
        print('PASS: CLI usage is available without a package or native host')
    print('LIMIT: archives are synthetic CLI fixtures; no Windows/Linux native build or signing credit')

if __name__ == '__main__':
    main()
