#!/usr/bin/env python3
"""Validate unsigned candidate files and prepare a reviewable release record.

This does not sign, install, publish, or authorize deployment. The GitHub
workflow may attach the resulting files to an explicitly requested draft.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


def digest(path: Path) -> str:
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def prepare(directory: Path, version: str, source_sha: str, required: set[str]) -> dict:
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*', version):
        raise ValueError('Use an explicit candidate version such as v0.1.0-rc.1')
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('A full source commit SHA is required')
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Package directory must be a regular directory')
    directory = directory.resolve()
    artifacts = []
    seen = set()
    for manifest in sorted(directory.glob('*.manifest.json')):
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Invalid package manifest file')
        data = json.loads(manifest.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise ValueError('Package manifest must be a JSON object')
        target = data.get('target')
        if target not in ('linux-x86_64', 'windows-x86_64') or target in seen:
            raise ValueError('Unexpected or duplicate package target')
        if data.get('schema') != 1 or data.get('source_sha') != source_sha:
            raise ValueError('Package does not match the exact candidate source')
        expected_stem = f'turansec-edr-{source_sha[:12]}-{target}-unsigned'
        extension = '.tar.gz' if target == 'linux-x86_64' else '.zip'
        expected_name = expected_stem + extension
        archive_record = data.get('archive', {})
        if not isinstance(archive_record, dict):
            raise ValueError('Package archive record must be a JSON object')
        if manifest.name != expected_stem + '.manifest.json' or archive_record.get('name') != expected_name:
            raise ValueError('Unexpected package filename or path')
        archive = directory / expected_name
        if archive.is_symlink() or not archive.is_file() or archive.resolve().parent != directory:
            raise ValueError('Archive must be a regular file within the package directory')
        actual_digest = digest(archive)
        if archive_record.get('size') != archive.stat().st_size or archive_record.get('sha256') != actual_digest:
            raise ValueError('Package size or SHA-256 does not match its manifest')
        seen.add(target)
        artifacts.append({'target': target, 'name': archive.name, 'bytes': archive.stat().st_size,
                          'sha256': actual_digest, 'manifest': manifest.name,
                          'manifest_sha256': digest(manifest), 'publisher_signature': 'absent'})
    if not artifacts or not required.issubset(seen):
        raise ValueError('Required native package target is missing')
    record = {'schema': 1, 'version': version, 'source_sha': source_sha,
              'status': 'unsigned-engineering-candidate', 'artifacts': artifacts,
              'native_platforms_not_built': sorted({'linux-x86_64', 'windows-x86_64'} - seen),
              'deployment_authorization': 'not-granted',
              'acceptance': 'Consult exact-SHA CI, independent reviews and native host evidence separately'}
    lines = []
    for artifact in artifacts:
        lines += [f"{artifact['sha256']}  {artifact['name']}",
                  f"{artifact['manifest_sha256']}  {artifact['manifest']}"]
    notes = f'''# TuranSec EDR {version}

Source commit: `{source_sha}`.

These files are **unsigned engineering candidates**. They do not carry an
approved publisher signature or deployment authorization. A draft release or
successful package build does not prove CI, native host acceptance or rollback.

The bundle contains the Go/PostgreSQL mTLS service, the single Rust endpoint
binary, React SOC assets, schema migrations, configuration examples and
installation guidance. Linux service staging and operation are documented in
the included manual. PostgreSQL, approved PKI identities, ClamAV and its verified
signature databases must be provisioned separately. No private credentials are
included.

Verify `SHA256SUMS`, compare the source SHA to the reviewed commit, and read the
included installation manual before staging. Checksums establish byte identity;
publisher authentication requires the separately approved release signature.

The native platforms absent from this package set are listed in `release.json`.
The original InfoSec/QA approval, actual Windows/Linux acceptance, trusted signing,
service/database rollback and deployment authorization remain separate gates.
'''
    outputs = {'release.json': json.dumps(record, indent=2) + '\n',
               'SHA256SUMS': '\n'.join(lines) + '\n', 'RELEASE_NOTES.md': notes}
    # Never replace a preexisting release record, including a linked output.
    for name in outputs:
        if (directory / name).exists() or (directory / name).is_symlink():
            raise ValueError('Release metadata already exists; use a fresh staging directory')
    for name, contents in outputs.items():
        with (directory / name).open('x', encoding='utf-8') as target:
            target.write(contents)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--require-target', action='append', default=[], choices=('linux-x86_64', 'windows-x86_64'))
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.directory, args.version, args.source_sha, set(args.require_target)), indent=2))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'Release preparation failed: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
