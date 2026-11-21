import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare_release', Path(__file__).with_name('prepare-release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = 'a' * 40


class ReleasePreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.stem = f'turansec-edr-{SHA[:12]}-linux-x86_64-unsigned'
        self.archive = self.root / (self.stem + '.tar.gz')
        self.archive.write_bytes(b'bounded archive identity fixture')
        self.manifest = self.root / (self.stem + '.manifest.json')
        self.data = {'schema': 1, 'source_sha': SHA, 'target': 'linux-x86_64',
                     'archive': {'name': self.archive.name, 'size': self.archive.stat().st_size,
                                 'sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest()}}
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.data))

    def run_prepare(self, **kw):
        return release.prepare(self.root, kw.get('version', 'v0.1.0-rc.1'),
                               kw.get('sha', SHA), kw.get('required', {'linux-x86_64'}))

    def test_records_only_actual_target_and_unsigned_state(self):
        result = self.run_prepare()
        self.assertEqual(result['status'], 'unsigned-engineering-candidate')
        self.assertEqual(result['native_platforms_not_built'], ['windows-x86_64'])
        self.assertEqual(result['artifacts'][0]['sha256'], self.data['archive']['sha256'])
        self.assertTrue((self.root / 'SHA256SUMS').is_file())

    def test_archive_tamper_rejected_before_metadata(self):
        self.archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse((self.root / 'release.json').exists())

    def test_wrong_source_and_missing_native_target_rejected(self):
        with self.assertRaises(ValueError): self.run_prepare(sha='b' * 40)
        with self.assertRaises(ValueError): self.run_prepare(required={'linux-x86_64', 'windows-x86_64'})

    def test_archive_path_escape_rejected(self):
        self.data['archive']['name'] = '../private'
        self.save()
        with self.assertRaises(ValueError): self.run_prepare()

    def test_malformed_manifest_structure_rejected(self):
        for malformed in [[], None, {'archive': []}, {'archive': None}]:
            with self.subTest(malformed=malformed):
                value = self.data | malformed if isinstance(malformed, dict) else malformed
                self.manifest.write_text(json.dumps(value))
                with self.assertRaises(ValueError): self.run_prepare()
                self.assertFalse((self.root / 'release.json').exists())

    def test_archive_symlink_rejected(self):
        outside = self.root / 'different'
        self.archive.rename(outside)
        self.archive.symlink_to(outside)
        with self.assertRaises(ValueError): self.run_prepare()

    def test_metadata_symlink_and_overwrite_rejected(self):
        outside = self.root / 'unchanged'
        outside.write_text('preserve')
        (self.root / 'release.json').symlink_to(outside)
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual(outside.read_text(), 'preserve')
        (self.root / 'release.json').unlink()
        self.run_prepare()
        with self.assertRaises(ValueError): self.run_prepare()

    def test_stable_or_injected_version_rejected(self):
        for value in ['v1.0.0', '../x', 'v1.0.0-rc.0', 'v1.0.0-rc.1\nrun']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_prepare(version=value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
