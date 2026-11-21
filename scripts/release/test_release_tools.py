#!/usr/bin/env python3
"""Release-tool regression tests; ephemeral test keys are not release identities.

Filesystem health callbacks below do not count as deployed service or Windows
host rollback acceptance. Real signing and host gates remain separate.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from release_switch import ActivationRolledBack, RollbackFailed, switch_release


spec = importlib.util.spec_from_file_location("package_candidate", Path(__file__).with_name("package-candidate.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageSignatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="edr-signature-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sha = "a" * 40
        self.archive = self.root / "candidate.tar.gz"
        self.archive.write_bytes(b"synthetic verification fixture; not an installation package\n")
        self.manifest = self.root / "candidate.manifest.json"
        self.manifest.write_text(json.dumps({
            "schema": 1, "source_sha": self.sha, "target": "test-fixture",
            "archive": {"name": self.archive.name, "size": self.archive.stat().st_size,
                        "sha256": package.digest(self.archive)},
        }))
        self.key = self.root / "fixture-key.pem"
        self.public = self.root / "fixture-public.pem"
        self.signature = self.root / "candidate.manifest.sig"
        self.command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.key)])
        self.command(["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(self.public)])
        self.command(["openssl", "dgst", "-sha256", "-sign", str(self.key), "-out", str(self.signature), str(self.manifest)])

    @staticmethod
    def command(argv):
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def verify(self, public=None, expected=None):
        return package.verify(self.archive, self.manifest, self.signature, public or self.public, expected or self.sha)

    def test_valid_signature_binds_source_and_archive(self):
        self.assertEqual(self.verify()["source_sha"], self.sha)

    def test_archive_tampering_rejected(self):
        data = bytearray(self.archive.read_bytes())
        data[0] ^= 1
        self.archive.write_bytes(data)
        with self.assertRaises(ValueError):
            self.verify()

    def test_manifest_tampering_rejected(self):
        self.manifest.write_text(self.manifest.read_text().replace("test-fixture", "tampered-fixture"))
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()

    def test_wrong_trust_root_rejected(self):
        other = self.root / "other-key.pem"
        public = self.root / "other-public.pem"
        self.command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(other)])
        self.command(["openssl", "pkey", "-in", str(other), "-pubout", "-out", str(public)])
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify(public=public)

    def test_different_candidate_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(expected="b" * 40)

    def test_missing_signature_rejected(self):
        self.signature.unlink()
        with self.assertRaises(ValueError):
            self.verify()


class AtomicReleaseSwitchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="edr-rollback-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.previous = self.root / "releases" / "previous"
        self.candidate = self.root / "releases" / "candidate"
        self.previous.mkdir(parents=True)
        self.candidate.mkdir()
        (self.root / "current").symlink_to("releases/previous")
        self.restarts = []

    def current(self):
        return (self.root / "current").resolve()

    def restart(self):
        self.restarts.append(self.current().name)

    def status(self):
        return json.loads((self.root / "activation.json").read_text())["status"]

    def test_success_preserves_previous_release(self):
        switch_release(self.root, self.candidate, self.restart, lambda: True)
        self.assertEqual(self.current(), self.candidate)
        self.assertTrue(self.previous.is_dir())
        self.assertEqual(self.restarts, ["candidate"])
        self.assertEqual(self.status(), "active")

    def test_failed_health_restores_previous_and_rechecks_it(self):
        checks = []
        def health():
            checks.append(self.current().name)
            return self.current() == self.previous
        with self.assertRaises(ActivationRolledBack):
            switch_release(self.root, self.candidate, self.restart, health)
        self.assertEqual(self.current(), self.previous)
        self.assertEqual(checks, ["candidate", "previous"])
        self.assertEqual(self.restarts, ["candidate", "previous"])
        self.assertEqual(self.status(), "rolled_back")

    def test_restart_failure_restores_previous(self):
        def restart():
            self.restart()
            if self.current() == self.candidate:
                raise RuntimeError("simulated service start failure")
        with self.assertRaises(ActivationRolledBack):
            switch_release(self.root, self.candidate, restart, lambda: True)
        self.assertEqual(self.current(), self.previous)
        self.assertEqual(self.status(), "rolled_back")

    def test_failed_rollback_health_is_not_reported_as_success(self):
        with self.assertRaises(RollbackFailed):
            switch_release(self.root, self.candidate, self.restart, lambda: False)
        self.assertEqual(self.status(), "rollback_failed")

    def test_pending_activation_requires_recovery(self):
        (self.root / "activation.json").write_text('{"status":"pending"}')
        with self.assertRaises(RuntimeError):
            switch_release(self.root, self.candidate, self.restart, lambda: True)
        self.assertEqual(self.current(), self.previous)

    def test_external_candidate_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        with self.assertRaises(ValueError):
            switch_release(self.root, outside, self.restart, lambda: True)
        self.assertEqual(self.current(), self.previous)


if __name__ == "__main__":
    unittest.main(verbosity=2)
