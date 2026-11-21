#!/usr/bin/env python3
"""Linux installation regressions: real filesystem/crypto/unit parser, simulated service manager.

These tests never claim systemd host acceptance. Test identities are temporary
fixtures, and the service-manager substitute cannot be selected through the CLI.
"""
import hashlib
import grp
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linux_service import (ActivationRolledBack, Installation, MAX_ARCHIVE_BYTES, Systemd,
                           RollbackFailed, authenticated_health, catalog, require_system_manager, sha256, verified_bundle)
from systemd_launcher import SERVER_CREDENTIALS, launch_plan, validate_agent


SOURCE = Path(__file__).resolve().parents[2]


class FakeSystemd:
    """Records requested service operations; performs no real service changes."""
    def __init__(self):
        self.calls = []
        self.agent_ok = True
        self.server_ok = True
        self.fail_start = False

    def reload(self): self.calls.append(("reload",))
    def assert_units(self, paths): self.calls.append(("assert", tuple(paths)))
    def ensure_absent(self, names): self.calls.append(("absent", tuple(names)))
    def stop(self, unit): self.calls.append(("stop", unit))
    def disable(self, unit): self.calls.append(("disable", unit))
    def start(self, unit):
        self.calls.append(("start", unit))
        if self.fail_start:
            raise RuntimeError("simulated service start failure")
    def restart(self, unit): self.start(unit)
    def successful_agent(self): return self.agent_ok
    def successful_server(self, binary): return self.server_ok


class InstallFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="edr-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prefix = self.root / "opt" / "turansec"
        self.units = self.root / "units"
        self.units.mkdir()
        self.manager = FakeSystemd()
        self.install = Installation(self.prefix, self.units, self.manager)
        self.config_dir = self.root / "configuration"
        self.config_dir.mkdir(mode=0o700)
        self.server_config = self.config_dir / "edrd.json"
        config = {"agent_listen": "127.0.0.1:9443", "soc_listen": "127.0.0.1:9444",
                  "ui_dir": str(self.prefix / "current" / "web")}
        for key, name in SERVER_CREDENTIALS.items():
            file = self.config_dir / name
            file.write_bytes(("private fixture for " + key).encode())
            file.chmod(0o600)
            config[key] = str(file)
        self.server_config.write_text(json.dumps(config))
        self.server_config.chmod(0o600)

    def bundle(self, sha, extra=None, mode=0o644):
        files = {
            "bin/edrd": b"synthetic test executable; never launched\n",
            "bin/turansec-edr-agent": b"synthetic test executable; never launched\n",
            "web/index.html": ("candidate " + sha).encode(),
            "docs/INSTALLATION.md": b"fixture manual\n",
            "scripts/release/systemd_launcher.py": (SOURCE / "scripts/release/systemd_launcher.py").read_bytes(),
        }
        for path in (SOURCE / "packaging/linux").iterdir():
            files["packaging/linux/" + path.name] = path.read_bytes()
        archive = self.root / f"candidate-{sha[:8]}.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = mode
                out.addfile(member, io.BytesIO(data))
            if extra:
                out.addfile(extra)
        manifest = self.root / f"candidate-{sha[:8]}.json"
        data = {"schema": 1, "target": "linux-x86_64", "source_sha": sha,
                "archive": {"name": archive.name, "size": archive.stat().st_size,
                            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()},
                "files": [{"path": name, "size": len(value), "sha256": sha256(value)} for name, value in files.items()]}
        manifest.write_text(json.dumps(data))
        return archive, manifest

    def stage(self, sha):
        archive, manifest = self.bundle(sha)
        with verified_bundle(archive, manifest, sha, unsigned_lab=True,
                             manifest_sha256=sha256(manifest.read_bytes())) as (data, copied, trust):
            return self.install.stage(data, copied, trust)

    def register(self, sha="a" * 40):
        self.stage(sha)
        return self.install.register(sha, self.server_config, None)

    def agent_configuration(self):
        scan = self.root / "scan-root"
        scan.mkdir(mode=0o750)
        socket_node = self.root / "clamd.socket"
        # A filesystem socket node tests ownership/group selection only. There
        # is no listening scanner behind it and no ClamAV acceptance claim.
        os.mknod(socket_node, stat.S_IFSOCK | 0o660)
        socket_node.chmod(0o660)
        gid = os.getegid() if os.getegid() != 0 else 65534
        if gid != os.getegid():
            os.chown(scan, -1, gid)
            os.chown(socket_node, -1, gid)
        config = json.loads((SOURCE / "config/agent.example.json").read_text())
        config.update(scan_root=str(scan), clamd_socket=str(socket_node), read_groups=[grp.getgrgid(gid).gr_name])
        for key, name in (("ca_file", "endpoint-ca.pem"), ("cert_file", "endpoint.pem"), ("key_file", "endpoint.key")):
            path = self.config_dir / name
            path.write_text("private test fixture")
            path.chmod(0o600)
            config[key] = str(path)
        path = self.config_dir / "agent.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        return path


class BundleTests(InstallFixture):
    def test_unsigned_stage_requires_explicit_independent_digest(self):
        archive, manifest = self.bundle("a" * 40)
        with self.assertRaises(ValueError), verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True):
            pass
        self.assertFalse(self.prefix.exists())

    def test_wrong_unsigned_digest_rejected(self):
        archive, manifest = self.bundle("a" * 40)
        with self.assertRaises(ValueError), verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True, manifest_sha256="0" * 64):
            pass

    def test_dry_run_writes_nothing_and_starts_nothing(self):
        archive, manifest = self.bundle("a" * 40)
        with verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True,
                             manifest_sha256=sha256(manifest.read_bytes())) as (data, copied, trust):
            result = self.install.stage(data, copied, trust, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertFalse(self.prefix.exists())
        self.assertEqual(self.manager.calls, [])

    def test_valid_stage_is_idempotent_and_never_starts_services(self):
        self.stage("a" * 40)
        # Reuse exactly the first package bytes/manifest for an idempotent stage.
        archive = self.root / "candidate-aaaaaaaa.tar.gz"
        manifest = self.root / "candidate-aaaaaaaa.json"
        with verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True,
                             manifest_sha256=sha256(manifest.read_bytes())) as (data, copied, trust):
            result = self.install.stage(data, copied, trust)
        self.assertTrue(result["already_staged"])
        self.assertFalse((self.prefix / "current").exists())
        self.assertEqual(self.manager.calls, [])

    def test_traversal_symlink_and_extra_members_rejected(self):
        for index, name in enumerate(("../outside", "/etc/edr-outside", "unexpected")):
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            sha = str(index + 1) * 40
            archive, manifest = self.bundle(sha, extra=member)
            with self.assertRaises(ValueError), verified_bundle(archive, manifest, sha, unsigned_lab=True,
                                                               manifest_sha256=sha256(manifest.read_bytes())):
                pass
        self.assertFalse(self.prefix.exists())

    def test_setuid_archive_member_rejected(self):
        archive, manifest = self.bundle("a" * 40, mode=0o4755)
        with self.assertRaises(ValueError), verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True,
                                                           manifest_sha256=sha256(manifest.read_bytes())):
            pass

    def test_input_snapshot_cannot_change_after_verification(self):
        archive, manifest = self.bundle("a" * 40)
        with verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True,
                             manifest_sha256=sha256(manifest.read_bytes())) as (data, copied, trust):
            archive.write_bytes(b"changed download")
            manifest.write_text("{}")
            self.install.stage(data, copied, trust)
        self.install.verify_release("a" * 40)

    def test_post_stage_tampering_blocks_registration(self):
        self.stage("a" * 40)
        file = self.prefix / "releases" / ("a" * 40) / "web/index.html"
        file.chmod(0o644)
        file.write_text("tampered")
        with self.assertRaises(ValueError):
            self.install.register("a" * 40, self.server_config, None)
        self.assertEqual(self.manager.calls, [])

    def test_prefix_symlink_is_not_followed(self):
        self.prefix.parent.mkdir(parents=True)
        self.prefix.symlink_to(self.config_dir)
        archive, manifest = self.bundle("a" * 40)
        with verified_bundle(archive, manifest, "a" * 40, unsigned_lab=True,
                             manifest_sha256=sha256(manifest.read_bytes())) as (data, copied, trust):
            with self.assertRaises(ValueError):
                self.install.stage(data, copied, trust)
        self.assertFalse((self.config_dir / "releases").exists())


class ServiceLifecycleTests(InstallFixture):
    def test_registration_writes_units_without_starting_or_enabling(self):
        self.register()
        self.assertEqual(self.install.state()["status"], "registered")
        self.assertEqual((self.prefix / "current").resolve().name, "a" * 40)
        self.assertFalse(any(call[0] in ("start", "enable") for call in self.manager.calls))
        unit = (self.units / "turansec-edrd.service").read_text()
        self.assertIn("DynamicUser=yes", unit)
        self.assertIn("LoadCredential=runtime.dsn:", unit)
        self.assertNotIn("private fixture", unit)
        self.assertIn("IPAddressAllow=localhost", unit)

    def test_generated_units_parse_with_real_systemd_analyze(self):
        self.stage("a" * 40)
        self.install.register("a" * 40, self.server_config, self.agent_configuration())
        result = subprocess.run(["systemd-analyze", "verify", *[str(self.units / name) for name in (
            "turansec-edrd.service", "turansec-agent.service", "turansec-agent.timer")]],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_agent_timer_starts_only_after_successful_bounded_preflight(self):
        self.stage("a" * 40)
        self.install.register("a" * 40, None, self.agent_configuration())
        self.manager.calls.clear()
        self.install.activate("a" * 40, lambda: True)
        starts = [call for call in self.manager.calls if call[0] == "start"]
        self.assertEqual(starts, [("start", "turansec-agent.service"), ("start", "turansec-agent.timer")])

    def test_extra_agent_group_is_not_granted(self):
        self.stage("a" * 40)
        path = self.agent_configuration()
        config = json.loads(path.read_text())
        config["read_groups"].append("arbitrary-host-group")
        path.write_text(json.dumps(config))
        real_lookup = grp.getgrnam
        with patch("linux_service.grp.getgrnam", side_effect=lambda name: SimpleNamespace(gr_gid=49999) if name == "arbitrary-host-group" else real_lookup(name)):
            with self.assertRaises(ValueError):
                self.install.register("a" * 40, None, path)
        self.assertEqual(self.manager.calls, [])

    def test_agent_socket_requires_group_connect_access_without_world_access(self):
        self.stage("a" * 40)
        path = self.agent_configuration()
        config = json.loads(path.read_text())
        for mode in (0o600, 0o666):
            Path(config["clamd_socket"]).chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                self.install.register("a" * 40, None, path)
        self.assertEqual(self.manager.calls, [])

    def test_failed_upgrade_restores_whole_release_units_and_credentials(self):
        self.register()
        self.install.activate("a" * 40, lambda: True)
        old_unit = (self.units / "turansec-edrd.service").read_bytes()
        secrets_before = {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in self.config_dir.iterdir()}
        self.stage("b" * 40)
        with self.assertRaises(ActivationRolledBack):
            self.install.activate("b" * 40, lambda: (self.prefix / "current").resolve().name == "a" * 40)
        self.assertEqual((self.prefix / "current").resolve().name, "a" * 40)
        self.assertEqual((self.units / "turansec-edrd.service").read_bytes(), old_unit)
        self.assertEqual(self.install.state()["status"], "rolled_back")
        self.assertEqual(secrets_before, {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in self.config_dir.iterdir()})

    def test_upgrade_stops_old_services_before_switching_current(self):
        self.register()
        self.install.activate("a" * 40, lambda: True)
        self.stage("b" * 40)
        selected_at_stop = []
        with patch.object(self.manager, "stop", side_effect=lambda _unit: selected_at_stop.append((self.prefix / "current").resolve().name)):
            self.install.activate("b" * 40, lambda: True)
        self.assertEqual(selected_at_stop[0], "a" * 40)
        self.assertEqual((self.prefix / "current").resolve().name, "b" * 40)

    def test_failed_rollback_is_explicit_recovery_state(self):
        self.register()
        self.install.activate("a" * 40, lambda: True)
        self.stage("b" * 40)
        with self.assertRaises(RollbackFailed):
            self.install.activate("b" * 40, lambda: False)
        self.assertEqual(self.install.state()["status"], "recovery_required")

    def test_initial_start_failure_stops_services_without_claiming_rollback(self):
        self.register()
        with self.assertRaises(RuntimeError):
            self.install.activate("a" * 40, lambda: False)
        self.assertEqual(self.install.state()["status"], "initial_start_failed")
        self.assertEqual(self.manager.calls[-1], ("stop", "turansec-edrd.service"))

    def test_other_process_answering_health_does_not_prove_candidate_started(self):
        self.register()
        self.manager.server_ok = False
        with self.assertRaises(RuntimeError):
            self.install.activate("a" * 40, lambda: True)
        self.assertEqual(self.install.state()["status"], "initial_start_failed")

    def test_reactivating_current_active_release_does_not_stop_it(self):
        self.register()
        self.install.activate("a" * 40, lambda: True)
        self.manager.calls.clear()
        with self.assertRaises(ValueError):
            self.install.activate("a" * 40, lambda: True)
        self.assertEqual(self.install.state()["status"], "active")
        self.assertEqual(self.manager.calls, [])

    def test_uninstall_preserves_configuration_database_marker_and_releases(self):
        self.register()
        database = self.root / "database-do-not-touch"
        database.write_text("preserve")
        before = {p.name: p.read_bytes() for p in self.config_dir.iterdir()}
        result = self.install.uninstall()
        self.assertFalse((self.units / "turansec-edrd.service").exists())
        self.assertEqual(self.install.state()["status"], "uninstalled")
        self.assertEqual(database.read_text(), "preserve")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config_dir.iterdir()})
        self.assertTrue((self.prefix / "releases" / ("a" * 40)).is_dir())
        self.assertIn("private keys", result["preserved"])

    def test_local_unit_changes_block_upgrade_and_uninstall(self):
        self.register()
        with (self.units / "turansec-edrd.service").open("a") as out:
            out.write("\n# local policy\n")
        self.manager.calls.clear()
        with self.assertRaises(ValueError):
            self.install.uninstall()
        self.assertEqual(self.manager.calls, [])

    def test_private_file_permissions_and_nonlocal_bind_fail_registration(self):
        self.stage("a" * 40)
        key = self.config_dir / "server-key.pem"
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            self.install.register("a" * 40, self.server_config, None)
        key.chmod(0o600)
        config = json.loads(self.server_config.read_text())
        config["agent_listen"] = "0.0.0.0:9443"
        self.server_config.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            self.install.register("a" * 40, self.server_config, None)
        self.assertEqual(self.manager.calls, [])

    def test_other_mutation_cannot_run_during_installation_lock(self):
        self.register()
        with self.install.lock():
            with self.assertRaises(BlockingIOError):
                self.install.uninstall()
        self.assertEqual(self.install.state()["status"], "registered")


class LauncherTests(InstallFixture):
    def test_systemctl_absence_requires_explicit_missing_inactive_properties(self):
        absent = "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
        for code in (0, 4):
            with self.subTest(code=code), patch("linux_service.subprocess.run", return_value=SimpleNamespace(returncode=code, stdout=absent)):
                Systemd().ensure_absent(["turansec-edrd.service"])
        for code, output in ((1, ""), (4, ""), (0, absent.replace("inactive", "active")), (0, absent.replace("not-found", "loaded"))):
            with self.subTest(code=code, output=output), patch("linux_service.subprocess.run", return_value=SimpleNamespace(returncode=code, stdout=output)):
                with self.assertRaises(ValueError):
                    Systemd().ensure_absent(["turansec-edrd.service"])

    def test_server_uses_read_only_credentials_and_clears_inherited_environment(self):
        self.register()
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        credentials = self.root / "credentials"
        shutil.copytree(self.config_dir, credentials)
        (credentials / "edrd.json").rename(credentials / "config.json")
        command, environment = launch_plan("server", self.prefix, None, {
            "CREDENTIALS_DIRECTORY": str(credentials), "RUNTIME_DIRECTORY": str(runtime),
            "PGPASSWORD": "fixture-must-not-propagate", "EDR_SOC_UI_DIR": "/wrong/tree",
        })
        generated = json.loads((runtime / "edrd.json").read_text())
        self.assertEqual(generated["runtime_dsn_file"], str(credentials / "runtime.dsn"))
        self.assertEqual(generated["ui_dir"], str(self.prefix / "releases" / ("a" * 40) / "web"))
        self.assertEqual(stat.S_IMODE((runtime / "edrd.json").stat().st_mode), 0o600)
        self.assertEqual(environment, {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.assertNotIn("fixture-must-not-propagate", str(command))

    def test_agent_configuration_rejects_privileged_groups_and_unbounded_batch(self):
        config = json.loads((SOURCE / "config/agent.example.json").read_text())
        validate_agent(config)
        config["read_groups"] = ["docker"]
        with self.assertRaises(ValueError): validate_agent(config)
        config["read_groups"] = ["clamav"]
        config["max_jobs"] = 21
        with self.assertRaises(ValueError): validate_agent(config)

    def test_enrolled_identity_contract_matches_go_and_rust(self):
        config = json.loads((SOURCE / "config/agent.example.json").read_text())
        for key in ("tenant_id", "agent_id"):
            for identity in ("linux.01", "a" * 96):
                with self.subTest(key=key, length=len(identity)):
                    config[key] = identity
                    validate_agent(config)
            for identity in ("a" * 97, ".", "..", "non-ascii-\u00e9"):
                with self.subTest(key=key, rejected=identity[:16]):
                    config[key] = identity
                    with self.assertRaises(ValueError):
                        validate_agent(config)
            config[key] = "valid.id"

    def test_agent_launcher_keeps_credentials_out_of_values_and_bounds_actions(self):
        self.stage("a" * 40)
        agent_path = self.agent_configuration()
        self.install.register("a" * 40, None, agent_path)
        config = json.loads(agent_path.read_text())
        credentials = self.root / "agent-credentials"
        credentials.mkdir(mode=0o700)
        shutil.copy2(agent_path, credentials / "config.json")
        for key, name in (("ca_file", "server-ca.pem"), ("cert_file", "agent-cert.pem"), ("key_file", "agent-key.pem")):
            shutil.copy2(config[key], credentials / name)
        for action, expected in (("heartbeat", ["--heartbeat-mtls"]), ("scanner-health", ["--clamav-health"]), ("scan", ["--scan-batch-mtls", "1"])):
            command, environment = launch_plan("agent", self.prefix, action, {
                "CREDENTIALS_DIRECTORY": str(credentials), "HTTP_PROXY": "http://untrusted.invalid",
            })
            self.assertEqual(command[1:], expected)
            self.assertNotIn("HTTP_PROXY", environment)
            self.assertNotIn("private test fixture", json.dumps(environment))
            self.assertEqual(environment["TURANSEC_MTLS_KEY_PEM"], str(credentials / "agent-key.pem"))

    def test_existing_static_reserved_identity_is_not_adopted(self):
        with patch("linux_service.os.geteuid", return_value=0), patch("linux_service.Path.is_dir", return_value=True), \
             patch("linux_service.subprocess.check_output", return_value="systemd 255\n"), \
             patch("linux_service.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=0)):
            with self.assertRaises(ValueError):
                require_system_manager(check_reserved_identities=True)

    def test_active_dynamic_identity_does_not_block_uninstall(self):
        with patch("linux_service.os.geteuid", return_value=0), patch("linux_service.Path.is_dir", return_value=True), \
             patch("linux_service.subprocess.check_output", return_value="systemd 255\n"), \
             patch("linux_service.pwd.getpwnam", side_effect=AssertionError("must not mistake active DynamicUser for a static user")):
            require_system_manager(check_reserved_identities=False)

    def test_runtime_symlink_is_not_overwritten(self):
        self.register()
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        credentials = self.root / "credentials"
        shutil.copytree(self.config_dir, credentials)
        (credentials / "edrd.json").rename(credentials / "config.json")
        outside = self.root / "unrelated"
        outside.write_text("preserve")
        (runtime / "edrd.json").symlink_to(outside)
        with self.assertRaises(OSError):
            launch_plan("server", self.prefix, None, {"CREDENTIALS_DIRECTORY": str(credentials), "RUNTIME_DIRECTORY": str(runtime)})
        self.assertEqual(outside.read_text(), "preserve")


class LoopbackHealthTests(InstallFixture):
    """Actual TLS 1.3 loopback connections with ephemeral test-only identities.

    This checks the installer's probe protocol, not the EDR runtime or a native
    systemd host. These fixture CAs are never release-signing identities.
    """
    @classmethod
    def setUpClass(cls):
        cls.pki_temporary = tempfile.TemporaryDirectory(prefix="edr-health-fixture-")
        cls.addClassCleanup(cls.pki_temporary.cleanup)
        cls.pki = Path(cls.pki_temporary.name)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.pki, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)

        for ca in ("server-ca", "operator-ca"):
            openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-days", "1", "-subj", f"/CN={ca}-fixture",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-keyout", ca + ".key", "-out", ca + ".pem")
        for name, ca, usage in (("server", "server-ca", "serverAuth"), ("operator", "operator-ca", "clientAuth")):
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-subj", f"/CN={name}-fixture", "-keyout", name + ".key", "-out", name + ".csr")
            extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + usage + "\n"
            if name == "server":
                extensions += "subjectAltName=IP:127.0.0.1\n"
            (cls.pki / (name + ".ext")).write_text(extensions)
            openssl("x509", "-req", "-in", name + ".csr", "-CA", ca + ".pem", "-CAkey", ca + ".key",
                    "-set_serial", "1", "-days", "1", "-extfile", name + ".ext", "-out", name + ".pem")
        for file in cls.pki.iterdir():
            file.chmod(0o600)

    def setUp(self):
        super().setUp()
        case = self
        self.requests = []
        self.peer_certificates = []
        self.response_status = 200
        self.session = {"tenant_id": "tenant.fixture", "operator_id": "health.fixture", "role": "viewer"}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                case.requests.append(self.path)
                case.peer_certificates.append(self.connection.getpeercert())
                self.send_response(case.response_status)
                self.send_header("Content-Type", "application/json")
                if case.response_status == 302:
                    self.send_header("Location", "/redirected")
                self.end_headers()
                self.wfile.write(json.dumps(case.session).encode())

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(self.pki / "server.pem", self.pki / "server.key")
        context.load_verify_locations(self.pki / "operator-ca.pem")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.shutdown)
        port = self.server.server_address[1]
        config = json.loads(self.server_config.read_text())
        config["soc_listen"] = f"127.0.0.1:{port}"
        self.server_config.write_text(json.dumps(config))
        self.health_config = self.config_dir / "health.json"
        self.health_config.write_text(json.dumps({
            "origin": f"https://127.0.0.1:{port}", "server_ca_file": str(self.pki / "server-ca.pem"),
            "operator_cert_file": str(self.pki / "operator.pem"), "operator_key_file": str(self.pki / "operator.key"),
            "expected_tenant_id": "tenant.fixture", "expected_operator_id": "health.fixture",
        }))
        self.health_config.chmod(0o600)

    def test_real_mtls_probe_accepts_only_the_expected_session(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1"}):
            self.assertTrue(authenticated_health(self.health_config, self.server_config)())
        self.assertEqual(self.requests, ["/soc/v1/session"])
        self.assertTrue(self.peer_certificates[0])

    def test_real_mtls_probe_rejects_another_operator_or_tenant(self):
        for key in ("tenant_id", "operator_id"):
            original = self.session[key]
            self.session[key] = "wrong.identity"
            with self.subTest(key=key):
                self.assertFalse(authenticated_health(self.health_config, self.server_config)())
            self.session[key] = original
        self.assertEqual(len(self.requests), 2)

    def test_real_mtls_probe_does_not_follow_redirects(self):
        self.response_status = 302
        self.assertFalse(authenticated_health(self.health_config, self.server_config)())
        self.assertEqual(self.requests, ["/soc/v1/session"])

    def test_real_mtls_probe_rejects_forbidden_session(self):
        self.response_status = 403
        self.assertFalse(authenticated_health(self.health_config, self.server_config)())
        self.assertEqual(self.requests, ["/soc/v1/session"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
