#!/usr/bin/env python3
"""Offline regressions: disposable QA entry points must reject libpq rerouting.

The shell tests substitute clients that only record invocation and exit. The
integration tests replace its first SQL operation. No PostgreSQL connection,
database, credential, service, or network access is used by this suite.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OVERRIDES = ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE")
INVENTORY_URL = "postgresql://qa@127.0.0.1:5432/edr_chain_test?sslmode=disable"
INTEGRATION_URL = "postgresql://qa@127.0.0.1:5432/edr_integrated_test?sslmode=disable"
ENROLLMENT_URL = "postgresql://qa@127.0.0.1:5432/edr_candidate_enrollment_wallclock?sslmode=disable"


class FirstDatabaseOperation(Exception):
    """Raised instead of opening the first integration database connection."""


class DisposableDatabaseTargets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="edr-qa-target-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.client_log = self.directory / "client-invocations.txt"
        for name in ("psql", "createdb"):
            executable = self.directory / name
            executable.write_text(
                "#!/bin/sh\n"
                f"printf '{name}\\n' >> \"$EDR_QA_TEST_CLIENT_LOG\"\n"
                "exit 97\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
        self.environment = dict(os.environ)
        for name in OVERRIDES:
            self.environment.pop(name, None)
        self.environment.update({
            "EDR_QA_DISPOSABLE_DB": "yes",
            "EDR_CANDIDATE_SHA": "f" * 40,
            "EDR_TEST_DATABASE_URL": INVENTORY_URL,
            "PGHOST": "127.0.0.1",
            "PGPORT": "5432",
            "PGUSER": "qa",
            "EDR_QA_TEST_CLIENT_LOG": str(self.client_log),
            "PATH": str(self.directory) + os.pathsep + os.environ.get("PATH", ""),
        })
        spec = importlib.util.spec_from_file_location(
            "edr_integrated_candidate_qa", ROOT / "scripts/test-integrated-candidate.py"
        )
        assert spec is not None and spec.loader is not None
        self.integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.integration)
        spec = importlib.util.spec_from_file_location(
            "edr_enrollment_clock_qa", ROOT / "scripts/test-enrollment-wallclock-races.py"
        )
        assert spec is not None and spec.loader is not None
        self.enrollment = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.enrollment)

    def shell(self, script, *args, environment=None):
        self.client_log.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", str(ROOT / script), *args], cwd=ROOT,
            env=environment or self.environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15,
        )

    def assert_no_client(self):
        self.assertFalse(self.client_log.exists(), "A database client was invoked before refusal")

    def assert_integration_refused(self, environment):
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(self.integration, "sql", side_effect=FirstDatabaseOperation) as sql:
            with self.assertRaises(RuntimeError):
                self.integration.run()
            sql.assert_not_called()

    def assert_enrollment_refused(self, environment):
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(self.enrollment, "DATABASE", environment["EDR_TEST_DATABASE_URL"]), \
             mock.patch.object(self.enrollment, "query", side_effect=FirstDatabaseOperation) as query:
            with self.assertRaises(RuntimeError):
                self.enrollment.main()
            query.assert_not_called()

    def test_candidate_refuses_inherited_libpq_routes_before_any_client(self):
        for name in OVERRIDES:
            with self.subTest(override=name):
                env = dict(self.environment, **{name: "unexpected-route"})
                result = self.shell("scripts/ci/candidate-postgres.sh", "test", environment=env)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_client()

    def test_inventory_refuses_inherited_libpq_routes_before_any_client(self):
        for name in OVERRIDES:
            with self.subTest(override=name):
                env = dict(self.environment, **{name: "unexpected-route"})
                result = self.shell("scripts/test-soc-endpoint-inventory-sql.sh", environment=env)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_client()

    def test_integration_refuses_inherited_libpq_routes_before_any_sql(self):
        for name in OVERRIDES:
            with self.subTest(override=name):
                env = dict(self.environment, EDR_TEST_DATABASE_URL=INTEGRATION_URL,
                           **{name: "unexpected-route"})
                self.assert_integration_refused(env)

    def test_enrollment_runner_refuses_inherited_libpq_routes_before_any_sql(self):
        for name in OVERRIDES:
            with self.subTest(override=name):
                env = dict(self.environment, EDR_TEST_DATABASE_URL=ENROLLMENT_URL,
                           **{name: "unexpected-route"})
                self.assert_enrollment_refused(env)

    def test_inventory_refuses_url_parser_control_character_normalization(self):
        for prefix in ("\n", "\t", " ", "\x7f"):
            with self.subTest(prefix=repr(prefix)):
                env = dict(self.environment, EDR_TEST_DATABASE_URL=prefix + INVENTORY_URL)
                result = self.shell("scripts/test-soc-endpoint-inventory-sql.sh", environment=env)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_client()

    def test_integration_refuses_url_parser_control_character_normalization(self):
        for prefix in ("\n", "\t", " ", "\x7f"):
            with self.subTest(prefix=repr(prefix)):
                env = dict(self.environment, EDR_TEST_DATABASE_URL=prefix + INTEGRATION_URL)
                self.assert_integration_refused(env)

    def test_enrollment_runner_refuses_url_parser_control_character_normalization(self):
        for prefix in ("\n", "\t", " ", "\x7f"):
            with self.subTest(prefix=repr(prefix)):
                env = dict(self.environment, EDR_TEST_DATABASE_URL=prefix + ENROLLMENT_URL)
                self.assert_enrollment_refused(env)

    def test_candidate_explicit_loopback_target_reaches_only_stub_client(self):
        result = self.shell("scripts/ci/candidate-postgres.sh", "test")
        self.assertEqual(result.returncode, 97)
        self.assertEqual(self.client_log.read_text(), "psql\n")

    def test_inventory_explicit_loopback_target_passes_offline_preflight(self):
        result = self.shell("scripts/test-soc-endpoint-inventory-sql.sh", "--preflight-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_no_client()

    def test_integration_explicit_loopback_target_reaches_only_stub_sql(self):
        env = dict(self.environment, EDR_TEST_DATABASE_URL=INTEGRATION_URL)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(self.integration, "sql", side_effect=FirstDatabaseOperation) as sql:
            with self.assertRaises(FirstDatabaseOperation):
                self.integration.run()
            sql.assert_called_once()

    def test_enrollment_runner_explicit_loopback_target_reaches_only_stub_sql(self):
        env = dict(self.environment, EDR_TEST_DATABASE_URL=ENROLLMENT_URL)
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(self.enrollment, "DATABASE", ENROLLMENT_URL), \
             mock.patch.object(self.enrollment, "query", side_effect=FirstDatabaseOperation) as query:
            with self.assertRaises(FirstDatabaseOperation):
                self.enrollment.main()
            query.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
