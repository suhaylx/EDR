#!/usr/bin/env python3
"""Enrollment deadline regressions on one empty, disposable loopback database.

Real PostgreSQL transaction/row-lock waits are observed before releasing each
fixture. Historical migrations supply negative controls, then 0014 is applied.
No production service, network endpoint or issuer credentials are exercised.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
DATABASE = os.environ.get("EDR_TEST_DATABASE_URL", "")
ACTIVE: list["Session"] = []


def preflight() -> None:
    try:
        target = urlsplit(DATABASE)
        safe = (
            os.environ.get("EDR_QA_DISPOSABLE_DB") == "yes"
            and not any(os.environ.get(key) for key in
                        ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"))
            and not any(ord(char) <= 32 or ord(char) == 127 for char in DATABASE)
            and target.scheme == "postgresql" and target.hostname == "127.0.0.1"
            and target.port == 5432
            and target.path == "/edr_candidate_enrollment_wallclock"
            and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", target.username or "")
            and target.password is None and not target.fragment
            and target.query in ("", "sslmode=disable")
        )
    except ValueError:
        safe = False
    if not safe:
        raise RuntimeError("refusing nonlocal, redirected or nondisposable enrollment test database")


def safe_text(value: str) -> str:
    for secret in (DATABASE, os.environ.get("PGPASSWORD", "")):
        if secret:
            value = value.replace(secret, "[redacted]")
    return value


def environment(name: str = "edr_clock_query") -> dict[str, str]:
    env = os.environ.copy()
    env.update(PGAPPNAME=name, PGCONNECT_TIMEOUT="5",
               PGOPTIONS="-c statement_timeout=45000 -c lock_timeout=35000")
    return env


def psql() -> list[str]:
    return ["psql", DATABASE, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"]


def query(statement: str) -> str:
    result = subprocess.run(psql(), input=statement, text=True,
                            capture_output=True, env=environment(), timeout=15)
    if result.returncode:
        raise AssertionError("SQL regression failed: " + safe_text(result.stderr))
    return result.stdout.strip()


def sql_file(path: Path) -> None:
    result = subprocess.run(psql() + ["-f", str(path)], cwd=ROOT, text=True,
                            capture_output=True, env=environment(), timeout=60)
    if result.returncode:
        raise AssertionError(path.name + " failed: " + safe_text(result.stderr))
    print("PASS: " + path.name, flush=True)


def wait_for(check, description: str) -> None:
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.025)
    raise AssertionError("Did not observe " + description)


class Session:
    def __init__(self, directory: Path, label: str):
        self.name = "edr_clock_" + label + "_" + uuid.uuid4().hex[:8]
        self.log_path = directory / (self.name + ".log")
        self.log = self.log_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            psql(), stdin=subprocess.PIPE, stdout=self.log, stderr=subprocess.STDOUT,
            text=True, env=environment(self.name),
        )
        ACTIVE.append(self)
        self.send("BEGIN;\n")

    def send(self, statement: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(statement)
        self.process.stdin.flush()

    def output(self) -> str:
        self.log.flush()
        return safe_text(self.log_path.read_text(encoding="utf-8"))

    def hold(self, statement: str = "") -> None:
        self.send(statement + "\nSELECT 1 AS edr_clock_hold;\n")

        def ready() -> bool:
            if self.process.poll() is not None:
                raise AssertionError("Session ended before hold: " + self.output())
            # Observe database state instead of relying on psql stdout flushing.
            return query(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                "AND application_name='" + self.name + "' AND state='idle in transaction' "
                "AND query LIKE 'SELECT 1 AS edr_clock_hold%';"
            ) == "1"

        wait_for(ready, "SQL transaction hold point")

    def finish(self, statement: str = "") -> None:
        self.send(statement + "\nCOMMIT;\n")
        assert self.process.stdin is not None
        self.process.stdin.close()
        self.process.wait(timeout=15)
        if self.process.returncode:
            raise AssertionError("Concurrent SQL failed: " + self.output())

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.log.close()


def fixture(kind: str, label: str, *, challenge_expires: bool = False) -> tuple[str, str]:
    tenant = "clock_" + label
    challenge = str(uuid.uuid4())
    digest = uuid.uuid4().hex * 2
    query(
        "BEGIN; INSERT INTO public.edr_tenants(tenant_id,display_name) VALUES('" +
        tenant + "','Enrollment deadline fixture');"
        "INSERT INTO public.edr_clock_fixture VALUES('" + tenant + "','" + challenge +
        "',decode('" + digest + "','hex'),clock_timestamp()+interval '3 seconds');"
        "INSERT INTO public.edr_enrollment_challenges(challenge_id,tenant_id,agent_id,challenge_digest,expires_at) "
        "SELECT challenge,tenant,'linux01',digest," +
        ("deadline" if kind == "consume" or challenge_expires else "clock_timestamp()+interval '1 hour'") +
        " FROM public.edr_clock_fixture WHERE tenant='" + tenant + "';" +
        ("INSERT INTO public.edr_agents(tenant_id,agent_id,platform) VALUES('" + tenant + "','linux01','linux');"
         "INSERT INTO public.edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after) "
         "VALUES('" + tenant + "','linux01',decode(repeat('aa',32),'hex'),"
         "clock_timestamp()-interval '1 day',clock_timestamp()+interval '1 day');" if kind == "rotate" else "") +
        "COMMIT;"
    )
    return tenant, challenge


def operation(kind: str, tenant: str, challenge: str, *, challenge_expires: bool = False) -> str:
    digest = "(SELECT digest FROM public.edr_clock_fixture WHERE tenant='" + tenant + "')"
    deadline = "(SELECT deadline FROM public.edr_clock_fixture WHERE tenant='" + tenant + "')"
    if kind == "consume":
        return "public.edr_consume_enrollment_challenge('" + challenge + "','" + tenant + "','linux01'," + digest + ")"
    if kind == "enroll":
        return ("public.edr_complete_agent_enrollment('" + challenge + "','" + tenant +
                "','linux01'," + digest + ",'linux',decode(repeat('bb',32),'hex'),"
                "clock_timestamp()-interval '1 day'," +
                ("clock_timestamp()+interval '1 day'" if challenge_expires else deadline) + ",'fixture-issuer')")
    return ("public.edr_rotate_agent_certificate('" + tenant +
            "','linux01',decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),"
            "clock_timestamp()-interval '1 day'," + deadline + ",'fixture-issuer')")


def assertion(kind: str, call: str, *, old: bool = False) -> str:
    if kind == "rotate" and not old:
        return ("DO $check$ BEGIN BEGIN PERFORM " + call +
                "; RAISE EXCEPTION 'expired replacement accepted';"
                " EXCEPTION WHEN invalid_parameter_value THEN NULL; END; END $check$;\n")
    return ("DO $check$ BEGIN IF " + call + " IS DISTINCT FROM " +
            ("true" if old else "false") +
            " THEN RAISE EXCEPTION 'unexpected enrollment deadline decision'; END IF; END $check$;\n")


def snapshot(tenant: str) -> str:
    return query(
        "SELECT json_build_object('consumed',(SELECT consumed_at FROM public.edr_enrollment_challenges WHERE tenant_id='" + tenant + "'),"
        "'agents',(SELECT count(*) FROM public.edr_agents WHERE tenant_id='" + tenant + "'),"
        "'certificates',(SELECT count(*) FROM public.edr_agent_certificates WHERE tenant_id='" + tenant + "'),"
        "'revoked',(SELECT count(*) FROM public.edr_agent_certificates WHERE tenant_id='" + tenant + "' AND revoked_at IS NOT NULL),"
        "'audit',(SELECT count(*) FROM public.edr_enrollment_audit WHERE tenant_id='" + tenant + "'))::text;"
    )


def transaction_before_deadline(session: Session, tenant: str) -> None:
    assert query(
        "SELECT s.xact_start<f.deadline FROM pg_stat_activity s CROSS JOIN public.edr_clock_fixture f "
        "WHERE s.datname=current_database() AND s.application_name='" + session.name +
        "' AND f.tenant='" + tenant + "';"
    ) == "t", "Fixture transaction did not start before expiry"


def wait_expired(tenant: str) -> None:
    wait_for(lambda: query("SELECT clock_timestamp()>=deadline FROM public.edr_clock_fixture WHERE tenant='" +
                           tenant + "';") == "t", "actual database deadline expiry")


def wait_lock(session: Session) -> None:
    def observed() -> bool:
        if session.process.poll() is not None:
            raise AssertionError("Worker ended before row-lock wait: " + session.output())
        return query("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                     "AND application_name='" + session.name + "' AND wait_event_type='Lock';") == "1"
    wait_for(observed, "PostgreSQL row-lock wait")


def expiry_case(directory: Path, kind: str, wait_on: str, *, old: bool = False,
                challenge_expires: bool = False) -> None:
    label = ("old_" if old else "fixed_") + kind + "_" + wait_on + ("_challenge_expiry" if challenge_expires else "")
    tenant, challenge = fixture(kind, label, challenge_expires=challenge_expires)
    before = snapshot(tenant)
    holder = None
    if wait_on != "transaction":
        holder = Session(directory, "holder")
        table, predicate = {
            "tenant": ("edr_tenants", "tenant_id='" + tenant + "'"),
            "agent": ("edr_agents", "tenant_id='" + tenant + "'"),
            "challenge": ("edr_enrollment_challenges", "challenge_id='" + challenge + "'"),
            "certificate": ("edr_agent_certificates", "tenant_id='" + tenant + "'"),
        }[wait_on]
        holder.hold("SELECT 1 FROM public." + table + " WHERE " + predicate + " FOR UPDATE;")
    worker = Session(directory, "worker")
    call = assertion(kind, operation(kind, tenant, challenge, challenge_expires=challenge_expires), old=old)
    if holder:
        worker.send(call)
        wait_lock(worker)
    else:
        worker.hold()
    transaction_before_deadline(worker, tenant)
    wait_expired(tenant)
    if holder:
        holder.finish()
        worker.finish()
    else:
        worker.finish(call)
    if not old:
        assert snapshot(tenant) == before, "Denied operation changed enrollment/certificate/audit state"
    print("PASS: " + ("historical negative control observed " if old else "fixed denial without mutation: ") +
          kind + " after " + wait_on + " wait" + (" (challenge expired)" if challenge_expires else ""), flush=True)


def tenant_disable_case(directory: Path) -> None:
    tenant, challenge = fixture("enroll", "tenant_disable")
    before = snapshot(tenant)
    holder = Session(directory, "disable")
    holder.hold("UPDATE public.edr_tenants SET disabled_at=clock_timestamp() WHERE tenant_id='" + tenant + "';")
    worker = Session(directory, "consume_disabled")
    worker.send(assertion("consume", operation("consume", tenant, challenge)))
    wait_lock(worker)
    holder.finish()
    worker.finish()
    assert snapshot(tenant) == before, "Tenant-disable denial consumed challenge"
    print("PASS: standalone consumption waits for tenant disablement and denies without mutation", flush=True)


def main() -> None:
    preflight()
    assert query("SHOW server_version_num;").startswith("16"), "PostgreSQL 16 is required"
    assert query("SELECT count(*) FROM pg_class WHERE relname LIKE 'edr_%' AND relname<>'edr_ci_candidate' AND relkind='r';") == "0", "Database is not empty"
    for path in sorted((ROOT / "backend/migrations").glob("*.up.sql")):
        if path.name < "0014_":
            sql_file(path)
    query("CREATE TABLE public.edr_clock_fixture(tenant text PRIMARY KEY,challenge uuid NOT NULL,digest bytea NOT NULL,deadline timestamptz NOT NULL);")
    with tempfile.TemporaryDirectory(prefix="edr-enrollment-clock-") as temp:
        directory = Path(temp)
        try:
            for kind in ("consume", "enroll", "rotate"):
                expiry_case(directory, kind, "transaction", old=True)
            sql_file(ROOT / "backend/migrations/0014_enrollment_wallclock.up.sql")
            for kind, wait_on in (
                ("consume", "transaction"), ("consume", "challenge"), ("consume", "tenant"),
                ("enroll", "transaction"), ("enroll", "tenant"), ("enroll", "challenge"),
                ("rotate", "transaction"), ("rotate", "tenant"), ("rotate", "agent"),
                ("rotate", "certificate"),
            ):
                expiry_case(directory, kind, wait_on)
            expiry_case(directory, "enroll", "challenge", challenge_expires=True)
            tenant_disable_case(directory)
            sql_file(ROOT / "scripts/test-enrollment-wallclock.sql")
        finally:
            for session in ACTIVE:
                session.close()
    print("PASS: 3 historical controls, 12 corrected timing/authorization schedules and SQL upgrade contracts", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit("FAIL: enrollment deadline regression: " + safe_text(str(error))) from None
