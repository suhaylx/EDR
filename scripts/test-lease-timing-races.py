#!/usr/bin/env python3
"""Disposable PostgreSQL lease-clock regressions, called by the grant runner.

Uses real runtime connections for supported service operations. The retired
boolean completion and maintenance recovery are tested as fixture administrator;
their denied runtime grants remain covered by test-runtime-privileges.sql.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

ADMIN = os.environ["EDR_TEST_DATABASE_URL"]
RUNTIME = os.environ["EDR_TEST_RUNTIME_CONNECTION"]
PASSWORD = os.environ["EDR_GRANT_TEST_PASSWORD"]
ACTIVE: list["Session"] = []


def safe_text(value: str) -> str:
    for secret in (ADMIN, RUNTIME, PASSWORD):
        value = value.replace(secret, "[redacted connection]")
    return value


def environment(runtime: bool) -> dict[str, str]:
    env = os.environ.copy()
    if runtime:
        env["PGPASSWORD"] = PASSWORD
    return env


def query(sql: str, runtime: bool = False) -> str:
    result = subprocess.run(
        ["psql", RUNTIME if runtime else ADMIN, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
        input=sql, text=True, capture_output=True, env=environment(runtime), timeout=10,
    )
    if result.returncode:
        raise AssertionError("SQL fixture failed: " + safe_text(result.stderr))
    return result.stdout.strip()


def wait_for(check, description: str, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.025)
    raise AssertionError("Did not observe " + description)


class Session:
    def __init__(self, directory: Path, name: str, runtime: bool):
        self.name = name
        self.ready = directory / (name + ".ready")
        self.log_path = directory / (name + ".log")
        self.log = self.log_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            ["psql", RUNTIME if runtime else ADMIN, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=self.log, stderr=subprocess.STDOUT,
            text=True, env=environment(runtime),
        )
        ACTIVE.append(self)
        self.send("BEGIN;\nSELECT set_config('application_name','" + name + "',false);\n")

    def send(self, sql: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(sql)
        self.process.stdin.flush()

    def hold(self, sql: str = "") -> None:
        # psql then waits for the next stdin command with the SQL transaction
        # open. The shell marker runs only after the preceding SQL succeeded.
        self.send(sql + "\n\\! touch " + str(self.ready) + "\n")
        wait_for(lambda: self.ready.exists() or self.process.poll() is not None,
                 "coordinated SQL hold point")
        if not self.ready.exists():
            raise AssertionError("Session ended before hold: " + self.output())

    def finish(self, sql: str = "") -> str:
        self.send(sql + "\nCOMMIT;\n")
        assert self.process.stdin is not None
        self.process.stdin.close()
        self.process.wait(timeout=10)
        output = self.output()
        if self.process.returncode:
            raise AssertionError("Concurrent session failed: " + output)
        return output

    def output(self) -> str:
        self.log.flush()
        return safe_text(self.log_path.read_text(encoding="utf-8"))

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.log.close()


def wait_lock(session: Session, job: str | None = None) -> None:
    def observed() -> bool:
        if session.process.poll() is not None:
            raise AssertionError("Worker ended before expected lock wait: " + session.output())
        return query(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
            "AND application_name='" + session.name + "' AND wait_event_type='Lock';"
        ) == "1"

    wait_for(observed, "PostgreSQL lock wait")
    if job:
        assert query(
            "SELECT s.xact_start<j.lease_expires_at FROM pg_stat_activity s "
            "JOIN public.edr_scan_jobs j ON j.job_id='" + job + "' "
            "WHERE s.datname=current_database() AND s.application_name='" + session.name + "';"
        ) == "t", "Expiry fixture did not begin its transaction before the deadline"


def wait_expired(job: str) -> None:
    wait_for(lambda: query(
        "SELECT clock_timestamp()>=lease_expires_at FROM public.edr_scan_jobs "
        "WHERE job_id='" + job + "';"
    ) == "t", "actual database lease expiry")


def fixture(label: str, *, pending: bool = False, expiry_seconds: int = 2) -> tuple[str, str, str]:
    tenant = "lease_" + label
    job = str(uuid.uuid4())
    token = str(uuid.uuid4())
    values = (
        "'pending',NULL,NULL,NULL,0" if pending else
        "'leased','linux01','" + token + "',clock_timestamp()+interval '" +
        str(expiry_seconds) + " seconds',1"
    )
    query(
        "BEGIN;"
        "INSERT INTO public.edr_tenants(tenant_id,display_name) VALUES('" + tenant + "','Lease timing fixture');"
        "INSERT INTO public.edr_agents(tenant_id,agent_id,platform) VALUES('" + tenant + "','linux01','linux');"
        "INSERT INTO public.edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after) "
        "VALUES('" + tenant + "','linux01',decode(repeat('aa',32),'hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day');"
        "INSERT INTO public.edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,state,lease_owner,lease_token,lease_expires_at,attempt_count)"
        "VALUES('" + job + "','" + tenant + "','linux01','/tmp/synthetic'," + values + ");COMMIT;"
    )
    return tenant, job, token


def authorize(tenant: str) -> str:
    return (
        "IF NOT public.edr_authorize_agent_certificate('" + tenant +
        "','linux01',decode(repeat('aa',32),'hex')) THEN "
        "RAISE EXCEPTION 'valid certificate rejected by timing fixture'; END IF;"
    )


def operation_call(kind: str, tenant: str, job: str, token: str) -> str:
    if kind == "renew":
        return ("public.edr_renew_scan_job_lease('" + tenant + "','linux01','" + job +
                "','linux01','" + token + "',30)")
    if kind == "result":
        return ("public.edr_complete_scan_job_with_result('" + tenant + "','linux01','" +
                job + "','" + token + "','clean_by_signature','','Synthetic protocol result')")
    if kind == "legacy":
        return ("public.edr_complete_scan_job('" + tenant + "','linux01','" + job +
                "','" + token + "',true)")
    raise AssertionError("Unknown test operation")


def expiry_race(directory: Path, kind: str, wait_on: str) -> None:
    tenant, job, token = fixture(kind + "_" + wait_on)
    holder = Session(directory, "lease_admin_" + kind + "_" + wait_on, False)
    if wait_on == "job":
        holder.hold("SELECT job_id FROM public.edr_scan_jobs WHERE job_id='" + job + "' FOR UPDATE;")
    else:
        holder.hold(
            "SELECT agent_id FROM public.edr_agent_certificates WHERE tenant_id='" +
            tenant + "' AND agent_id='linux01' FOR UPDATE;"
        )
    worker = Session(directory, "lease_runtime_" + kind + "_" + wait_on, kind != "legacy")
    worker.send(
        "DO $test$ BEGIN " + authorize(tenant) + "IF " +
        operation_call(kind, tenant, job, token) +
        " THEN RAISE EXCEPTION 'expired lease operation unexpectedly accepted'; END IF; END $test$;\n"
    )
    wait_lock(worker, job)
    wait_expired(job)
    holder.finish()
    worker.finish()
    assert query(
        "SELECT state='leased' AND lease_expires_at<=clock_timestamp() FROM public.edr_scan_jobs "
        "WHERE job_id='" + job + "';"
    ) == "t", "Rejected operation changed the expired lease"
    assert query(
        "SELECT count(*) FROM public.edr_scan_job_results WHERE job_id='" + job + "';"
    ) == "0", "Rejected expired completion persisted a result"
    print("PASS: " + kind + " rejected lease expired during " + wait_on +
          " lock wait (pre-expiry transaction; no mutation).", flush=True)


def fresh_extension(directory: Path, kind: str) -> None:
    tenant, job, token = fixture(kind + "_fresh_time", pending=kind == "claim", expiry_seconds=5)
    holder = Session(directory, "lease_admin_fresh_" + kind, False)
    holder.hold(
        "SELECT agent_id FROM public.edr_agent_certificates WHERE tenant_id='" +
        tenant + "' AND agent_id='linux01' FOR UPDATE;"
    )
    worker = Session(directory, "lease_runtime_fresh_" + kind, True)
    if kind == "claim":
        operation = (
            "SELECT job_id INTO selected_job FROM public.edr_claim_scan_job('" + tenant +
            "','linux01','linux01','" + token + "',5);"
            "IF selected_job IS DISTINCT FROM '" + job +
            "'::uuid THEN RAISE EXCEPTION 'claim did not acquire expected job'; END IF;"
        )
        seconds = 5
    else:
        operation = (
            "IF NOT " + operation_call("renew", tenant, job, token) +
            " THEN RAISE EXCEPTION 'live lease renewal failed'; END IF;"
        )
        seconds = 30
    worker.send("DO $test$ DECLARE selected_job uuid; BEGIN " +
                authorize(tenant) + operation + "END $test$;\n")
    wait_lock(worker)
    release_time = query("SELECT clock_timestamp();")
    holder.finish()
    worker.finish()
    assert query(
        "SELECT lease_expires_at>='" + release_time + "'::timestamptz+interval '" +
        str(seconds) + " seconds' AND updated_at>='" + release_time +
        "'::timestamptz FROM public.edr_scan_jobs WHERE job_id='" + job + "';"
    ) == "t", "Lease duration/update time incorrectly used transaction BEGIN"
    print("PASS: " + kind + " used fresh time after authorization wait for full lease duration.", flush=True)


def recovery_clock_and_skip_locked(directory: Path) -> None:
    tenant, locked_job, _ = fixture("recovery_clock")
    free_job = str(uuid.uuid4())
    query(
        "INSERT INTO public.edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,state,lease_owner,lease_token,lease_expires_at,attempt_count)"
        "SELECT '" + free_job + "',tenant_id,agent_id,scan_root,state,lease_owner,gen_random_uuid(),lease_expires_at,attempt_count "
        "FROM public.edr_scan_jobs WHERE job_id='" + locked_job + "';"
    )
    holder = Session(directory, "lease_admin_recovery_lock", False)
    holder.hold("SELECT job_id FROM public.edr_scan_jobs WHERE job_id='" + locked_job + "' FOR UPDATE;")
    maintenance = Session(directory, "lease_maintenance_clock", False)
    maintenance.hold()
    assert query(
        "SELECT s.xact_start<j.lease_expires_at FROM pg_stat_activity s "
        "JOIN public.edr_scan_jobs j ON j.job_id='" + free_job +
        "' WHERE s.application_name='lease_maintenance_clock' AND s.datname=current_database();"
    ) == "t", "Maintenance fixture did not begin before lease expiry"
    wait_expired(free_job)
    maintenance.finish("SELECT public.edr_recover_expired_scan_jobs(1000);")
    assert query("SELECT state FROM public.edr_scan_jobs WHERE job_id='" + free_job + "';") == "pending"
    assert query("SELECT state FROM public.edr_scan_jobs WHERE job_id='" + locked_job + "';") == "leased"
    holder.finish()
    query("SELECT public.edr_recover_expired_scan_jobs(1000);")
    assert query("SELECT state FROM public.edr_scan_jobs WHERE job_id='" + locked_job + "';") == "pending"
    print("PASS: maintenance used fresh expiry time and skipped the concurrently locked job.", flush=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="edr-lease-races-") as temporary:
        directory = Path(temporary)
        try:
            for kind, wait_on in (
                ("renew", "job"), ("result", "job"), ("legacy", "job"),
                ("renew", "certificate"), ("result", "certificate"),
            ):
                expiry_race(directory, kind, wait_on)
            fresh_extension(directory, "claim")
            fresh_extension(directory, "renew")
            recovery_clock_and_skip_locked(directory)
        finally:
            for session in ACTIVE:
                session.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit("FAIL: lease timing regression: " + safe_text(str(error))) from None
