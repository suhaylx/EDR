#!/usr/bin/env python3
"""Bounded external Rust protocol probe against verified real ClamAV.

No product source edits, broad host scan, network exposure, database download,
installed service or claim of native host acceptance. Start every process from
this script so the isolated executor's network namespace is shared.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent / "host-work"
VENDOR = WORK / "clamav-root/usr/local"
SHA = "fb0891f98919fd0a166ff10427088f195d208225"
REPORT = ROOT / "real-clamd-adapter-result.json"
PROBE = ROOT / "adapter-target/debug/real_clamd_probe"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    os.umask(0o077)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(VENDOR / "lib")
    env["CVD_CERTS_DIR"] = str(VENDOR / "etc/certs")
    report = {
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_sha": SHA,
        "execution_os": platform.platform(),
        "execution_class": "isolated Linux executor; external protocol acceptance probe",
        "status": "FAIL",
        "checks": [],
        "product_scan_command_exercised": False,
        "integrated_backend_postgresql_ui_path_exercised": False,
        "native_deployment_host_acceptance": False,
        "signature_database_health_complete": False,
        "limits": [
            "The unchanged candidate clamav.rs and scan_jobs.rs modules are exercised by an external probe.",
            "The product's Unix socket transport is not exercised; Unix sockets are prohibited in this executor.",
            "Only signed daily and bytecode databases are present; main.cvd is missing after vendor CDN cooldown.",
            "This is not Windows/Ubuntu deployment-host, installed-service, rollback or deployment-authorization evidence.",
        ],
    }
    daemon = None
    try:
        assert PROBE.is_file(), "compiled external probe missing"
        assert digest(WORK / "eicar.com") == EICAR_SHA, "refusing a non-EICAR fixture"
        assert (WORK / "eicar.com").stat().st_size == 68, "EICAR size mismatch"
        expected_deb = "fff17fb1f8917d1ea1308c9736dabe376077458aba000a5dadcce7193a8c538c"
        assert digest(WORK / "clamav-1.5.5.linux.x86_64.deb") == expected_deb, "vendor archive changed"
        report["vendor_archive_sha256"] = expected_deb
        report["vendor_pgp_fingerprint"] = "5BADCA2665EF59DCF8A23D8B707F0DB480836771"
        report["vendor_pgp_evidence"] = "../host-work/clamav-pgp-verification.log"
        report["clamd_sha256"] = digest(VENDOR / "sbin/clamd")
        report["probe_sha256"] = digest(PROBE)
        report["database_checks"] = []
        for name in ("daily.cvd", "bytecode.cvd"):
            database = WORK / "signature-db" / name
            result = subprocess.run([str(VENDOR / "bin/sigtool"), "--verify", str(database)],
                                    env=env, text=True, capture_output=True, timeout=30)
            log = ROOT / (name + ".verify.log")
            log.write_text(result.stdout + result.stderr)
            report["database_checks"].append({"name": name, "sha256": digest(database),
                                               "vendor_signature_exit": result.returncode,
                                               "evidence": log.name})
            assert result.returncode == 0, "vendor database signature verification failed"
        report["checks"].append({"check": "genuine daily and bytecode database signatures", "status": "PASS"})
        with tempfile.TemporaryDirectory(prefix="isolated-clamd-", dir=ROOT) as temp:
            tmp = Path(temp)
            benign = tmp / "benign.txt"
            benign.write_text("TuranSec isolated benign acceptance fixture.\n")
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            config = tmp / "clamd.conf"
            config.write_text(
                "Foreground yes\nTCPAddr 127.0.0.1\nTCPSocket " + str(port) + "\n"
                "DatabaseDirectory " + str(WORK / "signature-db") + "\n"
                "CVDCertsDirectory " + str(VENDOR / "etc/certs") + "\n"
                "TemporaryDirectory " + str(tmp) + "\nMaxThreads 2\nStreamMaxLength 1M\n"
                "LogTime yes\n"
            )
            with (ROOT / "clamd-tcp-runtime.log").open("w") as daemon_log:
                daemon = subprocess.Popen([str(VENDOR / "sbin/clamd"), "--config-file", str(config)],
                                          env=env, stdout=daemon_log, stderr=daemon_log)
                ready = False
                for _ in range(200):
                    assert daemon.poll() is None, "clamd stopped before readiness"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as conn:
                            conn.sendall(b"zPING\0")
                            ready = conn.recv(32) == b"PONG\0"
                        if ready:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                assert ready, "real clamd did not become ready"
                report["checks"].append({"check": "real vendor clamd loopback TCP PING", "status": "PASS"})
                result = subprocess.run([str(PROBE), str(port), str(benign), str(WORK / "eicar.com")],
                                        env=env, text=True, capture_output=True, timeout=60)
                (ROOT / "rust-real-clamd-probe.log").write_text(result.stdout + result.stderr)
                assert result.returncode == 0, "Rust adapter actual daemon probe failed"
                report["real_scan_results"] = json.loads(result.stdout)
                report["checks"].extend([
                    {"check": "unchanged candidate Rust adapter real benign scan", "status": "PASS"},
                    {"check": "unchanged candidate Rust adapter real EICAR detection", "status": "PASS"},
                ])
                daemon.terminate()
                daemon.wait(timeout=12)
                daemon = None
                unavailable = subprocess.run([str(PROBE), str(port), str(benign), str(WORK / "eicar.com")],
                                             env=env, text=True, capture_output=True, timeout=10)
                (ROOT / "rust-clamd-unavailable.log").write_text(unavailable.stdout + unavailable.stderr)
                assert unavailable.returncode != 0 and "Connection refused" in unavailable.stderr, "missing daemon not rejected"
                report["checks"].append({"check": "real stopped daemon produces connection error, never clean", "status": "PASS"})
            report["benign_sha256"] = digest(benign)
            report["eicar_sha256"] = EICAR_SHA
        report["status"] = "PASS_WITH_SCOPE_LIMITS"
    except Exception as exc:
        report["error"] = str(exc) if isinstance(exc, AssertionError) else type(exc).__name__
    finally:
        if daemon is not None:
            daemon.terminate()
            try:
                daemon.wait(timeout=12)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
        REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks_passed": len(report["checks"]),
                      "error": report.get("error"), "report": str(REPORT)}))
    return 0 if report["status"] == "PASS_WITH_SCOPE_LIMITS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
