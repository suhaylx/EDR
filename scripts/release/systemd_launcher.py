#!/usr/bin/env python3
"""Map systemd read-only credential files to the existing Go/Rust interfaces.

No credential values are printed or copied into environment variables. The
service manager provides CREDENTIALS_DIRECTORY and, for Go, RUNTIME_DIRECTORY.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit


SERVER_CREDENTIALS = {
    "server_cert_file": "server-cert.pem", "server_key_file": "server-key.pem",
    "agent_ca_file": "agent-ca.pem", "operator_ca_file": "operator-ca.pem",
    "registry_dsn_file": "registry.dsn", "runtime_dsn_file": "runtime.dsn",
}
AGENT_CREDENTIALS = {"ca_file": "server-ca.pem", "cert_file": "agent-cert.pem", "key_file": "agent-key.pem"}


def regular_file(path: Path, private: bool = False, limit: int = 1 << 20) -> bytes:
    # File-type validation must not block on a FIFO before reaching fstat.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Required file is non-regular, empty or oversized")
        if private and info.st_mode & 0o077:
            raise ValueError("Private files require owner-only permissions")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
            if not 0 < len(data) <= limit:
                raise ValueError("Required file changed or exceeded its size limit")
            return data
    finally:
        os.close(fd)


def read_json(path: Path) -> dict:
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate configuration field")
            result[key] = value
        return result
    value = json.loads(regular_file(path, private=True, limit=16 << 10), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a JSON object")
    return value


def loopback_listener(value: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise ValueError("Listener must be a numeric loopback address and port")
    host, separator, port = value.rpartition(":")
    host = host.strip("[]")
    try:
        number = int(port)
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("Listener must be a numeric loopback address and port") from None
    if not separator or not address.is_loopback or not 1024 <= number <= 65535:
        raise ValueError("Listener must be an unprivileged numeric loopback address and port")
    return str(address), number


def loopback_origin(value: str) -> str:
    try:
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname or "")
        port = url.port or 443
        valid = (url.scheme == "https" and address.is_loopback and 1024 <= port <= 65535
                 and not url.username and not url.password and url.path in ("", "/")
                 and not url.query and not url.fragment)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("Origin must be a bare HTTPS numeric loopback origin on an unprivileged port")
    return value.rstrip("/")


def validate_server(config: dict) -> None:
    required = {*SERVER_CREDENTIALS, "ui_dir"}
    if set(config) - (required | {"agent_listen", "soc_listen"}) or not required.issubset(config):
        raise ValueError("Unexpected or missing server configuration field")
    agent = loopback_listener(config.get("agent_listen", "127.0.0.1:9443"))
    soc = loopback_listener(config.get("soc_listen", "127.0.0.1:9444"))
    if agent == soc or config["registry_dsn_file"] == config["runtime_dsn_file"]:
        raise ValueError("Distinct listeners and database credential files are required")


def validate_agent(config: dict) -> None:
    required = {*AGENT_CREDENTIALS, "origin", "tenant_id", "agent_id", "scan_root", "clamd_socket", "max_jobs", "read_groups"}
    if set(config) != required:
        raise ValueError("Unexpected or missing agent configuration field")
    loopback_origin(config["origin"])
    for key in ("tenant_id", "agent_id"):
        if (not isinstance(config[key], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", config[key])
                or config[key] in (".", "..")):
            raise ValueError("Enrolled tenant and agent identifiers are required")
    if type(config["max_jobs"]) is not int or not 1 <= config["max_jobs"] <= 20:
        raise ValueError("Agent batch size must be 1..20")
    groups = config["read_groups"]
    if (not isinstance(groups, list) or not 1 <= len(groups) <= 8
            or not all(isinstance(group, str) for group in groups) or len(set(groups)) != len(groups)):
        raise ValueError("Explicit scan/socket read groups are required")
    forbidden = {"root", "sudo", "wheel", "disk", "shadow", "docker", "lxd", "adm", "systemd-journal"}
    if any(not isinstance(group, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", group) or group in forbidden for group in groups):
        raise ValueError("Invalid or privileged agent read group")
    for key in ("scan_root", "clamd_socket"):
        if not isinstance(config[key], str) or not Path(config[key]).is_absolute() or ".." in Path(config[key]).parts:
            raise ValueError("Agent paths must be absolute")
    if Path(config["scan_root"]) == Path("/"):
        raise ValueError("Filesystem root is not an approved scan root")


def credential_directory(environment: dict) -> Path:
    value = environment.get("CREDENTIALS_DIRECTORY", "")
    directory = Path(value)
    if not value or not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError("systemd credential directory is required")
    return directory


def launch_plan(component: str, prefix: Path, action: str | None, environment: dict) -> tuple[list[str], dict]:
    prefix = prefix.resolve(strict=True)
    current = (prefix / "current").resolve(strict=True)
    if current.parent != prefix / "releases":
        raise ValueError("Current release is outside the managed release directory")
    credentials = credential_directory(environment)
    config = read_json(credentials / "config.json")
    clean_environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    if component == "server":
        validate_server(config)
        for key, name in SERVER_CREDENTIALS.items():
            private = key in ("server_key_file", "registry_dsn_file", "runtime_dsn_file")
            regular_file(credentials / name, private=private)
            config[key] = str(credentials / name)
        config["ui_dir"] = str(current / "web")
        runtime = Path(environment.get("RUNTIME_DIRECTORY", ""))
        if not runtime.is_absolute() or runtime.is_symlink() or not runtime.is_dir():
            raise ValueError("systemd private runtime directory is required")
        if runtime.stat().st_uid != os.getuid() or runtime.stat().st_mode & 0o077:
            raise ValueError("Runtime directory must be private to the service identity")
        path = runtime / "edrd.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", closefd=False, encoding="utf-8") as stream:
                json.dump(config, stream)
                stream.flush()
        finally:
            os.close(fd)
        return [str(current / "bin" / "edrd"), "--config", str(path)], clean_environment
    validate_agent(config)
    for key, name in AGENT_CREDENTIALS.items():
        regular_file(credentials / name, private=(key == "key_file"))
    clean_environment.update({
        "TURANSEC_MTLS_ORIGIN": loopback_origin(config["origin"]),
        "TURANSEC_MTLS_TENANT_ID": config["tenant_id"],
        "TURANSEC_MTLS_AGENT_ID": config["agent_id"],
        "TURANSEC_MTLS_CA_PEM": str(credentials / "server-ca.pem"),
        "TURANSEC_MTLS_CERT_PEM": str(credentials / "agent-cert.pem"),
        "TURANSEC_MTLS_KEY_PEM": str(credentials / "agent-key.pem"),
        "TURANSEC_LAB_SCAN_ROOT": config["scan_root"],
        "TURANSEC_CLAMD_SOCKET": config["clamd_socket"],
    })
    arguments = {"heartbeat": ["--heartbeat-mtls"], "scanner-health": ["--clamav-health"],
                 "scan": ["--scan-batch-mtls", str(config["max_jobs"])]}
    if action not in arguments:
        raise ValueError("An explicit bounded agent action is required")
    return [str(current / "bin" / "turansec-edr-agent"), *arguments[action]], clean_environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=("server", "agent"))
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--action", choices=("heartbeat", "scanner-health", "scan"))
    args = parser.parse_args()
    try:
        command, environment = launch_plan(args.component, args.prefix, args.action, dict(os.environ))
        os.execve(command[0], command, environment)
    except (OSError, ValueError, TypeError, KeyError):
        print("TuranSec service preflight failed; verify managed files and credential permissions", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
