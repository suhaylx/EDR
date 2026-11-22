#!/usr/bin/env python3
"""Stage, register and explicitly activate a verified Linux EDR candidate.

Staging/registration do not start services. Activation requires an operator
health identity and preserves the previous complete release on failure. This
tool does not create credentials, change schema, or grant deployment approval.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
from functools import wraps
import grp
import hashlib
import importlib.util
import inspect
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

from release_switch import ActivationRolledBack, RollbackFailed, switch_release
from systemd_launcher import (AGENT_CREDENTIALS, SERVER_CREDENTIALS, loopback_origin,
                             read_json, regular_file, validate_agent, validate_server)


spec = importlib.util.spec_from_file_location("package_candidate", Path(__file__).with_name("package-candidate.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

UNIT_NAMES = {"turansec-edrd.service", "turansec-agent.service", "turansec-agent.timer"}
MAX_ARCHIVE_BYTES = 1 << 30
REQUIRED_FILES = {
    "bin/edrd", "bin/turansec-edr-agent", "web/index.html",
    "scripts/release/systemd_launcher.py", "docs/INSTALLATION.md",
    "packaging/linux/turansec-edrd.service.in",
    "packaging/linux/turansec-agent.service.in", "packaging/linux/turansec-agent.timer.in",
}


def exclusive(operation):
    """Serialize filesystem and service state changes, including initial install."""
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        bound = inspect.signature(operation).bind(self, *args, **kwargs)
        if bound.arguments.get("dry_run", False):
            return operation(self, *args, **kwargs)
        with self.lock():
            return operation(self, *args, **kwargs)
    return wrapped


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def atomic_write(path: Path, value: bytes, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".edr-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def simple_path(value: str | Path) -> Path:
    text = str(value)
    path = Path(text)
    if (not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", text)
            or ".." in path.parts or str(path) != text or path == Path("/")):
        raise ValueError("Use an absolute normalized path without whitespace or shell/systemd metacharacters")
    return path


def trusted_path(path: Path, *, must_exist: bool = True, extra_owners: set[int] | None = None) -> None:
    """Reject writable/symlinked ancestors; root-owned sticky /tmp is allowed."""
    path = simple_path(path)
    for item in reversed((path, *path.parents)):
        if not item.exists():
            if item == path and must_exist:
                raise ValueError("Required managed path does not exist")
            continue
        info = item.lstat()
        sticky_temp = (item == Path("/tmp") and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        owners = {0, os.geteuid()} | (extra_owners or set())
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in owners or (info.st_mode & 0o022 and not sticky_temp):
            raise ValueError("Managed path has a symlink, untrusted owner or writable ancestor")


def read_owned_json(path: Path) -> dict:
    trusted_path(path)
    return json.loads(regular_file(path, private=True, limit=4 << 20))


def catalog(data: dict) -> dict[str, dict]:
    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("target") != "linux-x86_64":
        raise ValueError("This installer requires the Linux x86_64 candidate manifest")
    package.checked_sha(data.get("source_sha", ""))
    rows = data.get("files")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10000:
        raise ValueError("Invalid package file inventory")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}:
            raise ValueError("Invalid package file record")
        name = row["path"]
        if not isinstance(name, str) or len(name) > 512 or "\\" in name:
            raise ValueError("Unsafe package member path")
        path = PurePosixPath(name)
        if path.is_absolute() or not path.parts or ".." in path.parts or str(path) != name:
            raise ValueError("Unsafe package member path")
        if name in result or type(row["size"]) is not int or not 0 <= row["size"] <= MAX_ARCHIVE_BYTES:
            raise ValueError("Duplicate or oversized package member")
        if not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ValueError("Invalid package member digest")
        result[name] = row
    if not REQUIRED_FILES.issubset(result) or sum(row["size"] for row in rows) > MAX_ARCHIVE_BYTES:
        raise ValueError("Incomplete or oversized installable candidate")
    return result


def validate_archive(archive: Path, inventory: dict[str, dict]) -> None:
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if (not member.isfile() or member.name not in inventory or member.name in seen
                    or member.mode & 0o7000 or member.size != inventory[member.name]["size"]):
                raise ValueError("Archive contains an unsafe, extra or duplicate member")
            contents = source.extractfile(member)
            if contents is None:
                raise ValueError("Cannot read package member")
            with contents:
                actual = hashlib.file_digest(contents, "sha256").hexdigest()
            if actual != inventory[member.name]["sha256"]:
                raise ValueError("Package member digest mismatch")
            seen.add(member.name)
    if seen != set(inventory):
        raise ValueError("Archive does not match its complete file inventory")


def copy_bounded(source: Path, target: Path, limit: int) -> None:
    # Open FIFOs without waiting for a writer so fstat can reject them below.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Package input is non-regular, empty or oversized")
        total = 0
        with os.fdopen(fd, "rb", closefd=False) as incoming, target.open("xb") as outgoing:
            while chunk := incoming.read(1 << 20):
                total += len(chunk)
                if total > limit:
                    raise ValueError("Package input grew beyond its limit")
                outgoing.write(chunk)
    finally:
        os.close(fd)


@contextmanager
def verified_bundle(archive: Path, manifest: Path, expected_sha: str, *, signature: Path | None = None,
                    trusted_key: Path | None = None, unsigned_lab: bool = False, manifest_sha256: str | None = None):
    expected_sha = package.checked_sha(expected_sha)
    # Snapshot input bytes into an owner-only temporary directory. Verification
    # and extraction never reopen mutable files from the download directory.
    with tempfile.TemporaryDirectory(prefix="edr-verified-") as temporary:
        work = Path(temporary)
        archive_copy = work / archive.name
        manifest_copy = work / "manifest.json"
        copy_bounded(archive, archive_copy, MAX_ARCHIVE_BYTES)
        copy_bounded(manifest, manifest_copy, 4 << 20)
        manifest_digest = package.digest(manifest_copy)
        if unsigned_lab:
            if signature or trusted_key or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256 or ""):
                raise ValueError("Unsigned lab staging requires an independent manifest SHA-256 pin and no signing arguments")
            if manifest_digest != manifest_sha256:
                raise ValueError("Unsigned lab manifest does not match the approved checksum")
            trust = {"publisher_signature": "not-present", "unsigned_lab": True}
        else:
            if not signature or not trusted_key or manifest_sha256:
                raise ValueError("A detached publisher signature and independent trusted public key are required")
            trusted_path(trusted_key)
            key_copy = work / "publisher.pem"
            signature_copy = work / "manifest.sig"
            copy_bounded(trusted_key, key_copy, 64 << 10)
            copy_bounded(signature, signature_copy, 64 << 10)
            result = package.verify(archive_copy, manifest_copy, signature_copy, key_copy, expected_sha)
            trust = {"publisher_signature": "verified", "unsigned_lab": False,
                     "trusted_public_key_sha256": result["trusted_public_key_sha256"]}
        data = json.loads(manifest_copy.read_text(encoding="utf-8"))
        inventory = catalog(data)
        item = data.get("archive", {})
        if (data["source_sha"] != expected_sha or item.get("name") != archive.name
                or item.get("size") != archive_copy.stat().st_size
                or item.get("sha256") != package.digest(archive_copy)):
            raise ValueError("Archive identity does not match the requested candidate")
        validate_archive(archive_copy, inventory)
        trust["manifest_sha256"] = manifest_digest
        yield data, archive_copy, trust


class Systemd:
    """Actual host operations; the CLI never substitutes a test implementation."""
    def call(self, *arguments: str, timeout: int = 90) -> str:
        result = subprocess.run(["systemctl", *arguments], check=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return result.stdout.strip()

    def reload(self):
        self.call("daemon-reload")

    def stop(self, unit):
        self.call("stop", unit)

    def disable(self, unit):
        self.call("disable", unit)

    def start(self, unit):
        self.call("start", unit, timeout=930)

    def restart(self, unit):
        self.call("restart", unit)

    def assert_units(self, paths):
        for name, path in paths.items():
            values = self.call("show", name, "--property=FragmentPath,DropInPaths")
            state = dict(line.split("=", 1) for line in values.splitlines() if "=" in line)
            if state.get("FragmentPath") != str(path) or state.get("DropInPaths"):
                raise ValueError("Unmanaged systemd fragment or drop-in overrides the requested service")

    def ensure_absent(self, names):
        for name in names:
            # systemctl documents status 4 for an unknown unit. Inspect the
            # properties as well: a failed manager connection is not absence.
            result = subprocess.run(["systemctl", "show", name, "--property=LoadState,ActiveState,SubState"],
                                    check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            state = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            if (result.returncode not in (0, 4) or state.get("LoadState") != "not-found"
                    or state.get("ActiveState") != "inactive" or state.get("SubState") != "dead"):
                raise ValueError("Could not confirm that the service name is absent and inactive")

    def successful_server(self, binary: Path) -> bool:
        values = self.call("show", "turansec-edrd.service", "--property=ActiveState,SubState,MainPID,ExecMainStatus")
        state = dict(line.split("=", 1) for line in values.splitlines() if "=" in line)
        if (state.get("ActiveState") != "active" or state.get("SubState") != "running"
                or state.get("ExecMainStatus") != "0" or not state.get("MainPID", "").isdigit()):
            return False
        pid = int(state["MainPID"])
        if pid <= 0:
            return False
        try:
            return Path(os.readlink(f"/proc/{pid}/exe")) == binary
        except OSError:
            return False

    def successful_agent(self) -> bool:
        values = self.call("show", "turansec-agent.service", "--property=Result,ExecMainStatus")
        state = dict(line.split("=", 1) for line in values.splitlines() if "=" in line)
        return state.get("Result") == "success" and state.get("ExecMainStatus") == "0"


class Installation:
    def __init__(self, prefix: Path, unit_directory: Path = Path("/etc/systemd/system"), manager=None):
        self.prefix = simple_path(prefix)
        self.units = simple_path(unit_directory)
        self.manager = manager if manager is not None else Systemd()
        self.state_path = self.prefix / ".service-installation.json"

    @contextmanager
    def lock(self):
        trusted_path(self.prefix, must_exist=False)
        self.prefix.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd = os.open(self.prefix / ".installation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Installation lock has unsafe ownership or mode")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    @exclusive
    def stage(self, data: dict, archive: Path, trust: dict, dry_run=False) -> dict:
        trusted_path(self.prefix, must_exist=False)
        sha = data["source_sha"]
        inventory = catalog(data)
        release = self.prefix / "releases" / sha
        result = {"action": "stage", "source_sha": sha, "release": str(release),
                  "file_count": len(inventory), "publisher_signature": trust["publisher_signature"],
                  "services_started": False, "dry_run": dry_run}
        if dry_run:
            return result
        self.prefix.mkdir(mode=0o755, parents=True, exist_ok=True)
        (self.prefix / "releases").mkdir(mode=0o755, exist_ok=True)
        (self.prefix / "receipts").mkdir(mode=0o700, exist_ok=True)
        for directory in (self.prefix, self.prefix / "releases", self.prefix / "receipts"):
            trusted_path(directory)
        if release.exists():
            self.verify_release(sha)
            previous = read_owned_json(self.prefix / "receipts" / f"{sha}.json")
            if previous["trust"]["manifest_sha256"] != trust["manifest_sha256"]:
                raise ValueError("The candidate SHA is already staged with a different manifest")
            result["already_staged"] = True
            return result
        temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=self.prefix / "releases"))
        try:
            with tarfile.open(archive, "r:gz") as source:
                for member in source:
                    target = temporary / member.name
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    with source.extractfile(member) as incoming, target.open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                    target.chmod(0o555 if member.name.startswith("bin/") else 0o444)
            for directory in sorted((p for p in temporary.rglob("*") if p.is_dir()), reverse=True):
                directory.chmod(0o755)
            temporary.chmod(0o755)
            os.rename(temporary, release)
            atomic_json(self.prefix / "receipts" / f"{sha}.json", {"manifest": data, "trust": trust})
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        self.verify_release(sha)
        return result

    def verify_release(self, sha: str) -> tuple[Path, dict]:
        package.checked_sha(sha)
        trusted_path(self.prefix)
        receipt = read_owned_json(self.prefix / "receipts" / f"{sha}.json")
        inventory = catalog(receipt["manifest"])
        release = self.prefix / "releases" / sha
        trusted_path(release)
        files = set()
        for path in release.rglob("*"):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise ValueError("Installed release has an unsafe owner, link or writable file")
            if path.is_dir():
                continue
            name = path.relative_to(release).as_posix()
            if not stat.S_ISREG(info.st_mode) or name not in inventory or info.st_size != inventory[name]["size"]:
                raise ValueError("Installed release differs from its receipt")
            if package.digest(path) != inventory[name]["sha256"]:
                raise ValueError("Installed release content has changed")
            files.add(name)
        if files != set(inventory):
            raise ValueError("Installed release is incomplete")
        return release, receipt

    def configuration(self, path: Path, component: str) -> dict:
        trusted_path(path)
        config = read_json(path)
        (validate_server if component == "server" else validate_agent)(config)
        fields = SERVER_CREDENTIALS if component == "server" else AGENT_CREDENTIALS
        for key in fields:
            file = simple_path(config[key])
            trusted_path(file)
            regular_file(file, private=(key in ("server_key_file", "registry_dsn_file", "runtime_dsn_file", "key_file")))
        if component == "server":
            if config["ui_dir"] != str(self.prefix / "current" / "web"):
                raise ValueError("Managed service ui_dir must name this installation's current/web")
        else:
            scan_root = simple_path(config["scan_root"])
            trusted_path(scan_root)
            if not scan_root.is_dir():
                raise ValueError("Agent scan_root must be a real administrator-controlled directory")
            scan_info = scan_root.stat()
            if scan_info.st_gid == 0 or scan_info.st_mode & 0o050 != 0o050:
                raise ValueError("Scan root requires an approved non-root group with read and search access")
            clamd_socket = simple_path(config["clamd_socket"])
            # The approved ClamAV service normally owns its runtime directory
            # and socket. No arbitrary additional owner is inferred from input.
            try:
                clamav_uid = pwd.getpwnam("clamav").pw_uid
            except KeyError:
                clamav_uid = 0
            trusted_path(clamd_socket.parent, extra_owners={clamav_uid})
            socket_info = clamd_socket.lstat()
            if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid not in (0, os.geteuid(), clamav_uid):
                raise ValueError("The configured ClamAV endpoint must be the approved local Unix socket")
            if socket_info.st_gid == 0 or not socket_info.st_mode & 0o020 or socket_info.st_mode & 0o007:
                raise ValueError("ClamAV socket requires an approved non-root connect group and no world access")
            selected_groups = set()
            for name in config["read_groups"]:
                gid = grp.getgrnam(name).gr_gid
                if gid == 0:
                    raise ValueError("Privileged read group is not allowed")
                selected_groups.add(gid)
            resource_groups = {scan_info.st_gid, socket_info.st_gid}
            if selected_groups != resource_groups:
                raise ValueError("Read groups must exactly match the non-root scan-root and ClamAV-socket groups")
        return config

    def render_units(self, release: Path, configuration: dict) -> dict[str, bytes]:
        rendered = {}
        for component, fields, unit in (("server", SERVER_CREDENTIALS, "turansec-edrd.service"),
                                        ("agent", AGENT_CREDENTIALS, "turansec-agent.service")):
            value = configuration.get(component)
            if not value:
                continue
            path = simple_path(value)
            config = self.configuration(path, component)
            lines = [f"LoadCredential=config.json:{path}"]
            lines += [f"LoadCredential={name}:{simple_path(config[key])}" for key, name in fields.items()]
            template = (release / "packaging" / "linux" / f"{unit}.in").read_text(encoding="utf-8")
            text = template.replace("@@PREFIX@@", str(self.prefix)).replace("@@CREDENTIALS@@", "\n".join(lines))
            text = text.replace("@@GROUPS@@", "SupplementaryGroups=" + " ".join(config.get("read_groups", [])))
            if "@@" in text:
                raise ValueError("Unexpanded systemd template field")
            rendered[unit] = text.encode()
            if component == "agent":
                rendered["turansec-agent.timer"] = (release / "packaging" / "linux" / "turansec-agent.timer.in").read_bytes()
        if not rendered:
            raise ValueError("At least one server or endpoint configuration is required")
        return rendered

    def state(self) -> dict:
        return read_owned_json(self.state_path)

    def assert_managed_units(self, state: dict) -> None:
        trusted_path(self.units)
        for name, expected in state["unit_digests"].items():
            if name not in UNIT_NAMES:
                raise ValueError("Unexpected managed unit name")
            path = self.units / name
            trusted_path(path)
            if sha256(regular_file(path)) != expected:
                raise ValueError("Managed unit has local changes; refusing to overwrite it")
            drop_ins = self.units / (name + ".d")
            if drop_ins.exists() and any(drop_ins.iterdir()):
                raise ValueError("Unmanaged systemd drop-ins require explicit review")

    def write_units(self, rendered: dict[str, bytes]) -> None:
        for name, value in rendered.items():
            atomic_write(self.units / name, value, 0o644)
        self.manager.reload()
        self.manager.assert_units({name: self.units / name for name in rendered})

    @exclusive
    def register(self, sha: str, server_config: Path | None, agent_config: Path | None, dry_run=False) -> dict:
        release, _ = self.verify_release(sha)
        configuration = {"server": str(server_config) if server_config else None,
                         "agent": str(agent_config) if agent_config else None}
        rendered = self.render_units(release, configuration)
        current = self.prefix / "current"
        old = self.state() if self.state_path.exists() else None
        if old and old.get("status") != "uninstalled":
            raise ValueError("Service is already registered; stage and activate an upgrade instead")
        if os.path.lexists(current) and not old:
            raise ValueError("An unmanaged current release already exists")
        trusted_path(self.units)
        for name in rendered:
            if os.path.lexists(self.units / name):
                raise ValueError("A service unit already exists; it will not be adopted")
        result = {"action": "register", "source_sha": sha, "units": list(rendered),
                  "services_started": False, "autostart_enabled": False, "dry_run": dry_run}
        if dry_run:
            return result
        self.manager.ensure_absent(rendered)
        if current.is_symlink():
            current.unlink()
        current.symlink_to(Path("releases") / sha)
        try:
            self.write_units(rendered)
        except BaseException:
            for name in rendered:
                if (self.units / name).is_file() and sha256((self.units / name).read_bytes()) == sha256(rendered[name]):
                    (self.units / name).unlink()
            self.manager.reload()
            current.unlink()
            raise
        state = {"schema": 1, "status": "registered", "source_sha": sha, "configuration": configuration,
                 "unit_digests": {name: sha256(value) for name, value in rendered.items()}}
        atomic_json(self.state_path, state)
        return result

    def stop_services(self, state):
        for name in ("turansec-agent.timer", "turansec-agent.service", "turansec-edrd.service"):
            if name in state["unit_digests"]:
                self.manager.stop(name)

    @exclusive
    def activate(self, sha: str, health, dry_run=False) -> dict:
        candidate, _ = self.verify_release(sha)
        state = self.state()
        if state.get("status") not in ("registered", "active", "initial_start_failed", "rolled_back"):
            raise ValueError("Installation requires operator recovery or registration")
        self.assert_managed_units(state)
        current = self.prefix / "current"
        if not current.is_symlink():
            raise ValueError("Managed current release is missing")
        previous = current.resolve(strict=True)
        if previous.parent != self.prefix / "releases" or previous.name != state["source_sha"]:
            raise ValueError("Current release differs from the recorded installation")
        if previous == candidate and state["status"] == "active":
            raise ValueError("Requested release is already active")
        self.verify_release(previous.name)
        rendered_new = self.render_units(candidate, state["configuration"])
        if set(rendered_new) != set(state["unit_digests"]):
            raise ValueError("Upgrade cannot silently change installed service components")
        result = {"action": "activate", "source_sha": sha, "previous_sha": previous.name, "dry_run": dry_run,
                  "schema_migrations": "not-performed", "publisher_approval": "external-gate"}
        if dry_run:
            return result

        def restart():
            selected = current.resolve(strict=True)
            self.stop_services(state)
            self.write_units(self.render_units(selected, state["configuration"]))
            if state["configuration"]["server"]:
                self.manager.restart("turansec-edrd.service")
                if not health() or not self.manager.successful_server(selected / "bin" / "edrd"):
                    raise RuntimeError("Authenticated operator health check failed")
            if state["configuration"]["agent"]:
                self.manager.start("turansec-agent.service")
                if not self.manager.successful_agent():
                    raise RuntimeError("Bounded endpoint preflight failed")
                self.manager.start("turansec-agent.timer")

        def healthy():
            return (not state["configuration"]["server"] or (
                health() and self.manager.successful_server(current.resolve(strict=True) / "bin" / "edrd"))) and (
                not state["configuration"]["agent"] or self.manager.successful_agent())

        try:
            if previous == candidate:
                state["status"] = "starting"
                atomic_json(self.state_path, state)
                restart()
                if not healthy():
                    raise RuntimeError("Initial service health check failed")
            else:
                # Close the timer/worker before changing what `current` names.
                # The restart callback also stops units during recovery, but
                # waiting until that callback would leave a timer race here.
                self.stop_services(state)
                switch_release(self.prefix, candidate, restart, healthy)
            state.update(status="active", source_sha=sha,
                         unit_digests={name: sha256(value) for name, value in rendered_new.items()})
            atomic_json(self.state_path, state)
            result["result"] = "active-and-health-checked"
            return result
        except ActivationRolledBack:
            state["status"] = "rolled_back"
            atomic_json(self.state_path, state)
            raise
        except BaseException:
            if previous == candidate:
                self.stop_services(state)
                state["status"] = "initial_start_failed"
            else:
                state["status"] = "recovery_required"
            atomic_json(self.state_path, state)
            raise

    @exclusive
    def uninstall(self, dry_run=False) -> dict:
        state = self.state()
        self.assert_managed_units(state)
        result = {"action": "uninstall", "units": list(state["unit_digests"]), "dry_run": dry_run,
                  "preserved": ["configuration", "private keys", "database", "release directories", "receipts"]}
        if dry_run:
            return result
        self.stop_services(state)
        for name in ("turansec-agent.timer", "turansec-edrd.service"):
            if name in state["unit_digests"]:
                self.manager.disable(name)
        for name in state["unit_digests"]:
            (self.units / name).unlink()
        self.manager.reload()
        state["status"] = "uninstalled"
        atomic_json(self.state_path, state)
        return result


def authenticated_health(path: Path, server_config: Path):
    trusted_path(path)
    config = read_json(path)
    expected = {"origin", "server_ca_file", "operator_cert_file", "operator_key_file", "expected_tenant_id", "expected_operator_id"}
    if set(config) != expected:
        raise ValueError("Unexpected or missing operator health field")
    origin = loopback_origin(config["origin"])
    server = read_json(server_config)
    validate_server(server)
    from urllib.parse import urlsplit
    from systemd_launcher import loopback_listener
    target = urlsplit(origin)
    if (str(ipaddress.ip_address(target.hostname)), target.port) != loopback_listener(server.get("soc_listen", "127.0.0.1:9444")):
        raise ValueError("Health identity must check the configured local operator listener")
    for name in ("server_ca_file", "operator_cert_file", "operator_key_file"):
        file = simple_path(config[name])
        trusted_path(file)
        regular_file(file, private=(name == "operator_key_file"))
    context = ssl.create_default_context(cafile=config["server_ca_file"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(config["operator_cert_file"], config["operator_key_file"])
    # Ignore proxy environment variables; this is a direct numeric-loopback check.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, new_url):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def health() -> bool:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with opener.open(origin + "/soc/v1/session", timeout=3) as response:
                    if response.status != 200:
                        return False
                    data = response.read(16385)
                    if len(data) > 16384:
                        return False
                    session = json.loads(data)
                    return (isinstance(session, dict) and session.get("tenant_id") == config["expected_tenant_id"]
                            and session.get("operator_id") == config["expected_operator_id"]
                            and session.get("role") in ("viewer", "scanner"))
            except urllib.error.HTTPError:
                return False
            except (OSError, ValueError, urllib.error.URLError, socket.timeout):
                time.sleep(0.25)
        return False
    return health


def require_system_manager(*, check_reserved_identities: bool) -> None:
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise ValueError("Actual service changes require root on the approved Linux systemd host")
    version = subprocess.check_output(["systemd-analyze", "--version"], text=True).splitlines()[0].split()
    if len(version) < 2 or not version[1].isdigit() or int(version[1]) < 249:
        raise ValueError("systemd 249 or newer is required")
    # During an active installation NSS exposes the running DynamicUser. Only
    # registration may test for preexisting identities; otherwise upgrades and
    # uninstall would mistake the service's own dynamic identity for a static one.
    if not check_reserved_identities:
        return
    for name in ("turansec-edrd", "turansec-agent"):
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise ValueError("Reserved dynamic service identity already exists as a static account")
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise ValueError("Reserved dynamic service identity already exists as a static group")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path("/opt/turansec"))
    sub = parser.add_subparsers(dest="operation", required=True)
    stage = sub.add_parser("stage")
    for name in ("archive", "manifest"):
        stage.add_argument(f"--{name}", type=Path, required=True)
    stage.add_argument("--expected-sha", required=True)
    stage.add_argument("--signature", type=Path)
    stage.add_argument("--trusted-key", type=Path)
    stage.add_argument("--unsigned-lab", action="store_true")
    stage.add_argument("--manifest-sha256")
    stage.add_argument("--dry-run", action="store_true")
    register = sub.add_parser("register")
    register.add_argument("--sha", required=True)
    register.add_argument("--server-config", type=Path)
    register.add_argument("--agent-config", type=Path)
    register.add_argument("--dry-run", action="store_true")
    for operation in ("activate", "rollback"):
        command = sub.add_parser(operation)
        command.add_argument("--sha", required=True)
        command.add_argument("--health-config", type=Path)
        command.add_argument("--dry-run", action="store_true")
    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("--dry-run", action="store_true")
    sub.add_parser("status")
    args = parser.parse_args()
    try:
        installation = Installation(args.prefix)
        if args.operation == "stage":
            with verified_bundle(args.archive, args.manifest, args.expected_sha, signature=args.signature,
                                 trusted_key=args.trusted_key, unsigned_lab=args.unsigned_lab,
                                 manifest_sha256=args.manifest_sha256) as (data, archive, trust):
                result = installation.stage(data, archive, trust, args.dry_run)
        elif args.operation == "status":
            state = installation.state()
            result = {"status": state["status"], "source_sha": state["source_sha"],
                      "units": list(state["unit_digests"]), "deployment_approval": "external-gate"}
        else:
            if not args.dry_run:
                require_system_manager(check_reserved_identities=(args.operation == "register"))
            if args.operation == "register":
                result = installation.register(args.sha, args.server_config, args.agent_config, args.dry_run)
            elif args.operation == "uninstall":
                result = installation.uninstall(args.dry_run)
            else:
                state = installation.state()
                if state["configuration"]["server"] and not args.health_config:
                    raise ValueError("Server activation requires an enrolled operator health identity")
                health = (authenticated_health(args.health_config, Path(state["configuration"]["server"]))
                          if state["configuration"]["server"] and not args.dry_run else lambda: True)
                result = installation.activate(args.sha, health, args.dry_run)
        print(json.dumps(result, indent=2))
        return 0
    except ActivationRolledBack:
        print("Candidate failed; previous release and authenticated health were restored", file=sys.stderr)
        return 3
    except RollbackFailed:
        print("Rollback health failed; stop rollout and perform operator recovery", file=sys.stderr)
        return 4
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError, tarfile.TarError):
        # Never print configuration/DSN/parser diagnostics or command stderr.
        print("Service operation failed closed; inspect package identity, local permissions and the approved configuration", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
