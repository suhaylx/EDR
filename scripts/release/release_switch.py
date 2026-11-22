"""POSIX release-switch primitive for an already verified, approved bundle.

This module is not a deployment CLI and grants no authorization. The caller
must verify package signatures and approval before invoking it, and supply
bounded service restart/health checks. It never applies database migrations.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Callable


class ActivationRolledBack(RuntimeError):
    """Candidate failed; the previous release was restored and healthy."""


class RollbackFailed(RuntimeError):
    """Restoration or the previous release's health check failed."""


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _journal(root: Path, value: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".activation-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / "activation.json")
        _sync_directory(root)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _point_current(root: Path, target: Path) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".current-", dir=root)
    os.close(fd)
    os.unlink(temporary)
    try:
        os.symlink(os.path.relpath(target, root), temporary)
        os.replace(temporary, root / "current")
        _sync_directory(root)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def switch_release(root: Path, candidate: Path, restart: Callable[[], None], health: Callable[[], bool]) -> None:
    """Atomically switch and restore the prior release on restart/health failure.

Existing pending/failed journals require deliberate operator recovery; this
function never silently ignores a prior interrupted activation. Configuration,
identity keys and database state stay outside immutable release directories.
"""
    if os.name != "posix":
        raise RuntimeError("Native Windows activation/rollback requires separate implementation and acceptance")
    import fcntl

    root = root.resolve(strict=True)
    releases = root / "releases"
    if not releases.is_dir() or releases.is_symlink():
        raise ValueError("A real releases directory is required")
    candidate = candidate.resolve(strict=True)
    if candidate.parent != releases or not candidate.is_dir():
        raise ValueError("Candidate must be a direct release directory")
    current = root / "current"
    if not current.is_symlink():
        raise ValueError("An existing current release symlink is required for rollback")

    with (root / ".activation.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = current.resolve(strict=True)
        if previous.parent != releases or not previous.is_dir():
            raise ValueError("Previous release must be a direct release directory")
        if previous == candidate:
            raise ValueError("Candidate is already the current release")
        journal = root / "activation.json"
        if journal.exists():
            state = json.loads(journal.read_text(encoding="utf-8"))
            if state.get("status") not in ("active", "rolled_back"):
                raise RuntimeError("A previous activation needs operator recovery")
        state = {"previous": previous.name, "candidate": candidate.name, "status": "pending"}
        _journal(root, state)
        try:
            _point_current(root, candidate)
            restart()
            if not health():
                raise RuntimeError("Candidate health check failed")
        except BaseException as activation_error:
            try:
                _point_current(root, previous)
                restart()
                if not health():
                    raise RuntimeError("Previous release health check failed")
            except BaseException as rollback_error:
                state["status"] = "rollback_failed"
                _journal(root, state)
                raise RollbackFailed("Rollback requires operator recovery") from rollback_error
            state["status"] = "rolled_back"
            _journal(root, state)
            raise ActivationRolledBack("Previous release restored and healthy") from activation_error
        state["status"] = "active"
        _journal(root, state)
