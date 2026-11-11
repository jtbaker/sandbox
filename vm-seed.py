#!/usr/bin/python3
"""Seed private configuration around required, native shared session mounts."""

import fcntl
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

HOST_ROOTS = ((Path("/root/.pi-host"), ".pi"), (Path("/root/.omp-host"), ".omp"))
SKIP_DIRS = {
    "sessions",
    "terminal-sessions",
    "cache",
    "caches",
    "logs",
    "bin",
    "__pycache__",
    ".git",
}
# Host runtime trees are not configuration. Limit this rule to config roots
# so portable extension/package directories with these names remain intact.
RUNTIME_DIRS = {"run", "ssh-control", "puppeteer", "natives", ".supervisor"}
PROFILE = Path("/opt/sandbox/sandbox.json.autonomous")
MARKER = Path("/run/sandbox.seeded")
NETWORK_MARKER = Path("/run/sandbox-network.json")


def backup_database(source, destination):
    # SQLite's backup API includes committed WAL data without copying a live
    # database and its journal at different instants. Never open the host RW.
    deadline = time.monotonic() + 30

    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError("database snapshot exceeded 30 seconds")

    try:
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
            # Pin one committed WAL snapshot for the entire backup. Without a
            # read transaction, each batch can restart when the host writes.
            src.execute("BEGIN")
            src.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchall()
            with closing(sqlite3.connect(destination)) as dst:
                src.backup(dst, pages=256, progress=progress)
    except (sqlite3.Error, TimeoutError) as error:
        raise RuntimeError(f"SQLite snapshot failed for {source}: {error}") from error


def copy_tree(source, destination, relative=Path(), shared=frozenset()):
    destination.mkdir(mode=0o700)
    config_root = not relative.parts or (
        len(relative.parts) == 2 and relative.parts[0] == "profiles"
    )
    for entry in source.iterdir():
        mode = entry.lstat().st_mode
        target = destination / entry.name
        # Do not follow host symlinks or import sockets/devices/FIFOs.
        if stat.S_ISDIR(mode):
            if (
                relative / entry.name not in shared
                and entry.name not in SKIP_DIRS
                and not (config_root and entry.name in RUNTIME_DIRS)
            ):
                copy_tree(entry, target, relative / entry.name, shared)
        elif stat.S_ISREG(mode):
            if (
                entry.name.startswith(("history.db", "trust.db"))
                or entry.name in {"trust.json", ".seeded"}
                or entry.name.endswith((".db-wal", ".db-shm", ".db-journal"))
            ):
                continue
            if entry.suffix == ".db":
                backup_database(entry, target)
            else:
                # O_NOFOLLOW also rejects a file replaced by a symlink since
                # lstat; O_NONBLOCK avoids hanging if it became a FIFO.
                fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as src:
                    if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                        raise RuntimeError("configuration source is not a regular file")
                    with target.open("xb") as dst:
                        shutil.copyfileobj(src, dst)
            os.chmod(target, 0o700 if mode & stat.S_IXUSR else 0o600)


def absolute_path(value, name):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"{name} must be an absolute path without '..'")
    return path


def ensure_directory(path):
    # Never follow a preexisting symlink while building the mirrored VM paths.
    for directory in (*reversed(path.parents), path):
        if directory.is_symlink():
            raise RuntimeError(f"directory must not be a symlink: {directory}")
        if directory.exists():
            if not directory.is_dir():
                raise RuntimeError(f"not a directory: {directory}")
        else:
            directory.mkdir(mode=0o700)


def source_profiles(source):
    profiles = source / "profiles"
    if profiles.is_symlink():
        raise RuntimeError(f"profile root must not be a symlink: {profiles}")
    if not profiles.exists():
        return []
    if not profiles.is_dir():
        raise RuntimeError(f"profile root is not a directory: {profiles}")
    names = []
    for profile in profiles.iterdir():
        if profile.is_symlink():
            raise RuntimeError(f"profile must not be a symlink: {profile}")
        if profile.is_dir():
            names.append(profile.name)
    return sorted(names)


def mount_paths():
    # Bind mounts on the same filesystem can evade Path.is_mount(). Linux
    # mountinfo supplies the exact mountpoints, including virtiofs mounts.
    mounts = set()
    with open("/proc/self/mountinfo") as mountinfo:
        for line in mountinfo:
            encoded = line.split()[4]
            for escaped, character in (
                (r"\040", " "),
                (r"\011", "\t"),
                (r"\012", "\n"),
                (r"\134", "\\"),
            ):
                encoded = encoded.replace(escaped, character)
            mounts.add(Path(encoded))
    return mounts


def state_layout(home):
    layouts = []
    for source, name in HOST_ROOTS:
        if source.is_symlink() or (source.exists() and not source.is_dir()):
            raise RuntimeError(f"configuration mount is not a directory: {source}")
        shared = {Path("agent/sessions")}
        if name == ".omp":
            shared.add(Path("agent/blobs"))
            for profile in source_profiles(source):
                agent = Path("profiles") / profile / "agent"
                shared.update((agent / "sessions", agent / "blobs"))
        layouts.append((source, home / name, shared))
    return layouts


def validate_mounts(layouts, mounts):
    for _, destination, shared in layouts:
        for relative in shared:
            path = destination / relative
            # Validate ancestors too: a symlink above the mount would give
            # session headers a different realpath from the host's native path.
            for directory in (path, *path.parents):
                if directory.is_symlink() or not directory.is_dir():
                    raise RuntimeError(
                        f"state path is not a plain directory: {directory}"
                    )
            if path not in mounts and not path.is_mount():
                raise RuntimeError(f"required shared state mount is missing: {path}")


def structural_directories(destination, shared):
    directories = {destination}
    for relative in shared:
        directories.update(destination / parent for parent in relative.parents)
    return directories


def validate_native_root(destination, shared, mounts):
    structural = structural_directories(destination, shared)
    state = {destination / relative for relative in shared}

    def visit(directory):
        if directory in mounts or directory.is_mount():
            raise RuntimeError(
                f"configuration directory must be VM-private: {directory}"
            )
        for entry in directory.iterdir():
            if entry in state:
                continue  # Never inspect or change shared mount contents.
            if entry not in structural or entry.is_symlink() or not entry.is_dir():
                raise RuntimeError(
                    f"unexpected preexisting configuration path: {entry}"
                )
            visit(entry)

    visit(destination)
    return structural


def merge_snapshot(snapshot, destination, structural):
    for entry in snapshot.iterdir():
        target = destination / entry.name
        if target.exists() or target.is_symlink():
            if target not in structural or target.is_symlink() or not target.is_dir():
                raise RuntimeError(
                    f"refusing to replace existing configuration: {target}"
                )
            if not entry.is_dir():
                raise RuntimeError(
                    f"configuration conflicts with state directory: {target}"
                )
            merge_snapshot(entry, target, structural)
        else:
            entry.rename(target)


def write_sandbox_profile(destination, home):
    with PROFILE.open() as source:
        profile = json.load(source)
    # Translate only native private-HOME paths, never the fixed RO host roots.
    paths = {
        f"/root/{relative}": str(home / relative)
        for relative in (".pi", ".omp", ".npm", ".cache", ".local/share", ".config")
    }
    for permission in ("allowWrite", "denyRead"):
        profile["filesystem"][permission] = [
            paths.get(path, path) for path in profile["filesystem"][permission]
        ]
    with destination.open("w") as target:
        json.dump(profile, target, indent=2)
        target.write("\n")
    os.chmod(destination, 0o600)


def ensure_symlink(path, target):
    if path.exists() or path.is_symlink():
        if not path.is_symlink() or path.resolve() != target.resolve():
            raise RuntimeError(f"refusing to replace existing path: {path}")
    else:
        path.symlink_to(target)


def prepare_private_home(home):
    if home != Path("/root"):
        for name in (".zshrc", ".oh-my-zsh"):
            ensure_symlink(home / name, Path("/root") / name)
        # Image installers source ~/.local/bin/env from the login shell.
        # This is a private image directory, never the host's executable tree.
        ensure_directory(home / ".local")
        ensure_symlink(home / ".local/bin", Path("/root/.local/bin"))
    gitconfig = home / ".gitconfig"
    if gitconfig.exists() or gitconfig.is_symlink():
        raise RuntimeError(
            f"refusing to replace existing private git config: {gitconfig}"
        )
    subprocess.run(
        [
            "git",
            "config",
            "--file",
            str(gitconfig),
            "--add",
            "safe.directory",
            str(Path.cwd()),
        ],
        check=True,
    )


def prepare_workspace_alias():
    value = os.environ.get("SANDBOX_WORKSPACE_ALIAS")
    if not value:
        return
    alias = absolute_path(value, "SANDBOX_WORKSPACE_ALIAS")
    if Path("/tmp") not in alias.parents:
        raise RuntimeError("workspace alias must name a project below /tmp")
    ensure_directory(alias.parent)
    ensure_symlink(alias, Path.cwd())


def seed():
    if not NETWORK_MARKER.is_file():
        raise RuntimeError(
            "network policy was not initialized; launch through sandbox.sh"
        )
    if os.environ.get("SANDBOX_PERSIST_SESSIONS") != "1":
        raise RuntimeError(
            "persistent session mounts are required; launch through sandbox.sh"
        )
    home = absolute_path(os.environ.get("HOME", ""), "HOME")
    temporary = absolute_path(os.environ.get("TMPDIR", ""), "TMPDIR")
    os.umask(0o077)
    with open("/run/sandbox-seed.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        mounts = mount_paths()
        if home in mounts or home.is_mount():
            raise RuntimeError(f"HOME must be VM-private, not a mount: {home}")
        ensure_directory(home)
        ensure_directory(temporary)
        layouts = state_layout(home)
        validate_mounts(layouts, mounts)
        if MARKER.exists():
            return
        structural = {}
        for _, destination, shared in layouts:
            structural[destination] = validate_native_root(destination, shared, mounts)
            # Mount setup creates these VM-private ancestors before seeding.
            # Harden only those directories, never the shared state roots.
            for directory in structural[destination]:
                os.chmod(directory, 0o700)
        # Stage both roots before installing either. State directories are
        # excluded before traversal; their permissions and contents stay intact.
        with tempfile.TemporaryDirectory(prefix=".sandbox-seed-", dir=home) as tmp:
            staged = []
            for source, destination, shared in layouts:
                snapshot = Path(tmp) / destination.name
                if source.exists():
                    copy_tree(source, snapshot, shared=shared)
                else:
                    snapshot.mkdir(mode=0o700)
                agent = snapshot / "agent"
                agent.mkdir(mode=0o700, exist_ok=True)
                if destination.name == ".pi":
                    write_sandbox_profile(agent / "sandbox.json", home)
                staged.append((snapshot, destination))
            if state_layout(home) != layouts:
                raise RuntimeError(
                    "host profiles changed during configuration snapshot; relaunch"
                )
            prepare_private_home(home)
            prepare_workspace_alias()
            for snapshot, destination in staged:
                merge_snapshot(snapshot, destination, structural[destination])
        MARKER.touch(mode=0o600)


if __name__ == "__main__":
    try:
        seed()
    except Exception as error:
        # Our RuntimeError messages describe paths/operations, never file data.
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"sandbox: configuration seeding failed: {detail}", file=sys.stderr)
        sys.exit(1)
    command = sys.argv[1:] or ["zsh", "-l"]
    # Keep only filesystem permissions needed to edit host-owned workspace
    # files. Network, raw-socket, namespace, and privilege-escalation capabilities
    # must not reach agents, extensions, or shell commands.
    os.execv(
        "/usr/bin/setpriv",
        [
            "setpriv",
            "--bounding-set=-all,+dac_override,+fowner",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "--",
            *command,
        ],
    )
