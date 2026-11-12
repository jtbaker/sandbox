#!/usr/bin/python3
"""Seed private configuration around required, native shared session mounts."""

import fcntl
import grp
import json
import os
import pwd
import re
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
MAX_ID = 2**32 - 2
IMAGE_ROOTS = tuple(
    Path(path)
    for path in (
        "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt",
        "/proc", "/root", "/run", "/sbin", "/sys", "/usr",
    )
)


def workload_identity():
    values = []
    for name in ("SANDBOX_UID", "SANDBOX_GID"):
        value = os.environ.get(name, "")
        if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > MAX_ID:
            raise RuntimeError(f"{name} must be a bounded numeric identity")
        values.append(int(value))
    uid, gid = values
    if uid in (0, 65532):
        raise RuntimeError("SANDBOX_UID must be non-root and must not be 65532")
    return uid, gid


def prepare_identity(uid, gid, home):
    try:
        grp.getgrgid(gid)
    except KeyError:
        name = f"sandbox-{gid}"
        try:
            grp.getgrnam(name)
        except KeyError:
            with open("/etc/group", "a") as groups:
                groups.write(f"{name}:!:{gid}:\n")
        else:
            raise RuntimeError(f"guest group name is already assigned: {name}")
    try:
        pwd.getpwuid(uid)
    except KeyError:
        name = f"sandbox-{uid}"
        try:
            pwd.getpwnam(name)
        except KeyError:
            with open("/etc/passwd", "a") as users:
                users.write(f"{name}:!:{uid}:{gid}::{home}:/usr/sbin/nologin\n")
        else:
            raise RuntimeError(f"guest user name is already assigned: {name}")


def own_private_tree(path, uid, gid, mounts):
    # Never stat, traverse, chmod, or chown a mounted state tree or host source.
    if path in mounts or any(source == path for source, _ in HOST_ROOTS):
        return
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return  # In particular, leave image tool and shell targets root-owned.
    if stat.S_ISDIR(mode):
        for entry in path.iterdir():
            own_private_tree(entry, uid, gid, mounts)
    os.chown(path, uid, gid, follow_symlinks=False)


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


def skip_directory(relative):
    parent = relative.parent
    config_root = not parent.parts or (
        len(parent.parts) == 2 and parent.parts[0] == "profiles"
    )
    return (
        relative.name in SKIP_DIRS
        or (config_root and relative.name in RUNTIME_DIRS)
    )


def configuration_link(entry, roots):
    target = Path(os.readlink(entry))
    if not target.is_absolute():
        for source, native, _ in roots:
            if entry.is_relative_to(source):
                target = native / entry.relative_to(source).parent / target
                break
    target = Path(os.path.normpath(target))
    for source, native, _ in roots:
        if target.is_relative_to(native):
            target = source / target.relative_to(native)
            break
    else:
        return None
    try:
        target = target.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    for source, _, shared in roots:
        if target.is_relative_to(source):
            relative = target.relative_to(source)
            if any(
                parent in shared or skip_directory(parent)
                for parent in relative.parents
                if parent.parts
            ):
                return None
            return target if target.is_file() else None
    return None


def copy_tree(source, destination, relative=Path(), shared=frozenset(), roots=()):
    destination.mkdir(mode=0o700)
    roots = roots or ((source, source, shared),)
    for entry in source.iterdir():
        mode = entry.lstat().st_mode
        target = destination / entry.name
        # File links become private files only within the mounted config roots.
        if stat.S_ISLNK(mode):
            entry = configuration_link(entry, roots)
            if entry is None:
                continue
            mode = entry.lstat().st_mode
        if stat.S_ISDIR(mode):
            if (
                relative / entry.name not in shared
                and not skip_directory(relative / entry.name)
            ):
                copy_tree(entry, target, relative / entry.name, shared, roots)
        elif stat.S_ISREG(mode):
            if (
                any(
                    name.startswith(("history.db", "trust.db"))
                    or name in {"trust.json", ".seeded"}
                    or name.endswith((".db-wal", ".db-shm", ".db-journal"))
                    for name in (entry.name, target.name)
                )
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
            directory.mkdir(mode=0o700 if directory == path else 0o755)
            if directory != path:
                os.chmod(directory, 0o755)  # Ancestors must survive the private umask.


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
            "/usr/bin/git",
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
    if os.geteuid() != 0:
        raise RuntimeError("configuration seeding requires the root entrypoint")
    uid, gid = workload_identity()
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
    # These paths contain image-owned system files, not a native private HOME.
    for system in IMAGE_ROOTS:
        if home == system or system in home.parents or home in system.parents:
            raise RuntimeError(f"HOME must not overlap image system paths: {home}")
    if home in (Path("/home"), Path("/Users"), Path("/private"), Path("/var")):
        raise RuntimeError(f"HOME must not replace an image system directory: {home}")
    if ":" in str(home) or any(character in str(home) for character in "\r\n"):
        raise RuntimeError("HOME cannot be represented in the guest account database")
    os.umask(0o077)
    with open("/run/sandbox-seed.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        mounts = mount_paths()
        if home in mounts or home.is_mount():
            raise RuntimeError(f"HOME must be VM-private, not a mount: {home}")
        if any(mount in home.parents for mount in mounts if mount != Path("/")):
            raise RuntimeError(f"HOME must not be inside a mount: {home}")
        if temporary not in (Path("/tmp"), Path("/var/tmp")):
            if temporary in mounts or any(
                mount in temporary.parents for mount in mounts if mount != Path("/")
            ):
                raise RuntimeError(f"TMPDIR must be VM-private: {temporary}")
            if (
                temporary in (Path("/"), Path("/home"), Path("/Users"), Path("/private"), Path("/var"))
                or any(system == temporary or system in temporary.parents for system in IMAGE_ROOTS)
            ):
                raise RuntimeError(f"TMPDIR must not overlap image system paths: {temporary}")
        ensure_directory(home)
        ensure_directory(temporary)
        layouts = state_layout(home)
        validate_mounts(layouts, mounts)
        prepare_identity(uid, gid, home)
        if MARKER.exists():
            with MARKER.open() as marker:
                identity = json.load(marker)
            if identity != {"uid": uid, "gid": gid, "home": str(home), "tmpdir": str(temporary)}:
                raise RuntimeError("seeded workload identity does not match this entrypoint")
            return uid, gid
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
                    copy_tree(source, snapshot, shared=shared, roots=layouts)
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
        for _, destination, _ in layouts:
            own_private_tree(destination, uid, gid, mounts)
        for name in (".local", ".gitconfig", ".zshrc"):
            own_private_tree(home / name, uid, gid, mounts)
        os.chown(home, uid, gid, follow_symlinks=False)
        # /tmp is an image-owned shared temporary directory. Native per-user
        # temporary roots are private, but their mounted descendants stay alone.
        if temporary not in (Path("/tmp"), Path("/var/tmp")):
            os.chown(temporary, uid, gid, follow_symlinks=False)
        with MARKER.open("x") as marker:
            json.dump(
                {"uid": uid, "gid": gid, "home": str(home), "tmpdir": str(temporary)},
                marker,
            )
    return uid, gid


def joined_identity(uid, gid):
    if os.geteuid() != 0:
        raise RuntimeError("joining requires the root entrypoint")
    with MARKER.open() as marker:
        identity = json.load(marker)
    if (identity["uid"], identity["gid"]) != (uid, gid):
        raise RuntimeError("joined workload identity does not match seeded configuration")
    os.environ.update(
        HOME=identity["home"],
        TMPDIR=identity["tmpdir"],
        SANDBOX_UID=str(uid),
        SANDBOX_GID=str(gid),
        SANDBOX_PERSIST_SESSIONS="1",
    )
    return uid, gid


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--join"]:
            if len(sys.argv) < 6 or sys.argv[4] != "--":
                raise RuntimeError("join requires UID GID -- COMMAND")
            uid, gid = joined_identity(int(sys.argv[2]), int(sys.argv[3]))
            command = sys.argv[5:]
        else:
            uid, gid = seed()
            command = sys.argv[1:] or ["zsh", "-l"]
    except Exception as error:
        # Our RuntimeError messages describe paths/operations, never file data.
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"sandbox: configuration seeding failed: {detail}", file=sys.stderr)
        sys.exit(1)
    # Change numeric identity and remove every capability before any shell,
    # startup file, command, or PATH lookup can run.
    os.execv(
        "/usr/bin/setpriv",
        [
            "setpriv",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--clear-groups",
            "--reuid",
            str(uid),
            "--regid",
            str(gid),
            "--no-new-privs",
            "--",
            *command,
        ],
    )
