#!/usr/bin/env python3
"""Reuse a project's sandbox VM and reclaim abandoned ones.

`smolvm machine run` reaps its own VM when the guest exits cleanly. A run that
is killed, or whose terminal closes, leaks the VM: `machine ls` still lists it
as `running (eph)` and its `_boot-vm` process stays alive with no host process
attached.

`reuse` delegates to `sandbox.sh`, which validates the current image before
joining or creating a VM. `attach` opens another non-root session only in a
registered policy image with a live launcher. Discovery commands use the same
numeric identity and privilege restrictions as joined shells. `reap` stops
leaked VMs without entering them; ownership comes from the host process tree.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from network_policy import DNS_UID, POLICY_VERSION

SMOLVM = os.environ.get("SMOLVM", "smolvm")
# smolvm names ephemeral VMs vm-XXXXXXXX and names saved machines after the
# --name it was given, which is sandbox-<project>-<hash>.
EPHEMERAL_NAME = re.compile(r"^vm-[0-9a-f]{8}$")
SAVED_NAME = re.compile(r"^sandbox-[a-z0-9][a-z0-9._-]{0,63}$")
# The launcher exports the resolved image to a tar, so smolvm records the local
# archive identity, not the Docker image id.
LOCAL_IMAGE = re.compile(r"^local:[0-9a-f]{64}$")
SMOLVM_VMS = Path(os.environ.get("HOME", "")) / "Library" / "Caches" / "smolvm" / "vms"
MAX_ID = 2**32 - 2


def host_identity():
    uid, gid = os.getuid(), os.getegid()
    if uid != os.geteuid() or uid in (0, DNS_UID) or not 0 < uid <= MAX_ID:
        raise RuntimeError("run this helper as the non-root sandbox user")
    if not 0 <= gid <= MAX_ID:
        raise RuntimeError("host group identity is out of range")
    return uid, gid


def policy_cache():
    value = os.environ.get("HOME", "")
    if not value or not Path(value).is_absolute():
        raise RuntimeError("HOME must be an absolute host directory")
    home = Path(value).resolve(strict=True)
    return home / ".cache" / "sandbox"


def private_cache(cache, create=False):
    uid, _ = host_identity()
    if create:
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = cache.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise RuntimeError("sandbox image cache must be a host-owned directory")
    if create:
        os.chmod(cache, 0o700)
    elif info.st_mode & 0o077:
        raise RuntimeError("sandbox image cache must be private to the host user")
    return True


def registered_image():
    uid, gid = host_identity()
    cache = policy_cache()
    if not private_cache(cache):
        return None
    try:
        fd = os.open(cache / ".policy-image", os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "r") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_mode & 0o077
            or info.st_size > 4096
        ):
            raise RuntimeError("registered policy image metadata is not private")
        try:
            metadata = json.load(source)
        except ValueError as error:
            raise RuntimeError("registered policy image metadata is invalid") from error
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"policyVersion", "image", "uid", "gid"}
        or metadata.get("policyVersion") != POLICY_VERSION
        or type(metadata.get("uid")) is not int
        or type(metadata.get("gid")) is not int
        or metadata["uid"] != uid
        or metadata["gid"] != gid
        or not isinstance(metadata.get("image"), str)
        or LOCAL_IMAGE.fullmatch(metadata["image"]) is None
    ):
        raise RuntimeError("registered policy image does not match this host identity")
    return metadata["image"]


def do_record_image(args):
    uid, gid = host_identity()
    digest = hashlib.sha256()
    fd = os.open(args.image_tar, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as archive:
        if not stat.S_ISREG(os.fstat(archive.fileno()).st_mode):
            raise RuntimeError("image archive is not a regular file")
        while chunk := archive.read(1024 * 1024):
            digest.update(chunk)
    metadata = {
        "policyVersion": POLICY_VERSION,
        "image": f"local:{digest.hexdigest()}",
        "uid": uid,
        "gid": gid,
    }
    cache = policy_cache()
    private_cache(cache, create=True)
    staged = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=".policy-image-", dir=cache, delete=False
        ) as destination:
            staged = Path(destination.name)
            json.dump(metadata, destination, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(staged, cache / ".policy-image")
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return 0


def trusted_records(records):
    image = registered_image()
    if image is None:
        return []
    return [record for record in sandbox_records(records) if record.get("image") == image]


def guest_argv(record, command, interactive=False, workdir=None):
    # Validate before *any* guest command, including discovery. A root-era VM
    # must never execute even a probe, irrespective of its machine name.
    if record not in trusted_records([record]) or record.get("state") != "running":
        raise RuntimeError("machine does not use the registered non-root policy image")
    uid, gid = host_identity()
    argv = [SMOLVM, "machine", "exec", "--name", record["name"]]
    if interactive:
        argv += ["-i", "-t"]
    if workdir is not None:
        argv += ["-w", workdir]
    return [
        *argv,
        "/usr/bin/python3",
        "-I",
        "/usr/local/bin/vm-seed.py",
        "--join",
        str(uid),
        str(gid),
        "--",
        *command,
    ]


def guest_mounts(record):
    completed = subprocess.run(
        guest_argv(record, ["/usr/bin/cat", "/proc/self/mountinfo"]),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    mounts = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields[6:]:
            continue
        separator = fields.index("-", 6)
        if len(fields) <= separator + 3:
            continue
        path = re.sub(
            r"\\(040|011|012|134)",
            lambda match: chr(int(match.group(1), 8)),
            fields[4],
        )
        mounts.append((path, fields[separator + 1], fields[5].split(",")))
    return mounts


def run(args, check=True):
    completed = subprocess.run(
        [SMOLVM, "machine", *args], text=True, capture_output=True, check=False
    )
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"smolvm machine {' '.join(args)} failed: {detail}")
    return completed


def machines():
    completed = run(["ls", "--json"])
    try:
        records = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError("reading the machine list failed") from error
    if not isinstance(records, list):
        raise RuntimeError("reading the machine list failed: expected a list")
    return [record for record in records if isinstance(record, dict)]


def sandbox_records(records):
    """Machines that this launcher could plausibly have started."""
    selected = []
    for record in records:
        name = record.get("name")
        image = record.get("image")
        if not isinstance(name, str):
            continue
        if SAVED_NAME.match(name) or (
            EPHEMERAL_NAME.match(name)
            and isinstance(image, str)
            and LOCAL_IMAGE.match(image)
        ):
            selected.append(record)
    return selected


def launcher_children():
    """Live `smolvm machine run` processes and the VM boot processes they own.

    `record.pid` names each VM's `_boot-vm` process. An attached run is that
    process's ancestor; a leaked VM's `_boot-vm` was reparented to launchd, so
    walking its parents never reaches a `machine run` process.
    """
    completed = subprocess.run(
        ["ps", "-ax", "-o", "pid=,ppid=,args="],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("reading the process table failed")
    parents = {}
    launchers = set()
    booting = set()
    for line in completed.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) < 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        pid, ppid, args = int(fields[0]), int(fields[1]), fields[2]
        parents[pid] = ppid
        if "_boot-vm" in args:
            booting.add(pid)
        elif "smolvm" in args and "machine run" in args:
            launchers.add(pid)
    owned = set()
    for pid in booting:
        walker = parents.get(pid, 0)
        depth = 0
        while walker and depth < 32:
            if walker in launchers:
                owned.add(pid)
                break
            walker = parents.get(walker, 0)
            depth += 1
    return owned, booting


def attach_state(record, owned, booting):
    """Classify a running VM as attached to a launcher, or otherwise detached.

    Ownership is the process relationship, not a saved file: `record.pid` is
    the VM's boot process, and only an attached run is its ancestor. An
    interrupted `sandbox.sh` leaks a `vm-*` machine with no such ancestor.
    A machine named by `machine run --name` (for example `sandbox-app-1`)
    has a persistent record and no launcher, so it reports as detached here.
    """
    pid = record.get("pid")
    if isinstance(pid, int) and pid in owned:
        return "attached", "live launcher"
    if isinstance(pid, int) and pid not in booting:
        return "detached", "boot process is gone"
    if SAVED_NAME.match(record["name"]):
        return "detached", "named machine, no console"
    return "detached", "no launcher owns it"


def running_for(workspace, owned=None, booting=None):
    """The running sandbox VM that mounts this workspace, by guest mount table.

    Ephemeral VMs are named vm-XXXXXXXX and carry no workspace hint, so the
    guest mount table is the only reliable link between a VM and its project.
    An attached VM wins over an abandoned one that mounts the same directory,
    so a leaked VM never hides a live session. Pass owned and booting from
    `launcher_children` to enable that preference.
    """
    if owned is None:
        owned, booting = launcher_children()
    fallback = None
    for record in sorted(trusted_records(machines()), key=lambda item: item["name"]):
        if record.get("state") != "running":
            continue
        if not any(path == workspace for path, _, _ in guest_mounts(record)):
            continue
        status, _ = attach_state(record, owned, booting)
        if status == "attached":
            return record
        fallback = fallback or record
    return fallback


def do_list(args):
    owned, booting = launcher_children()
    records = sandbox_records(machines())
    if not records:
        print("No sandbox machines.")
        return 0
    print(f"{'NAME':16s} {'STATE':9s} {'MEM':9s} STATUS")
    for record in sorted(records, key=lambda item: item["name"]):
        name = record["name"]
        state = record.get("state", "?")
        if state == "running":
            status, reason = attach_state(record, owned, booting)
        elif state == "stopped":
            status, reason = "stopped", "start again with: reuse --target <dir>"
        else:
            status, reason = (state, "")
        memory = record.get("memory_mib")
        memory = f"{memory} MiB" if isinstance(memory, int) else "-"
        print(
            f"{name:16s} {state:9s} {memory:9s} {status}"
            + (f" ({reason})" if reason else "")
        )
    return 0


def do_reap(args):
    owned, booting = launcher_children()
    stopped = []
    pruned = []
    for record in sorted(sandbox_records(machines()), key=lambda item: item["name"]):
        name = record["name"]
        state = record.get("state")
        if state == "running":
            status, reason = attach_state(record, owned, booting)
            if status == "attached":
                print(f"Keeping {name}: {reason}")
                continue
            if SAVED_NAME.match(name) and not (args.include_named or args.all):
                print(f"Keeping {name}: {reason} (pass --include-named to stop it)")
                continue
            if args.dry_run:
                print(f"Would stop {name}: {reason}")
                continue
            stop(name)
            print(f"Stopped {name}: {reason}")
            stopped.append(name)
            continue
        if state == "stopped":
            if not (args.all or (SAVED_NAME.match(name) and args.include_named)):
                continue
            if args.dry_run:
                print(f"Would delete {name}: stopped")
                continue
            delete(name)
            print(f"Deleted {name}: stopped")
            pruned.append(name)
    if stopped:
        print(
            f"Reclaimed memory from {len(stopped)} abandoned VM"
            f"{'s' if len(stopped) != 1 else ''}."
        )
    freed = store_usage() if (stopped or pruned) else 0
    if freed:
        print(f"Machine store now uses {freed}.")
    return 0


def store_usage():
    """Real disk in the smolvm store. `du` counts sparse files by blocks used."""
    if not SMOLVM_VMS.is_dir():
        return ""
    completed = subprocess.run(
        ["du", "-sh", str(SMOLVM_VMS)], text=True, capture_output=True, check=False
    )
    if completed.returncode != 0:
        return ""
    fields = completed.stdout.split()
    return fields[0] if fields else ""


def stop(name):
    run(["stop", "-n", name])


def delete(name):
    run(["stop", "-n", name], check=False)
    run(["delete", "--name", name, "-f"])


def do_stop(args):
    for name in args.names:
        if args.delete:
            delete(name)
            print(f"Deleted {name} and freed its disk.")
        else:
            stop(name)
            print(
                f"Stopped {name}; its disk is still allocated. Pass --delete to free it."
            )
    return 0


def exec_shell(record, command=None, workdir=None):
    """Join the existing namespace without ever starting a root workload."""
    argv = guest_argv(
        record,
        command or ["/bin/zsh", "-i", "-l"],
        interactive=True,
        workdir=workdir,
    )
    sys.stdout.flush()
    os.execvp(argv[0], argv)


def launcher_path():
    script = Path(__file__).resolve().with_name("sandbox.sh")
    if not script.is_file():
        raise RuntimeError(f"launcher not found beside this script: {script}")
    return script


def do_reuse(args):
    """Use the launcher's canonical image validation and join selection."""
    argv = ["/usr/bin/env", "bash", str(launcher_path())]
    if args.agent:
        argv += ["--agent", args.agent]
    if args.dns:
        argv += ["--dns", args.dns]
    argv.append(args.target)
    sys.stdout.flush()
    os.execv(argv[0], argv)


def guest_project(record):
    """Find the project from decoded mountpoints, using a non-root probe."""
    for path, filesystem, options in guest_mounts(record):
        if (
            filesystem in {"virtiofs", "ext4", "9p", "nfs", "fuse"}
            and path.startswith("/")
            and path != "/"
            and "ro" not in options
            and re.match(r"^/(dev|proc|sys|run|tmp|boot|media|mnt)(/|$)", path) is None
            and not path.endswith(("pi-host", "omp-host", "/sessions", "/blobs"))
        ):
            return path
    return None


def resolve_target(args):
    """The VM to attach: named with --vm, else the one mounted on --target.

    Named and targeted attaches both require a registered image and a live
    launcher; neither enters an old or abandoned VM to discover its state.
    """
    owned, booting = launcher_children()
    workspace = None
    if args.target is not None or args.vm is None:
        workspace = str(Path(args.target or ".").resolve())
        if not Path(workspace).is_dir():
            raise RuntimeError(f"workspace is not a directory: {workspace}")
    if args.vm is not None:
        if not SAVED_NAME.match(args.vm) and not EPHEMERAL_NAME.match(args.vm):
            raise RuntimeError(f"not a sandbox machine name: {args.vm}")
        for record in trusted_records(machines()):
            if record.get("name") == args.vm and record.get("state") == "running":
                status, reason = attach_state(record, owned, booting)
                if status != "attached":
                    raise RuntimeError(
                        f"{args.vm} has {reason}; start a fresh VM with sandbox.sh instead"
                    )
                return record, workspace if workspace is not None else guest_project(record)
        raise RuntimeError(f"no running registered sandbox machine named {args.vm}")
    running = running_for(workspace, owned, booting)
    if running is None:
        raise RuntimeError(
            f"no running VM mounts {workspace}; start one with sandbox.sh"
        )
    status, reason = attach_state(running, owned, booting)
    if status != "attached":
        raise RuntimeError(
            f"{running['name']} mounts {workspace} but {reason}; "
            "start a fresh VM with sandbox.sh instead"
        )
    return running, workspace


def do_attach(args):
    record, workspace = resolve_target(args)
    print(f"Attaching to {record['name']}; a login shell starts beside any console.")
    # REMAINDER keeps the user's separator; setpriv receives its own separator
    # before the workload so flags cannot change privilege restrictions.
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    exec_shell(record, command, workdir=workspace)
    return 0


def join_spec(target):
    """Print the join decision for a workspace, for sandbox.sh.

    One line: `none` (no running VM, or one with a dead launcher: boot fresh),
    or `join <vm-name>` (an attached VM serves the workspace). A launcher that
    exits with the VM still running is exactly the leaked case and boots fresh.
    """
    workspace = str(Path(target).resolve())
    if not Path(workspace).is_dir():
        print("none")
        return 0
    owned, booting = launcher_children()
    running = running_for(workspace, owned, booting)
    if running is None:
        print("none")
        return 0
    status, _ = attach_state(running, owned, booting)
    if status == "attached":
        print(f"join {running['name']}")
    else:
        print("none")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="action", required=True)

    listing = subparsers.add_parser("list", help="show sandbox VMs and who owns them")
    listing.set_defaults(func=do_list)

    reap = subparsers.add_parser("reap", help="stop abandoned VMs, free stale disk")
    reap.add_argument(
        "--dry-run", action="store_true", help="report without changing state"
    )
    reap.add_argument(
        "--include-named", action="store_true", help="also stop detached named machines"
    )
    reap.add_argument(
        "--all", action="store_true", help="also delete stopped machines after reaping"
    )
    reap.set_defaults(func=do_reap)

    stop_parser = subparsers.add_parser("stop", help="stop named sandboxes")
    stop_parser.add_argument("names", nargs="+")
    stop_parser.add_argument(
        "--delete", action="store_true", help="also remove the record and free its disk"
    )
    stop_parser.set_defaults(func=do_stop)

    reuse = subparsers.add_parser(
        "reuse", help="reuse, reactivate, or create the VM for a project"
    )
    reuse.add_argument(
        "--target", default=".", help="project directory (default: current)"
    )
    reuse.add_argument("--agent", choices=("pi", "omp"))
    reuse.add_argument("--dns", help="guest resolver (default: the launcher's choice)")
    reuse.set_defaults(func=do_reuse)

    attach = subparsers.add_parser(
        "attach", help="open a login shell in a running sandbox VM"
    )
    attach.add_argument(
        "--target", help="project directory (default: current, or named VM's project)"
    )
    attach.add_argument("--vm", help="attach by machine name instead of by target")
    attach.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="run this command in the VM instead of a login shell",
    )
    attach.set_defaults(func=do_attach)

    join = subparsers.add_parser(
        "join-spec", help="print the join decision for a workspace (for launchers)"
    )
    join.add_argument("target")
    join.set_defaults(func=lambda args: join_spec(args.target))

    record = subparsers.add_parser(
        "record-image", help="register a validated non-root image archive (for launchers)"
    )
    record.add_argument("image_tar", metavar="IMAGE_TAR")
    record.set_defaults(func=do_record_image)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        host_identity()
        return args.func(args)
    except (RuntimeError, OSError) as error:
        print(f"sandbox-vm: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
