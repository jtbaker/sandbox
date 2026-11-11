#!/usr/bin/env python3
"""Reuse a project's sandbox VM and reclaim abandoned ones.

`smolvm machine run` reaps its own VM when the guest exits cleanly. A run that
is killed, or whose terminal closes, leaks the VM: `machine ls` still lists it
as `running (eph)` and its `_boot-vm` process stays alive with no host process
attached.

`reuse` picks the VM already mounted on a project directory when a live
launcher still owns it, and otherwise starts `sandbox.sh` for that
directory. A VM is never restarted in place, because smolvm skips init on
restart and init is what installs the pinned tailnet policy. `reap` stops
leaked VMs. Both decide ownership from the process tree, never from files, and
touch no VM that did not boot the sandbox image.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

SMOLVM = os.environ.get("SMOLVM", "smolvm")
# smolvm names ephemeral VMs vm-XXXXXXXX and names saved machines after the
# --name it was given, which is sandbox-<project>-<hash>.
EPHEMERAL_NAME = re.compile(r"^vm-[0-9a-f]{8}$")
SAVED_NAME = re.compile(r"^sandbox-[a-z0-9][a-z0-9._-]{0,63}$")
# The launcher exports the resolved image to a tar, so smolvm records the local
# archive identity, not the Docker image id.
LOCAL_IMAGE = re.compile(r"^local:[0-9a-f]{64}$")
SMOLVM_VMS = Path(os.environ.get("HOME", "")) / "Library" / "Caches" / "smolvm" / "vms"


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
    needle = shlex.quote(workspace)
    fallback = None
    for record in sorted(sandbox_records(machines()), key=lambda item: item["name"]):
        if record.get("state") != "running":
            continue
        completed = subprocess.run(
            [
                SMOLVM,
                "machine",
                "exec",
                "--name",
                record["name"],
                "--",
                "/bin/sh",
                "-c",
                f"mount | grep -F {needle}",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0 or workspace not in completed.stdout:
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


def launcher_path():
    script = Path(__file__).resolve().with_name("sandbox.sh")
    if not script.is_file():
        raise RuntimeError(f"launcher not found beside this script: {script}")
    return script


def do_reuse(args):
    """Reuse, reactivate, or create the VM for one project directory.

    A VM with a live launcher is reused: its terminal is the session. When the
    VM for this workspace has no launcher, or none is running, the launcher
    starts again, because smolvm skips init when a machine restarts and a
    stale policy would carry over. Sessions live in host mounts, so history
    survives in every branch.
    """
    workspace = str(Path(args.target).resolve())
    if not Path(workspace).is_dir():
        raise RuntimeError(f"workspace is not a directory: {workspace}")
    owned, booting = launcher_children()
    running = running_for(workspace, owned, booting)
    if running is not None:
        status, reason = attach_state(running, owned, booting)
        if status == "attached":
            print(f"Reusing {running['name']} for {workspace}: {reason}.")
            print(
                "That terminal is the session. Open a second VM from another directory."
            )
            return 0
        print(
            f"{running['name']} serves {workspace} but {reason}; starting a "
            "fresh VM with a current network policy."
        )
    else:
        print(f"No running VM for {workspace}; creating one.")
    agent = args.agent or "pi"
    dns = args.dns or ""
    argv = ["/usr/bin/env", "bash", str(launcher_path()), "--agent", agent]
    if dns:
        argv += ["--dns", dns]
    argv.append(workspace)
    sys.stdout.flush()
    os.execv(argv[0], argv)


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

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as error:
        print(f"sandbox-vm: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
