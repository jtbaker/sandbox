#!/usr/bin/env bash
# Build and boot the working tree without publishing. Only synthetic host
# configuration and session state are mounted; real ~/.pi and ~/.omp stay untouched.
# Reuse a local Docker archive with SANDBOX_VERIFY_IMAGE_TAR=/path/image.tar.
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-verify.XXXXXXXX")"
TMP="$(cd "$TMP" && pwd -P)"
HOST_HOME="$TMP/home"
HOST_TMPDIR="$TMP/native-tmp"
export PI_VERIFY_HOME="$HOST_HOME" PI_VERIFY_TMPDIR="$HOST_TMPDIR"
ACTIVE_VM=""
cleanup() {
    local result=$?
    if [[ -n "$ACTIVE_VM" ]]; then
        kill "$ACTIVE_VM" 2>/dev/null || true
        wait "$ACTIVE_VM" 2>/dev/null || true
    fi
    if [[ "$result" != 0 ]]; then
        printf 'Synthetic fixture diagnostics retained at %s\n' "$TMP" >&2
    else
        rm -rf -- "$TMP"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'printf "FAIL: verifier command failed at line %s\n" "$LINENO" >&2' ERR

command -v smolvm >/dev/null 2>&1 || fail 'smolvm is required'
IMAGE_TAR="${SANDBOX_VERIFY_IMAGE_TAR:-}"
if [[ -n "$IMAGE_TAR" ]]; then
    [[ -f "$IMAGE_TAR" ]] || fail 'SANDBOX_VERIFY_IMAGE_TAR is not a file'
    IMAGE_TAR="$(cd "$(dirname "$IMAGE_TAR")" && pwd)/$(basename "$IMAGE_TAR")"
else
    command -v docker >/dev/null 2>&1 || fail 'docker with buildx is required'
    case "$(uname -m)" in
        arm64|aarch64) ARCH=arm64 ;;
        x86_64|amd64) ARCH=amd64 ;;
        *) fail 'unsupported host architecture' ;;
    esac
    IMAGE_TAR="$TMP/image.tar"
    # Use the existing selected builder without creating, selecting, or removing
    # any builder. Docker output embeds the manifest and layers smolvm needs.
    if ! docker buildx build --progress quiet --platform "linux/$ARCH" \
        -f "$REPO/Dockerfile" --output "type=docker,dest=$IMAGE_TAR" \
        "$REPO" > "$TMP/build.log" 2>&1; then
        fail 'working-tree Docker image build failed'
    fi
    printf 'PASS: working-tree image built locally without publishing\n'
fi
if ! tar -tf "$IMAGE_TAR" > "$TMP/archive-members" 2>/dev/null; then
    fail 'image archive cannot be read'
fi
grep -Eq '^(\./)?manifest\.json$' "$TMP/archive-members" \
    || fail 'image archive is not Docker-compatible (manifest.json missing)'
printf 'PASS: Docker-compatible image archive\n'

mkdir -p "$TMP/fixtures" "$TMP/control" "$HOST_HOME/project" "$HOST_TMPDIR" "$TMP/default-workspace" "$TMP/preparation-workspace"
for workspace in "$HOST_HOME/project" "$TMP/default-workspace" "$TMP/preparation-workspace"; do
    printf 'host workspace content\n' > "$workspace/editable-host-file"
done
printf '{"tailnetHost":"100.64.0.10","httpsPort":443}\n' > "$TMP/control/network.json"
cat > "$TMP/Smolfile" <<'SMOLFILE'
net = true

[dev]
init = [
    "/usr/local/bin/vm-network.py /verify/network.json",
    "/usr/bin/python3 /verify/network-fixtures.py init",
]
SMOLFILE
cat > "$TMP/control/network-fixtures.py" <<'NETWORK'
import errno
import json
import socket
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path


PROOF = Path("/run/sandbox-fixture-network.json")
PAYLOAD = b"sandbox-local-network-fixture\n"
DROP = [
    "/usr/bin/setpriv", "--bounding-set=-all,+dac_override,+fowner", "--inh-caps=-all",
    "--ambient-caps=-all", "--no-new-privs", "/usr/bin/python3", __file__,
]


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def reject_packets():
    ruleset = json.loads(command("nft", "-j", "list", "chain", "inet", "sandbox", "egress"))
    return sum(
        expression["counter"]["packets"]
        for item in ruleset["nftables"] if "rule" in item
        for expression in item["rule"]["expr"] if "counter" in expression
        if any("reject" in part for part in item["rule"]["expr"])
    )


def probe(address, port, allowed):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        try:
            client.connect((address, port))
        except OSError as error:
            if allowed:
                raise AssertionError("configured TCP443 fixture was not reachable") from error
            return
        assert allowed, "forbidden fixture connection succeeded"
        assert client.recv(128) == PAYLOAD, "fixture listener payload mismatch"


def workload():
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    for name in ("CapEff", "CapBnd", "CapPrm"):
        assert int(status[name].strip(), 16) == 0xA, f"{name} exceeds filesystem-only permissions"
    for name in ("CapAmb", "CapInh"):
        assert int(status[name].strip(), 16) == 0, f"{name} is not zero"
    assert status["NoNewPrivs"].strip() == "1", "NoNewPrivs is not enabled"
    editable = Path.cwd() / "editable-host-file"
    editable.write_text("guest workspace edit\n")
    editable.chmod(0o600)
    assert editable.read_text() == "guest workspace edit\n"
    denied = subprocess.run(
        ["nft", "add", "table", "inet", "sandbox_bypass"],
        capture_output=True, text=True,
    )
    assert denied.returncode != 0, "capability-dropped workload modified nftables"
    assert any(text in denied.stderr.lower() for text in ("not permitted", "permission denied")), (
        "nft modification failed for a reason other than missing privilege"
    )
    for family, kind, protocol in (
        (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)),
        (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
        (socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6),
    ):
        try:
            raw = socket.socket(family, kind, protocol)
        except OSError as error:
            assert error.errno in (errno.EPERM, errno.EACCES), (
                "raw socket failed for a reason other than missing privilege"
            )
        else:
            raw.close()
            raise AssertionError("capability-dropped workload created a packet/raw socket")
    proof = json.loads(PROOF.read_text())
    assert proof["allowedTCP443"] is True
    assert proof["allowedPublicTCP443"] is True
    assert proof["deniedIPv4"] == ["100.64.0.10:22", "100.64.0.11:443"]
    assert all(delta >= 1 for delta in proof["rejectCounterDeltas"])
    assert len(proof["rejectCounterDeltas"]) == 2 + int(proof["ipv6Route"])
    marker = json.loads(Path("/run/sandbox-network.json").read_text())
    assert marker["tailnetHost"] == "100.64.0.10"
    assert marker["httpsPort"] == 443
    assert marker["allowedIPv4"] == ["100.64.0.10"] and marker["allowedIPv6"] == []
    print("PASS: network: local Tailscale-address fixture accepts only configured TCP443")
    print("PASS: network: simulated public IPv4 fixture accepts TCP443 through kernel policy")
    print("PASS: network: forbidden Tailscale IPv4 probes increment kernel reject counters")
    if proof["ipv6Route"]:
        print("PASS: network: forbidden Tailscale IPv6 probe increments kernel reject counter")
    else:
        print("PASS: network: IPv6 route absence recorded; IPv4 kernel reject proofs enforced")
    print("PASS: network: filesystem-only capabilities preserve workspace edits; nft and raw sockets denied")


def trusted_init():
    # This disposable network exists only during trusted init. It is not an
    # external server, a real tailnet peer, or a privileged background daemon.
    namespace = "pi-verify-peer"
    host = "pi-verify-host"
    peer = "pi-verify-peer"
    server = None
    created_namespace = False
    created_link = False
    try:
        command("ip", "netns", "add", namespace)
        created_namespace = True
        command("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
        created_link = True
        command("ip", "link", "set", peer, "netns", namespace)
        command("ip", "address", "add", "100.64.0.1/24", "dev", host)
        command("ip", "link", "set", host, "up")
        command("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
        command("ip", "netns", "exec", namespace, "ip", "address", "add",
                "100.64.0.10/24", "dev", peer)
        command("ip", "netns", "exec", namespace, "ip", "link", "set", peer, "up")
        # 1.1.1.1 is assigned solely inside this guest-owned namespace. Its
        # exact /32 route points across our veth, never to the real Internet.
        command("ip", "netns", "exec", namespace, "ip", "address", "add",
                "1.1.1.1/32", "dev", "lo")
        command("ip", "route", "add", "1.1.1.1/32", "via", "100.64.0.10", "dev", host)
        server = subprocess.Popen(
            ["ip", "netns", "exec", namespace, "/usr/bin/python3", __file__, "serve"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert server.stdout.readline() == "ready\n", "local fixture listener did not start"
        subprocess.run([*DROP, "probe", "100.64.0.10", "443", "allow"], check=True)
        subprocess.run([*DROP, "probe", "1.1.1.1", "443", "allow"], check=True)
        assert server.wait(timeout=5) == 0, "local fixture listener did not complete"
        proof = {
            "allowedTCP443": True, "allowedPublicTCP443": True,
            "deniedIPv4": [], "rejectCounterDeltas": [],
            "ipv6Route": False,
        }
        for address, port in (("100.64.0.10", 22), ("100.64.0.11", 443)):
            before = reject_packets()
            subprocess.run([*DROP, "probe", address, str(port), "deny"], check=True)
            delta = reject_packets() - before
            assert delta >= 1, "forbidden IPv4 probe did not hit a kernel reject rule"
            proof["rejectCounterDeltas"].append(delta)
            proof["deniedIPv4"].append(f"{address}:{port}")
        # An explicit fixture route makes IPv6 deterministic when the kernel
        # enables it. Disabled IPv6 has no route and is recorded, not faked.
        ipv6_disabled = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if ipv6_disabled.exists() and ipv6_disabled.read_text().strip() == "0":
            command("ip", "-6", "address", "add", "fd7a:115c:a1e0::a/64",
                    "dev", host, "nodad")
        route = subprocess.run(
            ["ip", "-6", "route", "get", "fd7a:115c:a1e0::b"],
            capture_output=True, text=True,
        )
        if route.returncode == 0:
            before = reject_packets()
            subprocess.run(
                [*DROP, "probe", "fd7a:115c:a1e0::b", "443", "deny"], check=True,
            )
            delta = reject_packets() - before
            assert delta >= 1, "forbidden IPv6 probe did not hit a kernel reject rule"
            proof["rejectCounterDeltas"].append(delta)
            proof["ipv6Route"] = True
        PROOF.write_text(json.dumps(proof))
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            server.wait(timeout=5)
        if created_link:
            command("ip", "link", "delete", host)
        if created_namespace:
            command("ip", "netns", "delete", namespace)


if sys.argv[1] == "init":
    try:
        trusted_init()
    except Exception as error:
        Path("/workspace/failure").write_text(
            f"FAIL: trusted network fixture failed ({type(error).__name__}: {error})\n"
        )
        raise
elif sys.argv[1] == "serve":
    with ExitStack() as resources:
        listeners = []
        for address in ("100.64.0.10", "1.1.1.1"):
            listener = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, 443))
            listener.listen(1)
            listener.settimeout(10)
            listeners.append(listener)
        print("ready", flush=True)
        for listener in listeners:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(PAYLOAD)
elif sys.argv[1] == "probe":
    probe(sys.argv[2], int(sys.argv[3]), sys.argv[4] == "allow")
elif sys.argv[1] == "workload":
    workload()
else:
    raise SystemExit("unsupported network fixture operation")
NETWORK
# Deliberately permissive sources ensure private copies are not just inheriting
# safe host modes. These are markers, not credentials or executable host tools.
for agent in pi omp; do
    root="$TMP/fixtures/$agent"
    mkdir -p "$root/agent/extensions/nested" "$root/profiles/work"
    printf '{"origin":"%s-root"}\n' "$agent" > "$root/config-origin.json"
    printf '{"origin":"%s-agent"}\n' "$agent" > "$root/agent/config-origin.json"
    printf '{"origin":"%s-profile"}\n' "$agent" > "$root/profiles/work/config.json"
    printf 'synthetic root config\n' > "$root/root-config.txt"
    printf 'synthetic nested config\n' > "$root/agent/extensions/nested/config.txt"
    mkdir -p "$root/agent/extensions/run"
    printf 'portable extension source\n' > "$root/agent/extensions/run/config.txt"
    for config_root in "$root" "$root/profiles/work"; do
        for runtime in run ssh-control puppeteer natives .supervisor; do
            mkdir -p "$config_root/$runtime"
            printf 'host process state\n' > "$config_root/$runtime/fixture-marker"
        done
    done
    printf 'synthetic removable config\n' > "$root/agent/deletable.txt"
    printf 'synthetic read-only marker\n' > "$root/read-only-marker"
    printf '#!/bin/sh\nexit 0\n' > "$root/agent/extensions/fixture-tool.sh"
    printf '{}\n' > "$root/agent/settings.json"
    printf '{}\n' > "$root/agent/auth.json"
    printf '{}\n' > "$root/agent/config.yml"
    # A valid empty provider map does not point agents at any host service.
    printf '{"providers":{}}\n' > "$root/agent/models.json"
    # Real SQLite coverage lives at root state.db, never at an agent-owned
    # database path. History database markers below must always be excluded.
    for level in "$root" "$root/agent" "$root/agent/extensions/nested"; do
        for excluded in sessions terminal-sessions cache caches logs bin __pycache__ .git; do
            mkdir -p "$level/$excluded"
            printf 'must not be copied\n' > "$level/$excluded/fixture-marker"
        done
        for excluded in history.db history.db-wal history.db-shm history.db.backup trust.json trust.db trust.db-wal fixture.db-wal fixture.db-shm .seeded; do
            printf 'must not be copied\n' > "$level/$excluded"
        done
    done
    ln -s /etc/passwd "$root/symlink-file"
    ln -s /etc "$root/symlink-directory"
    ln -s absent-target "$root/broken-symlink"
    ln -s extensions/nested/config.txt "$root/agent/relative-symlink-file"
    ln -s extensions "$root/agent/relative-symlink-directory"
    find "$root" -type d -exec chmod 0777 {} +
    find "$root" -type f -exec chmod 0666 {} +
    chmod 0777 "$root/agent/extensions/fixture-tool.sh"
done
# State is intentionally separate from read-only configuration fixtures, so the
# final byte-for-byte config comparison excludes legitimate transcript writes.
for state in "$HOST_HOME/.pi/agent/sessions" \
    "$HOST_HOME/.omp/agent/sessions" "$HOST_HOME/.omp/agent/blobs" \
    "$HOST_HOME/.omp/profiles/work/agent/sessions" "$HOST_HOME/.omp/profiles/work/agent/blobs"; do
    mkdir -p "$state"
    printf 'mounted state is not a private config copy\n' > "$state/mount-marker"
    chmod 0777 "$state"
    chmod 0666 "$state/mount-marker"
done
printf 'host HOME is not a volume\n' > "$HOST_HOME/private-home-marker"
mkdir -p "$TMP/fixtures/omp/profiles/work/agent"
printf '{}\n' > "$TMP/fixtures/omp/profiles/work/agent/config.yml"
cat > "$TMP/control/sqlite-fixtures.py" <<'SQLITE'
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path


if sys.argv[1] == "prepare":
    for agent in ("pi", "omp"):
        with tempfile.TemporaryDirectory(prefix="sqlite-fixture-") as temporary:
            database = Path(temporary) / "state.db"
            connection = sqlite3.connect(database)
            try:
                assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
                connection.execute("CREATE TABLE snapshot_fixture(value TEXT)")
                connection.commit()
                assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
                connection.execute(
                    "INSERT INTO snapshot_fixture(value) VALUES (?)",
                    (f"{agent}-wal-committed",),
                )
                connection.commit()
                # Prove the committed row really requires WAL replay, rather
                # than accidentally testing an already-checkpointed database.
                with closing(sqlite3.connect(f"{database.as_uri()}?immutable=1", uri=True)) as main_only:
                    assert main_only.execute("SELECT count(*) FROM snapshot_fixture").fetchone() == (0,)
                assert Path(f"{database}-wal").stat().st_size > 32
                for suffix in ("", "-wal", "-shm"):
                    target = Path("/fixtures") / agent / f"state.db{suffix}"
                    shutil.copyfile(Path(f"{database}{suffix}"), target)
                    target.chmod(0o666)
                # A host runtime WAL database without its SHM must not be
                # opened through the read-only configuration mount at all.
                for root in (Path("/fixtures") / agent,
                             Path("/fixtures") / agent / "profiles" / "work"):
                    shutil.copyfile(database, root / "run" / "browser-cache.db")
            finally:
                connection.close()
    Path("/fixtures/sqlite-prepared").write_text("complete\n")
elif sys.argv[1] == "check":
    for agent in ("pi", "omp"):
        database = Path.home() / f".{agent}" / "state.db"
        assert database.is_file()
        # Assert before connecting: opening a WAL-mode database can itself
        # create sidecars, which must not disguise files copied from the host.
        assert not Path(f"{database}-wal").exists()
        assert not Path(f"{database}-shm").exists()
        with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro&immutable=1", uri=True)) as snapshot:
            assert snapshot.execute("PRAGMA quick_check").fetchall() == [("ok",)]
            assert snapshot.execute("SELECT value FROM snapshot_fixture").fetchall() == [
                (f"{agent}-wal-committed",)
            ]
elif sys.argv[1] == "stress":
    import runpy
    module = runpy.run_path("/usr/local/bin/vm-seed.py")
    connect = sqlite3.connect
    with tempfile.TemporaryDirectory(prefix="sqlite-changing-") as temporary:
        source = Path(temporary) / "models.db"
        destination = Path(temporary) / "snapshot.db"
        with closing(connect(source)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("CREATE TABLE revision(value INTEGER)")
            writer.execute("INSERT INTO revision VALUES(0)")
            writer.execute("CREATE TABLE payload(data BLOB)")
            writer.executemany("INSERT INTO payload VALUES(?)", [(b"x" * 4096,)] * 4096)
            writer.commit()
            steps = []

            class ChangingSource(sqlite3.Connection):
                def backup(self, target, *, pages, progress):
                    def advance(status, remaining, total):
                        steps.append(remaining)
                        assert len(steps) <= 40, "snapshot restarted under concurrent writes"
                        if remaining:
                            writer.execute("UPDATE revision SET value=value+1")
                            writer.commit()
                        progress(status, remaining, total)
                    return super().backup(target, pages=pages, progress=advance)

            def changing_connect(database, *args, **kwargs):
                if str(database).endswith("?mode=ro"):
                    kwargs["factory"] = ChangingSource
                return connect(database, *args, **kwargs)

            # Commit a real write between every backup batch. This makes the
            # host-writer race deterministic without relying on thread timing.
            sqlite3.connect = changing_connect
            try:
                module["backup_database"](source, destination)
            finally:
                sqlite3.connect = connect
            with closing(connect(destination)) as snapshot:
                assert snapshot.execute("SELECT value FROM revision").fetchone() == (0,)
                assert snapshot.execute("SELECT count(*) FROM payload").fetchone() == (4096,)
                assert snapshot.execute("PRAGMA quick_check").fetchall() == [("ok",)]
            assert writer.execute("SELECT value FROM revision").fetchone()[0] > 0
else:
    raise SystemExit("unsupported fixture operation")
SQLITE

# Prepare genuine live-WAL snapshots using only the image's Python standard
# library. Writable host mounts contain only disposable synthetic fixtures.
if ! (cd "$TMP" && smolvm machine run --unprivileged --net-backend virtio-net \
    --smolfile "$TMP/Smolfile" --no-init-cache --timeout 120s --mem 2048 --cpus 2 \
    --workdir "$TMP/preparation-workspace" -v "$TMP/control:/verify:ro" \
    -v "$TMP/preparation-workspace:$TMP/preparation-workspace" \
    -v "$TMP/fixtures:/fixtures" --image "$IMAGE_TAR" \
    -- /usr/bin/setpriv --bounding-set=-all,+dac_override,+fowner --inh-caps=-all \
    --ambient-caps=-all --no-new-privs /usr/bin/python3 /verify/sqlite-fixtures.py prepare) \
    > "$TMP/sqlite-preparation.log" 2>&1; then
    if [[ -f "$TMP/preparation-workspace/failure" ]]; then
        IFS= read -r detail < "$TMP/preparation-workspace/failure"
        fail "SQLite preparation: $detail"
    fi
    fail 'SQLite WAL fixture preparation boot failed'
fi
[[ -f "$TMP/fixtures/sqlite-prepared" ]] || fail 'SQLite WAL fixture preparation did not finish'
printf 'PASS: genuine committed SQLite WAL fixtures prepared without host dependencies\n'
# Byte-for-byte snapshots also cover file modes, symlinks, names and mtimes.
# Reading a file may update atime, which ordinary tar headers do not include.
COPYFILE_DISABLE=1 tar -cf "$TMP/fixtures-before.tar" -C "$TMP/fixtures" pi omp

# Exercise published storage APIs, not a hand-written approximation of JSONL.
cat > "$TMP/control/pi-sessions.mjs" <<'PI_SESSIONS'
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { SessionManager } from "/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/dist/index.js";

const [mode, previous] = process.argv.slice(2);
const cwd = process.cwd();
const text = (manager) => JSON.stringify(manager.buildSessionContext().messages);
const append = (manager, phase) => {
    manager.appendMessage({ role: "user", content: `fixture-pi-${phase}`, timestamp: Date.now() });
    manager.appendMessage({
        role: "assistant", content: [{ type: "text", text: `fixture-pi-answer-${phase}` }],
        api: "openai-completions", provider: "fixture", model: "fixture",
        usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
        stopReason: "stop", timestamp: Date.now(),
    });
};
let manager;
if (mode === "fixture") {
    manager = SessionManager.create(cwd);
    assert(!fs.existsSync(manager.getSessionFile()), "Pi should persist lazily");
    append(manager, mode);
    const source = manager.getSessionFile();
    manager = SessionManager.forkFrom(source, cwd);
    assert.equal(manager.getHeader().parentSession, source);
    assert(path.isAbsolute(source) && fs.existsSync(source));
    // Ensure continueRecent has one winner even on coarse-mtime filesystems.
    fs.utimesSync(source, new Date(0), new Date(0));
} else {
    const listed = await SessionManager.list(cwd);
    assert(listed.some((entry) => entry.path === previous), "native Pi listing lost session");
    manager = SessionManager.continueRecent(cwd);
    assert.equal(manager.getSessionFile(), previous, "native Pi continue chose wrong session");
    assert(text(manager).includes("fixture-pi-answer-fixture"), "Pi replay lost first turn");
    assert(fs.existsSync(manager.getHeader().parentSession), "absolute parentSession is not host-valid");
    append(manager, mode);
}
const bucket = `--${cwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
assert.equal(path.dirname(manager.getSessionFile()), path.join(process.env.HOME, ".pi/agent/sessions", bucket));
assert.equal(manager.getHeader().cwd, cwd);
const opened = SessionManager.open(manager.getSessionFile());
assert(text(opened).includes("fixture-pi-answer-fixture"), "Pi public reader lost turn");
assert((await SessionManager.listAll()).some((entry) => entry.path === manager.getSessionFile()));
console.log(JSON.stringify({ path: manager.getSessionFile(), parent: manager.getHeader().parentSession }));
PI_SESSIONS

cat > "$TMP/control/sessions.py" <<'SESSIONS'
import base64
import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HOME = Path(os.environ["HOME"])
CWD = Path.cwd()
ROOTS = [HOME / ".pi/agent", HOME / ".omp/agent", HOME / ".omp/profiles/work/agent"]
MOUNTS = [ROOTS[0] / "sessions", *[root / name for root in ROOTS[1:] for name in ("sessions", "blobs")]]
PROOF = CWD / "session-proof.json"
MARKER = "mounted state is not a private config copy\n"


def login_shell(script):
    import fcntl
    import pty
    import termios

    master, slave = pty.openpty()
    try:
        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        result = subprocess.run(["zsh", "-lic", script], stdin=slave,
                                capture_output=True, text=True, timeout=30,
                                preexec_fn=terminal)
    finally:
        os.close(slave)
        os.close(master)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr, f"interactive login shell startup errors: {result.stderr}"


def mounted(path):
    # virtiofs is not guaranteed to change st_dev for nested host mounts.
    encoded = str(path).replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")
    return path.is_mount() or any(line.split()[4] == encoded for line in Path("/proc/self/mountinfo").read_text().splitlines())


def structure():
    assert not mounted(HOME) and not (HOME / "private-home-marker").exists(), "host HOME was mounted wholesale"
    targets = MOUNTS[:3] if len(sys.argv) > 2 and sys.argv[2] == "default" else MOUNTS
    for target in targets:
        assert target.is_dir() and not target.is_symlink() and mounted(target), f"missing native mount: {target}"
        assert (target / "mount-marker").read_text() == MARKER
        assert not (target / "fixture-marker").exists(), "configuration snapshot was merged into mounted state"
        assert stat.S_IMODE((target / "mount-marker").stat().st_mode) == 0o666, "seeder chmodded RW state"
        assert stat.S_IMODE(target.stat().st_mode) == 0o777, "seeder chmodded RW mountpoint"
    for root in (HOME / ".pi", HOME / ".omp"):
        for directory, names, files in os.walk(root, followlinks=False):
            current = Path(directory)
            names[:] = [name for name in names if current / name not in MOUNTS]
            assert not current.is_symlink() and stat.S_IMODE(current.stat().st_mode) == 0o700
            for name in [*names, *files]:
                item = current / name
                assert not item.is_symlink(), "symlink copied into private configuration"
                if item.is_file():
                    assert stat.S_IMODE(item.stat().st_mode) in (0o600, 0o700)
    for root in ROOTS:
        for name in ("history.db", "terminal-sessions"):
            assert not mounted(root / name), "runtime/index directory shared with host"
    assert not mounted(HOME / ".omp/run"), "run leases shared with host"


def policy():
    actual = json.loads((ROOTS[0] / "sandbox.json").read_text())["filesystem"]
    assert {str(HOME / ".pi"), str(HOME / ".omp"), "/root/.pi-host", "/root/.omp-host"} \
        <= set(actual["denyRead"]), "private credentials or RO source paths are not protected"
    assert {".", str(HOME / ".npm"), str(HOME / ".cache"),
            str(HOME / ".local/share"), str(HOME / ".config")} <= set(actual["allowWrite"])
    assert {".env", ".env.*", "*.pem", "*.key"} <= set(actual["denyWrite"])


def png():
    # A valid deterministic image above omp's 1024-base64-character blob
    # threshold; no Pillow, host interpreter, or model service is required.
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    pixels = bytes((index * 37 + index // 11) % 256 for index in range(64 * 64 * 3))
    rows = b"".join(b"\0" + pixels[offset:offset + 192] for offset in range(0, len(pixels), 192))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows, 0)) + chunk(b"IEND", b"")


def bucket():
    for root, prefix in ((Path(os.environ["TMPDIR"]), "-tmp"), (HOME, "-")):
        try:
            relative = str(CWD.relative_to(root))
        except ValueError:
            continue
        encoded = re.sub(r"[/\\:]", "-", "" if relative == "." else relative)
        return prefix + ("" if prefix.endswith("-") or not encoded else "-") + encoded
    return "--" + re.sub(r"[/\\:]", "-", str(CWD).lstrip("/\\")) + "--"


def entries(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def turn(root, profile, mode, saved):
    for name in ("history.db", "terminal-sessions"):
        assert not (root / name).exists(), f"new environment inherited {name}"
    requests, errors, image_digests = [], [], []
    answer = f"fixture-answer-{mode}-{profile}"
    previous = f"fixture-answer-{'fixture' if mode == 'resume' else 'resume'}-{profile}"

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                assert self.path == "/v1/chat/completions", "unexpected provider endpoint"
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert body["model"] == "fixture" and body["stream"] is True
                messages = body["messages"]
                (CWD / f"{mode}-{profile}-request.json").write_text(json.dumps(body))
                serialized = json.dumps(messages)
                assert f"fixture-prompt-{profile}" in serialized, "resume did not replay original user turn"
                if mode != "fixture":
                    assert previous in serialized, "resume did not replay last saved assistant turn"
                urls = [
                    part["image_url"]["url"] for message in messages
                    if isinstance(message.get("content"), list)
                    for part in message["content"] if part.get("type") == "image_url"
                ]
                assert urls, "saved image blob did not rehydrate"
                incoming = [hashlib.sha256(base64.b64decode(url.split(",", 1)[1], validate=True)).hexdigest() for url in urls]
                if saved:
                    assert incoming == saved["images"], "resume changed or lost saved provider image data"
                image_digests.extend(incoming)
                assert "blob:sha256:" not in serialized, "unresolved blob sent to provider"
                requests.append(body)
                chunks = [
                    {"index": 0, "delta": {"role": "assistant", "content": answer}, "finish_reason": None},
                    {"index": 0, "delta": {}, "finish_reason": "stop"},
                ]
                payload = "".join("data: " + json.dumps({"id": "fixture", "object": "chat.completion.chunk", "model": "fixture", "choices": [choice]}) + "\n\n" for choice in chunks) + "data: [DONE]\n\n"
                payload = payload.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as error:
                errors.append(str(error))
                self.send_error(400, "synthetic provider assertion failed")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    model = {"id": "fixture", "name": "Fixture", "api": "openai-completions", "reasoning": False,
             "input": ["text", "image"], "contextWindow": 128000, "maxTokens": 256,
             "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
             "compat": {"stripImageInput": False}}
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.yml").write_text(json.dumps({"images": {"autoResize": False, "blockImages": False}}))
    # No host index is supplied. Start with a genuinely empty, VM-private
    # SQLite database, so continue/id resolution must discover JSONL itself.
    import sqlite3
    fresh = sqlite3.connect(root / "history.db")
    try:
        fresh.execute("VACUUM")
        assert fresh.execute("SELECT name FROM sqlite_master").fetchall() == []
    finally:
        fresh.close()
    (root / "models.yml").write_text(json.dumps({"providers": {"fixture": {
        "baseUrl": f"http://127.0.0.1:{server.server_port}/v1", "api": "openai-completions",
        "apiKey": "fixture-key", "models": [model]}}}))
    command = ["omp", "-p", "--model", "fixture/fixture", "--api-key", "fixture-key",
               "--no-title", "--no-tools", "--no-lsp", "--no-extensions", "--no-skills", "--no-rules",
               "--thinking", "off", "--system-prompt", "Reply with the synthetic provider response."]
    if profile == "work":
        command += ["--profile", "work"]
    if mode == "fixture":
        command += [f"@{CWD / 'fixture-image.png'}", f"fixture-prompt-{profile}"]
    else:
        command += (["--resume", saved["id"]] if mode == "resume" and profile == "work" else ["--continue"])
        command += [f"fixture-next-{mode}-{profile}"]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                                env={**os.environ, "PI_NO_TITLE": "1"})
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
        (CWD / f"{mode}-{profile}-cli.log").write_text(decoded(error.stdout) + decoded(error.stderr))
        (CWD / f"{mode}-{profile}-provider.json").write_text(json.dumps({
            "requestCount": len(requests), "errors": errors,
        }))
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    (CWD / f"{mode}-{profile}-cli.log").write_text(result.stdout + result.stderr)
    assert not errors, errors
    assert result.returncode == 0 and answer in result.stdout, "actual omp CLI turn failed (see synthetic CLI log)"
    assert len(requests) == 1, "unexpected extra model requests"
    files = list((root / "sessions").glob("*/*.jsonl"))
    assert len(files) == 1, "omp wrote outside native bucket or mixed profile histories"
    session = files[0]
    assert session.parent.name == bucket(), "native omp project bucket mismatch"
    content = entries(session)
    header = next(entry for entry in content if entry["type"] == "session")
    assert header["cwd"] == str(CWD)
    assert answer in session.read_text()
    if saved:
        assert str(session) == saved["path"] and header["id"] == saved["id"], "resume relocated/forked the original session"
    refs = re.findall(r"blob:sha256:([0-9a-f]{64})", session.read_text())
    assert refs, "actual image-bearing turn did not produce a blob reference"
    blobs = [root / "blobs" / digest for digest in set(refs)]
    assert all(blob.is_file() and hashlib.sha256(blob.read_bytes()).hexdigest() == blob.name for blob in blobs)
    assert set(image_digests) <= {blob.name for blob in blobs}, "provider image is missing from persisted blobs"
    artifact = session.with_suffix("") / "local" / "fixture-artifact.txt"
    if mode == "fixture":
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(f"fixture-artifact-{profile}\n")
    assert artifact.read_text() == f"fixture-artifact-{profile}\n", "omp same-basename artifacts disappeared"
    assert (root / "history.db").is_file() and not mounted(root / "history.db"), "fresh omp index is not private"
    return {"path": str(session), "id": header["id"], "artifact": str(artifact), "blobs": [str(blob) for blob in blobs], "images": image_digests}


def sessions(mode):
    assert HOME == Path(os.environ["PI_VERIFY_HOME"]) and Path(os.environ["TMPDIR"]) == Path(os.environ["PI_VERIFY_TMPDIR"])
    assert CWD == Path(os.environ["PI_VERIFY_WORKSPACE"]) and str(CWD) != "/workspace"
    old = json.loads(PROOF.read_text()) if mode != "fixture" else {}
    image = png()
    (CWD / "fixture-image.png").write_bytes(image)
    command = ["node", "/verify/pi-sessions.mjs", mode]
    if old:
        command.append(old["pi"]["path"])
    pi = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    proof = {"pi": json.loads(pi.stdout)}
    for root, profile in zip(ROOTS[1:], ("omp", "work")):
        proof[profile] = turn(root, profile, mode, old.get(profile))
    assert len({proof[name]["path"] for name in ("pi", "omp", "work")}) == 3
    PROOF.write_text(json.dumps(proof))
    if mode == "fixture":
        paths = [proof["pi"]["path"], proof["pi"]["parent"]]
        for profile in ("omp", "work"):
            paths += [proof[profile]["path"], proof[profile]["artifact"], *proof[profile]["blobs"]]
        (CWD / "live-paths").write_text("".join(path + "\n" for path in paths))
        (CWD / "live-ready").write_text("actual agent writes complete\n")
        deadline = time.monotonic() + 45
        while not (CWD / "host-observed").exists():
            assert time.monotonic() < deadline, "host did not observe writes while VM was running"
            time.sleep(0.1)
    if mode == "host":
        (CWD / "assertions").write_text("PASS: host-equivalent native discovery/continue replays VM turns and images without seeding or shared SQLite\n")
        (CWD / "completed").write_text("host-complete\n")


try:
    operation = sys.argv[1]
    if operation == "structure":
        structure()
    elif operation == "policy":
        policy()
    elif operation == "shell":
        login_shell(sys.argv[2])
    else:
        sessions(operation)
except Exception:
    (CWD / "failure").write_text("FAIL: session API/native state regression (see synthetic boot log)\n")
    raise
SESSIONS

cat > "$TMP/control/checks.zsh" <<'GUEST'
set -eu
setopt PIPE_FAIL
workspace="$PWD"
fail() { print -r -- "FAIL: $1" > "$workspace/failure"; exit 1; }
pass() { print -r -- "PASS: $1" >> "$workspace/assertions"; }
trap 'print -r -- "FAIL: guest assertion or command failed" > "$workspace/failure"' ZERR
mode="$1"
/usr/bin/python3 /verify/network-fixtures.py workload >> "$workspace/assertions" \
    || fail 'network filter proof or capability-drop contract failed'
[[ ${+PI_CODING_AGENT_DIR} == 0 && ${+PI_CODING_AGENT_SESSION_DIR} == 0 ]] \
    || fail 'global agent/session directory override is set'
[[ "$HOME" == "$PI_VERIFY_HOME" && "$TMPDIR" == "$PI_VERIFY_TMPDIR" ]] \
    || fail 'canonical HOME or TMPDIR was not mirrored'
[[ "$PWD" == "$PI_VERIFY_WORKSPACE" && "$PWD" != /workspace ]] || fail 'canonical workspace was not mirrored'
[[ "$SANDBOX_PERSIST_SESSIONS" == 1 ]] || fail 'persistent session boot flag missing'
[[ -d "$HOME/.pi/agent" && -d "$HOME/.omp/agent" ]] || fail 'native agent directories missing'
[[ ! -L "$HOME/.pi" && ! -L "$HOME/.omp" && ! -e "$HOME/.pi-agent" ]] || fail 'config roots are not separate native directories'
/usr/bin/python3 /verify/sessions.py policy || fail 'Pi autonomous sandbox policy missing or changed'
[[ ! -e "$HOME/.omp/agent/sandbox.json" ]] || fail 'Pi sandbox profile leaked into omp config'
pass "$mode: mirrored HOME, TMPDIR, cwd and independent native config paths"

# Mounted state retains its original modes; only private config is hardened.
/usr/bin/python3 /verify/sessions.py structure "$mode" || fail 'native state mounts or private config permissions failed'
pass "$mode: exact RW state mounts preserve contents and modes; private config has no symlinks"

if [[ "$mode" != default ]]; then
    /usr/bin/python3 /verify/sqlite-fixtures.py check \
        || fail 'SQLite backup omitted committed WAL data, copied sidecars, or failed quick_check'
    pass 'fixture: private SQLite snapshots include committed WAL data and pass quick_check'
    for agent in pi omp; do
        root="$HOME/.$agent"
        src="/root/.$agent-host"
        [[ "$(< "$root/config-origin.json")" == "{\"origin\":\"$agent-root\"}" ]] || fail 'same-named root config was merged or lost'
        [[ "$(< "$root/agent/config-origin.json")" == "{\"origin\":\"$agent-agent\"}" ]] || fail 'same-named agent config was merged or lost'
        [[ "$(< "$root/profiles/work/config.json")" == "{\"origin\":\"$agent-profile\"}" ]] || fail 'named profile was not copied'
        cmp -s "$src/root-config.txt" "$root/root-config.txt" || fail 'root-level configuration not copied'
        cmp -s "$src/agent/extensions/nested/config.txt" "$root/agent/extensions/nested/config.txt" || fail 'nested configuration not copied'
        cmp -s "$src/agent/extensions/run/config.txt" "$root/agent/extensions/run/config.txt" \
            || fail 'portable extension directory named run was incorrectly excluded'
        for config_root in "$root" "$root/profiles/work"; do
            for runtime in run ssh-control puppeteer natives .supervisor; do
                [[ ! -e "$config_root/$runtime" ]] || fail 'host daemon/browser/native runtime tree copied'
            done
        done
        [[ "$(stat -c %a "$root/agent/extensions/fixture-tool.sh")" == 700 ]] || fail 'copied executable is not private 0700'
        [[ "$(stat -c %a "$root/root-config.txt")" == 600 ]] || fail 'copied ordinary file is not private 0600'
        for level in "$root" "$root/agent" "$root/agent/extensions/nested"; do
            for excluded in sessions terminal-sessions cache caches logs bin __pycache__ .git history.db history.db-wal history.db-shm history.db.backup trust.json trust.db trust.db-wal fixture.db-wal fixture.db-shm .seeded; do
                [[ "$level/$excluded" == "$root/agent/sessions" ]] && continue
                [[ ! -e "$level/$excluded" && ! -L "$level/$excluded" ]] || fail 'non-mounted host history, binaries, cache, or trust copied'
            done
        done
        for link in "$root/symlink-file" "$root/symlink-directory" "$root/broken-symlink" "$root/agent/relative-symlink-file" "$root/agent/relative-symlink-directory"; do
            [[ ! -e "$link" && ! -L "$link" ]] || fail 'symlink was followed or copied'
        done
        if (print -r -- forbidden > "$src/write-probe") 2>/dev/null; then
            fail 'source mount allowed file creation'
        fi
        if (print -r -- forbidden > "$src/config-origin.json") 2>/dev/null; then
            fail 'source mount allowed existing file modification'
        fi
        if rm "$src/read-only-marker" 2>/dev/null; then
            fail 'source mount allowed file deletion'
        fi
        if chmod 0600 "$src/config-origin.json" 2>/dev/null; then
            fail 'source mount allowed metadata modification'
        fi
        command -v mount >/dev/null || fail 'mount command is required for the remount regression'
        if mount -o remount,rw "$src" 2>/dev/null; then
            fail 'restricted guest remounted a host config source writable'
        fi
        if (print -r -- forbidden >> "$src/read-only-marker") 2>/dev/null; then
            fail 'source mount allowed writes after remount attempt'
        fi
    done
    pass 'fixture: same-named Pi and omp config, root files, and named profiles stay separate'
    pass 'fixture: only native mounted sessions survive; arbitrary nested sessions and private runtime state omitted'
    pass "$mode: host runtime trees omitted while portable extension run directories survive"
    pass "$mode: source mounts reject writes and metadata changes, including after remount attempts"
    # Nested login shells remain supported; privileged nested bubblewrap does
    # not, because restoring NET_ADMIN/SYS_ADMIN would undermine the filter.

    for agent in pi omp; do
        print -r -- '{"origin":"vm-edit"}' > "$HOME/.$agent/config-origin.json"
        print -r -- '{"origin":"vm-edit"}' > "$HOME/.$agent/agent/config-origin.json"
        touch -t 200001010000 "$HOME/.$agent/config-origin.json" "$HOME/.$agent/agent/config-origin.json"
        rm "$HOME/.$agent/agent/deletable.txt"
    done
    print '' >> "$HOME/.pi/agent/sandbox.json"
    cp "$HOME/.pi/agent/sandbox.json" "$workspace/edited-sandbox.json"
    /usr/bin/python3 /verify/sessions.py shell '
        set -eu
        [[ ${+PI_CODING_AGENT_DIR} == 0 ]]
        uv --version >/dev/null
        for agent in pi omp; do
            [[ "$(< "$HOME/.$agent/config-origin.json")" == "{\"origin\":\"vm-edit\"}" ]]
            [[ "$(< "$HOME/.$agent/agent/config-origin.json")" == "{\"origin\":\"vm-edit\"}" ]]
            [[ ! -e "$HOME/.$agent/agent/deletable.txt" ]]
        done
        cmp -s "$HOME/.pi/agent/sandbox.json" "$PWD/edited-sandbox.json"
    ' || fail 'interactive login zsh failed or changed private config'
    pass 'fixture: clean interactive login zsh finds image tools and preserves VM edits'
else
    [[ ! -e "$HOME/.pi/config-origin.json" && ! -e "$HOME/.omp/config-origin.json" ]] || fail 'unmounted boot retained fixture config'
    print -r -- synthetic > "$HOME/.pi/agent/default-write-probe"
    print -r -- synthetic > "$HOME/.omp/agent/default-write-probe"
    pass 'default: boot without host config mounts provides writable native config'
    /usr/bin/python3 /verify/sqlite-fixtures.py stress \
        || fail 'configuration snapshot cannot finish consistently under ongoing host writes'
    pass 'default: configuration snapshot completes consistently while source writes continue'
fi

for agent in pi omp; do
    command -v "$agent" >/dev/null || fail "$agent command is missing"
    version="$(timeout 30 "$agent" --version 2>/dev/null)" || fail "$agent --version failed"
    case "$agent:$version" in
        pi:*0.85.1*|omp:*18.12.6*) ;;
        *) fail "$agent does not match the pinned verifier API version" ;;
    esac
done
pass "$mode: actual pi --version and omp --version succeed"
if [[ "$mode" == fixture || "$mode" == resume ]]; then
    /usr/bin/python3 /verify/sessions.py "$mode" || fail 'real-agent session persistence or resume failed'
    pass "$mode: real Pi and omp default/profile sessions use native buckets, artifacts and image blobs"
fi
print -r -- "$mode-complete" > "$workspace/completed"
GUEST

run_guest() {
    local mode="$1" workspace="$2" result=0 detail vm_pid attempt ready=0 path
    shift 2
    local args=(machine run --unprivileged --net-backend virtio-net
        --smolfile "$TMP/Smolfile" --no-init-cache --timeout 240s --mem 2048 --cpus 2
        --workdir "$workspace" --env "HOME=$HOST_HOME" --env "TMPDIR=$HOST_TMPDIR"
        --env "PI_VERIFY_HOME=$HOST_HOME" --env "PI_VERIFY_TMPDIR=$HOST_TMPDIR"
        --env "PI_VERIFY_WORKSPACE=$workspace" --env SANDBOX_PERSIST_SESSIONS=1)
    local state
    for state in .pi/agent/sessions .omp/agent/sessions .omp/agent/blobs \
        .omp/profiles/work/agent/sessions .omp/profiles/work/agent/blobs; do
        [[ "$mode" == default && "$state" == .omp/profiles/* ]] && continue
        args+=(-v "$HOST_HOME/$state:$HOST_HOME/$state")
    done
    local command=(/usr/local/bin/vm-seed.py zsh -l -c 'source /verify/checks.zsh "$1"' verify "$mode")
    if [[ "$mode" == host ]]; then
        # Same native namespace without seeding, snapshots or a shared index.
        # The image supplies pinned agents; no host tool installation is needed.
        command=(/usr/bin/setpriv --bounding-set=-all,+dac_override,+fowner
            --inh-caps=-all --ambient-caps=-all --no-new-privs
            /usr/bin/python3 /verify/sessions.py host)
    fi
    rm -f "$workspace/failure" "$workspace/completed" "$workspace/assertions" \
        "$workspace/live-ready" "$workspace/host-observed"
    (cd "$TMP" && smolvm "${args[@]}" \
        -v "$TMP/control:/verify:ro" -v "$workspace:$workspace" \
        "$@" --image "$IMAGE_TAR" -- "${command[@]}") \
        > "$TMP/$mode-boot.log" 2>&1 &
    vm_pid=$!
    ACTIVE_VM="$vm_pid"
    if [[ "$mode" == fixture ]]; then
        # Wait after real agent writes, before VM exit: teardown-only copies
        # cannot satisfy this host observation and guest acknowledgement.
        for ((attempt = 0; attempt < 180; attempt++)); do
            if [[ -f "$workspace/live-ready" ]]; then ready=1; break; fi
            kill -0 "$vm_pid" 2>/dev/null || break
            sleep 1
        done
        if [[ "$ready" == 1 ]]; then
            [[ -s "$workspace/live-paths" ]] || fail 'guest omitted live native state paths'
            while IFS= read -r path; do
                [[ "$path" == "$HOST_HOME/"* && -s "$path" ]] \
                    || fail 'live VM state is not readable at its native host path'
                case "$path" in
                    *.jsonl) grep -Eq 'fixture-pi-answer-fixture|fixture-answer-fixture-(omp|work)' "$path" \
                        || fail 'host cannot read real saved agent turn while VM is live' ;;
                    */blobs/*) [[ "$(shasum -a 256 "$path")" == "${path##*/} "* ]] \
                        || fail 'host image blob does not match its content address while VM is live' ;;
                    */local/fixture-artifact.txt) grep -Eq '^fixture-artifact-(omp|work)$' "$path" \
                        || fail 'host artifact is missing while VM is live' ;;
                    *) fail 'unexpected live fixture path' ;;
                esac
            done < "$workspace/live-paths"
            printf 'host observed live transcripts, artifacts and blobs\n' > "$workspace/host-observed"
            printf 'PASS: real-agent transcripts, artifacts and blobs are host-visible before VM exit\n'
        fi
    fi
    wait "$vm_pid" || result=$?
    ACTIVE_VM=""
    if [[ -f "$workspace/failure" ]]; then
        IFS= read -r detail < "$workspace/failure"
        case "$detail" in
            'FAIL: '*) fail "$mode: ${detail#FAIL: }" ;;
            *) fail "$mode: guest assertion failed" ;;
        esac
    fi
    [[ "$result" == 0 ]] || fail "$mode: smolvm boot or guest checks failed"
    [[ -f "$workspace/completed" ]] || fail "$mode: guest did not complete its assertions"
    [[ "$(< "$workspace/completed")" == "$mode-complete" ]] || fail "$mode: guest completion marker invalid"
    # Only our concise assertion records reach stdout, never VM logs/config.
    while IFS= read -r assertion; do
        case "$assertion" in
            'PASS: '*) printf '%s\n' "$assertion" ;;
            *) fail "$mode: unexpected guest assertion output" ;;
        esac
    done < "$workspace/assertions"
    [[ ! -e "$HOST_HOME/.omp/agent/history.db" \
        && ! -e "$HOST_HOME/.omp/profiles/work/agent/history.db" ]] \
        || fail 'VM history SQLite database leaked to host state'
}

run_guest fixture "$HOST_HOME/project" \
    -v "$TMP/fixtures/pi:/root/.pi-host:ro" \
    -v "$TMP/fixtures/omp:/root/.omp-host:ro"
run_guest resume "$HOST_HOME/project" \
    -v "$TMP/fixtures/pi:/root/.pi-host:ro" \
    -v "$TMP/fixtures/omp:/root/.omp-host:ro"
run_guest host "$HOST_HOME/project"
run_guest default "$TMP/default-workspace"
COPYFILE_DISABLE=1 tar -cf "$TMP/fixtures-after.tar" -C "$TMP/fixtures" pi omp
cmp -s "$TMP/fixtures-before.tar" "$TMP/fixtures-after.tar" \
    || fail 'synthetic host configuration changed'
printf 'PASS: synthetic host fixtures remain byte-for-byte unchanged\n'
