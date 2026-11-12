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
