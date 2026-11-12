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
