import errno
import hashlib
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, "/usr/local/bin")
from network_policy import DNS_PORT, DNS_UID, POLICY_VERSION, read_policy

PROOF = Path("/run/sandbox-fixture-network.json")
FEEDS = Path("/run/sandbox-fixture-feeds")
PAYLOAD = b"sandbox-local-network-fixture\n"
PUBLIC_V6 = "2606:4700:2222::b"
DENIED_V4 = "203.0.114.10"
DENIED_V6 = "2606:4700:1111::b"


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def prepare():
    policy = read_policy(Path("/verify/network.json"))
    # --dns configures the host proxy; this server runs inside the guest.
    Path("/etc/resolv.conf").write_text("nameserver 100.64.0.10\n")
    FEEDS.mkdir(mode=0o755)
    data = {
        "domains.txt": b"aliyuncs.com\nmalware.sandbox.test\n",
        "ipv4.txt": b"203.0.114.0/24\n",
        "ipv6.txt": b"2606:4700:1111::/48\n",
    }
    manifest = {
        "version": POLICY_VERSION,
        "createdAt": int(time.time()),
        "policySha256": hashlib.sha256(canonical(policy)).hexdigest(),
        "files": {name: hashlib.sha256(content).hexdigest() for name, content in data.items()},
        "sources": [
            {"name": name, "url": "https://example.invalid/" + name,
             "sha256": hashlib.sha256(data[filename]).hexdigest(), "license": "CC0-1.0"}
            for name, filename in (
                ("synthetic-domains", "domains.txt"),
                ("synthetic-ipv4", "ipv4.txt"),
                ("synthetic-ipv6", "ipv6.txt"),
            )
        ],
    }
    manifest["snapshotId"] = hashlib.sha256(canonical(manifest)).hexdigest()
    for name, content in data.items():
        (FEEDS / name).write_bytes(content)
    (FEEDS / "manifest.json").write_bytes(canonical(manifest) + b"\n")


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
                raise AssertionError("allowed fixture TCP connection failed") from error
            return
        assert allowed, "forbidden fixture connection succeeded"
        assert client.recv(128) == PAYLOAD, "fixture listener payload mismatch"


def dns_question(name, kind):
    labels = name.rstrip(".").split(".")
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return struct.pack("!6H", 0x5342, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", kind, 1)


def receive_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        assert chunk, "DNS TCP response ended early"
        data.extend(chunk)
    return bytes(data)


def dns_query(name, kind=1, tcp=False, address="127.0.0.1", port=DNS_PORT):
    query = dns_question(name, kind)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        if tcp:
            client.connect((address, port))
            client.sendall(struct.pack("!H", len(query)) + query)
            answer = receive_exact(client, struct.unpack("!H", receive_exact(client, 2))[0])
        else:
            client.sendto(query, (address, port))
            answer, _ = client.recvfrom(4096)
    assert len(answer) >= 12 and answer[:2] == query[:2], "DNS response mismatch"
    return answer


def check_dns(upstream_available=False):
    for name, kind, tcp in (
        ("malware.sandbox.test", 1, False),
        ("child.malware.sandbox.test.", 28, True),
        ("SANMAOHE.OSS-CN-BEIJING.ALIYUNCS.COM.", 16, False),
        ("routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com", 1, True),
    ):
        answer = dns_query(name, kind, tcp)
        assert answer[3] & 15 == 3, "blocked domain did not return NXDOMAIN"
    for tcp in (False, True):
        answer = dns_query("malware.sandbox.test", tcp=tcp, address="1.1.1.1", port=53)
        assert answer[3] & 15 == 3, "alternate DNS server bypassed filtering"
    if upstream_available:
        for tcp in (False, True):
            answer = dns_query("allowed.sandbox.test", tcp=tcp)
            assert answer[3] & 15 == 0 and answer.endswith(socket.inet_aton("93.184.216.34")), (
                "allowed DNS query did not reach the synthetic upstream"
            )


def workload(joined=False):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    assert os.getuid() == int(os.environ["SANDBOX_UID"]) != 0
    assert os.getgid() == int(os.environ["SANDBOX_GID"])
    for name in ("CapEff", "CapPrm", "CapAmb", "CapInh"):
        assert int(status[name].strip(), 16) == 0, f"{name} is not zero"
    assert int(status["CapBnd"].strip(), 16) == 0, "workload bounding set is not empty"
    assert status["NoNewPrivs"].strip() == "1"
    editable = Path.cwd() / "editable-host-file"
    editable.write_text("guest workspace edit\n")
    editable.chmod(0o600)
    assert editable.read_text() == "guest workspace edit\n"
    denied = subprocess.run(["nft", "add", "table", "inet", "sandbox_bypass"], capture_output=True, text=True)
    assert denied.returncode != 0 and any(
        text in denied.stderr.lower() for text in ("not permitted", "permission denied")
    ), "workload could modify nftables or failure was not permission-related"
    for family, kind, protocol in (
        (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)),
        (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
        (socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6),
    ):
        try:
            raw = socket.socket(family, kind, protocol)
        except OSError as error:
            assert error.errno in (errno.EPERM, errno.EACCES)
        else:
            raw.close()
            raise AssertionError("workload created a raw socket")
    try:
        os.setuid(DNS_UID)
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError("workload assumed the resolver identity")
    for protected in ("/usr/bin/setpriv", "/usr/local/bin/vm-seed.py", "/usr/local/bin/vm-network.py"):
        try:
            descriptor = os.open(protected, os.O_WRONLY)
        except OSError as error:
            assert error.errno in (errno.EPERM, errno.EACCES, errno.EROFS)
        else:
            os.close(descriptor)
            raise AssertionError("workload can change trusted entry code")
    check_dns()
    proof = json.loads(PROOF.read_text())
    assert proof["allowedTCP443"] and proof["allowedPublicTCP443"] and proof["filteredDNS"]
    assert proof["deniedIPv4"] == ["100.64.0.10:22", "100.64.0.11:443", f"{DENIED_V4}:443"]
    assert all(delta >= 1 for delta in proof["rejectCounterDeltas"])
    print("PASS: network: pinned Spark and public IPv4 TCP443 succeed; forbidden tailnet and feed IPv4 destinations hit reject counters")
    if proof["ipv6Route"]:
        assert proof["allowedPublicIPv6"], "allowed IPv6 failed with an empty neighbor cache"
        print("PASS: network: public IPv6 succeeds with neighbor discovery; tailnet and feed IPv6 destinations hit reject counters")
    else:
        print("PASS: network: IPv6 disabled recorded; IPv4 enforcement proofs required")
    print("PASS: network: malware and Alibaba suffixes reject A/AAAA/TXT queries over UDP/TCP; alternate port53 resolvers are filtered")
    print("PASS: network: non-root workload edits host files but cannot modify rules, use raw sockets, assume DNS identity, or replace trusted entry code")


def trusted_init():
    namespace, host, peer = "pi-verify-peer", "pi-verify-host", "pi-verify-peer"
    server = None
    created_namespace = created_link = False
    try:
        command("ip", "netns", "add", namespace)
        created_namespace = True
        command("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
        created_link = True
        command("ip", "link", "set", peer, "netns", namespace)
        command("ip", "address", "add", "100.64.0.1/24", "dev", host)
        command("ip", "link", "set", host, "up")
        command("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
        command("ip", "netns", "exec", namespace, "ip", "address", "add", "100.64.0.10/24", "dev", peer)
        command("ip", "netns", "exec", namespace, "ip", "link", "set", peer, "up")
        command("ip", "netns", "exec", namespace, "ip", "address", "add", "1.1.1.1/32", "dev", "lo")
        command("ip", "route", "add", "1.1.1.1/32", "via", "100.64.0.10", "dev", host)
        command("ip", "route", "add", "203.0.114.0/24", "via", "100.64.0.10", "dev", host)
        ipv6 = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() == "0"
        if ipv6:
            command("ip", "-6", "address", "add", "2606:4700:2222::a/64", "dev", host, "nodad")
            command("ip", "netns", "exec", namespace, "ip", "-6", "address", "add", PUBLIC_V6 + "/64", "dev", peer, "nodad")
            command("ip", "-6", "route", "add", "2606:4700:1111::/48", "via", PUBLIC_V6, "dev", host)
            command("ip", "-6", "address", "add", "fd7a:115c:a1e0::a/64", "dev", host, "nodad")
            command("ip", "-6", "neigh", "flush", "dev", host)
        server = subprocess.Popen(
            ["ip", "netns", "exec", namespace, "/usr/bin/python3", __file__, "serve", str(int(ipv6))],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert server.stdout.readline() == "ready\n", "synthetic upstream did not start"
        drop = ["/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                "--clear-groups", "--reuid", os.environ["SANDBOX_UID"], "--regid", os.environ["SANDBOX_GID"],
                "--no-new-privs", "--", "/usr/bin/python3", __file__]
        for address in ("100.64.0.10", "1.1.1.1", *([PUBLIC_V6] if ipv6 else [])):
            subprocess.run([*drop, "probe", address, "443", "allow"], check=True)
        proof = {"allowedTCP443": True, "allowedPublicTCP443": True, "deniedIPv4": [],
                 "rejectCounterDeltas": [], "ipv6Route": ipv6, "allowedPublicIPv6": ipv6}
        denied = [("100.64.0.10", 22), ("100.64.0.11", 443), (DENIED_V4, 443)]
        if ipv6:
            denied += [("fd7a:115c:a1e0::b", 443), (DENIED_V6, 443)]
        for address, port in denied:
            before = reject_packets()
            subprocess.run([*drop, "probe", address, str(port), "deny"], check=True)
            delta = reject_packets() - before
            assert delta >= 1, "forbidden connection did not hit a kernel reject rule"
            proof["rejectCounterDeltas"].append(delta)
            if ":" not in address:
                proof["deniedIPv4"].append(f"{address}:{port}")
        subprocess.run([*drop, "dns"], check=True)
        proof["filteredDNS"] = True
        PROOF.write_text(json.dumps(proof))
    finally:
        if server is not None:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
            if server.returncode > 0:
                print(server.stderr.read()[-4000:], file=sys.stderr)
        if created_link:
            command("ip", "link", "delete", host)
        if created_namespace:
            command("ip", "netns", "delete", namespace)


def dns_reply(query):
    assert len(query) >= 17
    cursor = 12
    while query[cursor]:
        cursor += query[cursor] + 1
    end = cursor + 5
    assert end == len(query)
    kind = struct.unpack("!H", query[cursor + 1:cursor + 3])[0]
    answer = struct.pack("!6H", struct.unpack("!H", query[:2])[0], 0x8180, 1, int(kind == 1), 0, 0)
    answer += query[12:end]
    if kind == 1:
        answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("93.184.216.34")
    return answer


def serve(ipv6):
    with ExitStack() as resources:
        listeners = {}
        for address, port, udp in [("100.64.0.10", 53, True), ("100.64.0.10", 53, False),
                                   ("100.64.0.10", 443, False), ("1.1.1.1", 443, False),
                                   *([(PUBLIC_V6, 443, False)] if ipv6 else [])]:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            listener = resources.enter_context(socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port))
            if not udp:
                listener.listen(8)
            listeners[listener] = (port, udp)
        print("ready", flush=True)
        while True:
            readable, _, _ = select.select(list(listeners), [], [], 30)
            assert readable, "synthetic upstream timed out"
            for listener in readable:
                port, udp = listeners[listener]
                if udp:
                    query, peer = listener.recvfrom(4096)
                    listener.sendto(dns_reply(query), peer)
                else:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        if port == 443:
                            connection.sendall(PAYLOAD)
                        else:
                            query = receive_exact(connection, struct.unpack("!H", receive_exact(connection, 2))[0])
                            answer = dns_reply(query)
                            connection.sendall(struct.pack("!H", len(answer)) + answer)


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "prepare":
        prepare()
    elif operation == "init":
        try:
            trusted_init()
        except Exception:
            (Path.cwd() / "failure").write_text("FAIL: trusted synthetic network checks failed\n")
            raise
    elif operation == "serve":
        serve(sys.argv[2] == "1")
    elif operation == "probe":
        probe(sys.argv[2], int(sys.argv[3]), sys.argv[4] == "allow")
    elif operation == "dns":
        check_dns(upstream_available=True)
    elif operation == "workload":
        workload()
    elif operation == "joined":
        workload(joined=True)
    else:
        raise SystemExit("unsupported network fixture operation")
