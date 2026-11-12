#!/usr/bin/python3
"""Install the VM's pinned egress policy before starting unprivileged work."""

import ipaddress
import hashlib
import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from network_policy import DNS_PORT, DNS_UID, POLICY_VERSION, read_policy, read_snapshot

DEFAULT_CONFIG = Path("/opt/sandbox/network.json")
DEFAULT_FEEDS = Path("/opt/sandbox/feeds")
DNS_DIRECTORY = Path("/run/sandbox-dns")
DNS_CONFIG = DNS_DIRECTORY / "dnsmasq.conf"
DNS_PID = DNS_DIRECTORY / "dnsmasq.pid"
DNSMASQ = "/usr/sbin/dnsmasq"
SETPRIV = "/usr/bin/setpriv"
NFT = "/usr/sbin/nft"
MARKER = Path("/run/sandbox-network.json")
TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
# Deny special-purpose space before the final IPv4 Internet allowance. Keep
# multicast, reserved space and transition mechanisms out, not just RFC1918.
NONPUBLIC_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
NONPUBLIC_V6 = (
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
)

# Discovery has hop limit 255 and narrowly scoped destinations/types. Router
# advertisements and redirects are never emitted by this guest.
IPV6_DISCOVERY_RULES = (
    "add rule inet sandbox egress ip6 hoplimit 255 ip6 daddr ff02::2 "
    "icmpv6 type nd-router-solicit accept",
    "add rule inet sandbox egress ip6 hoplimit 255 "
    "ip6 daddr { ff02::1:ff00:0/104, fe80::/10, 2000::/3 } "
    "icmpv6 type nd-neighbor-solicit accept",
    "add rule inet sandbox egress ip6 hoplimit 255 "
    "ip6 daddr { ff02::1, fe80::/10, 2000::/3 } "
    "icmpv6 type nd-neighbor-advert accept",
)


def resolve_tailnet(host, port):
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            answers = socket.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}
        except (OSError, ValueError) as error:
            raise RuntimeError(f"resolving tailnet host {host} failed") from error
    if not addresses:
        raise RuntimeError(f"resolving tailnet host {host} returned no addresses")
    for address in addresses:
        network = TAILNET_V4 if address.version == 4 else TAILNET_V6
        if address not in network or getattr(address, "scope_id", None) is not None:
            raise RuntimeError(
                f"validating resolved addresses for {host} failed: outside Tailscale space"
            )
    return sorted(addresses, key=lambda address: (address.version, int(address)))


def resolver_addresses(host="network policy"):
    try:
        lines = Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines()
        addresses = set()
        for line in lines:
            fields = line.split("#", 1)[0].split(";", 1)[0].split()
            if not fields or fields[0] != "nameserver":
                continue
            if len(fields) != 2 or "%" in fields[1]:
                raise ValueError("invalid nameserver")
            address = ipaddress.ip_address(fields[1])
            if address.is_unspecified or address.is_multicast:
                raise ValueError("invalid nameserver")
            addresses.add(address)
        if not addresses:
            raise ValueError("no nameservers")
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(f"reading resolver addresses for {host} failed") from error
    return sorted(addresses, key=lambda address: (address.version, int(address)))


def nft_rules(addresses, dns_servers, port, denied_ipv4=(), denied_ipv6=()):
    # Only validated IP/network objects and an integer enter this transaction.
    rules = [
        "add table inet sandbox",
        "flush table inet sandbox",
        "add set inet sandbox denied_ipv4 { type ipv4_addr; flags interval; auto-merge; }",
        "add set inet sandbox denied_ipv6 { type ipv6_addr; flags interval; auto-merge; }",
    ]
    for name, networks in (
        ("denied_ipv4", denied_ipv4),
        ("denied_ipv6", denied_ipv6),
    ):
        if networks:
            rules.append(
                f"add element inet sandbox {name} {{ "
                + ", ".join(str(network) for network in networks)
                + " }"
            )
    rules.extend(
        (
            # Some nft versions reject the dstnat priority name on output.
            "add chain inet sandbox dns_redirect { type nat hook output priority -100; policy accept; }",
            f"add rule inet sandbox dns_redirect meta skuid != {DNS_UID} "
            f"meta l4proto {{ tcp, udp }} th dport 53 redirect to :{DNS_PORT}",
            "add chain inet sandbox egress { type filter hook output priority 0; policy drop; }",
        )
    )
    # The resolver has only its explicitly enumerated upstream DNS authority.
    for address in dns_servers:
        family = "ip" if address.version == 4 else "ip6"
        rules.append(
            f"add rule inet sandbox egress meta skuid {DNS_UID} {family} "
            f"daddr {address} meta l4proto {{ tcp, udp }} th dport 53 accept"
        )
    rules.extend(
        (
            f"add rule inet sandbox egress meta skuid {DNS_UID} "
            "meta l4proto { tcp, udp } th dport 53 counter reject",
            # NAT output rerouting may happen after the output filter hook.
            f"add rule inet sandbox egress ip daddr 127.0.0.1 "
            f"meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept",
            f"add rule inet sandbox egress ip6 daddr ::1 "
            f"meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept",
            f"add rule inet sandbox egress meta l4proto {{ tcp, udp }} "
            f"th dport {DNS_PORT} counter reject",
            'add rule inet sandbox egress oifname "lo" accept',
            f"add rule inet sandbox egress meta skuid {DNS_UID} counter reject",
            "add rule inet sandbox egress meta l4proto { tcp, udp } th dport 53 counter reject",
            *IPV6_DISCOVERY_RULES,
            "add rule inet sandbox egress ip daddr @denied_ipv4 counter reject",
            "add rule inet sandbox egress ip6 daddr @denied_ipv6 counter reject",
        )
    )
    for address in addresses:
        family = "ip" if address.version == 4 else "ip6"
        rules.append(
            f"add rule inet sandbox egress {family} daddr {address} tcp dport {port} accept"
        )
    for family, networks in (("ip", NONPUBLIC_V4), ("ip6", NONPUBLIC_V6)):
        rules.append(
            f"add rule inet sandbox egress {family} daddr {{ {', '.join(networks)} }} counter reject"
        )
    rules.extend(
        (
            "add rule inet sandbox egress meta nfproto ipv4 accept",
            "add rule inet sandbox egress ip6 daddr 2000::/3 accept",
            "add rule inet sandbox egress counter reject",
        )
    )
    return "\n".join(rules) + "\n"


def lockdown_rules(dns_servers=()):
    rules = [
        "add table inet sandbox",
        "flush table inet sandbox",
        "add chain inet sandbox egress { type filter hook output priority 0; policy drop; }",
        'add rule inet sandbox egress oifname "lo" accept',
    ]
    if dns_servers:
        rules.extend(IPV6_DISCOVERY_RULES)
    # Only the trusted root installer may resolve the pinned tailnet endpoint.
    for address in dns_servers:
        family = "ip" if address.version == 4 else "ip6"
        rules.append(
            f"add rule inet sandbox egress meta skuid 0 {family} daddr {address} "
            "meta l4proto { tcp, udp } th dport 53 accept"
        )
    return "\n".join(rules) + "\n"


def apply_nft(rules, stage):
    try:
        subprocess.run(
            [NFT, "-f", "-"],
            input=rules,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        # Keep nft's error headers, not the echoed rule/configuration lines.
        headers = [
            line.strip()[:400]
            for line in (error.stderr or "").splitlines()
            if "Error:" in line
        ][:3]
        detail = "; ".join(headers) or f"nft exited with status {error.returncode}"
        raise RuntimeError(f"installing nft {stage} transaction failed: {detail}") from error
    except OSError as error:
        raise RuntimeError(f"executing nft for {stage} failed: {error.strerror}") from error


def dnsmasq_config(domains, dns_servers):
    # All suffixes came through read_policy/read_snapshot syntax validation.
    lines = [
        f"port={DNS_PORT}",
        "listen-address=127.0.0.1,::1",
        "bind-interfaces",
        "no-resolv",
        "no-poll",
        "no-hosts",
        f"pid-file={DNS_PID}",
        "log-facility=/dev/null",
    ]
    lines.extend(f"server={address}" for address in dns_servers)
    # A local zone with no hosts answers NXDOMAIN for ALL query types, including
    # TXT/HTTPS; address=/suffix/0.0.0.0 would not enforce that property.
    lines.extend(f"local=/{domain}/" for domain in sorted(set(domains)))
    return "\n".join(lines) + "\n"


def stop_dns():
    try:
        pid_text = DNS_PID.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return
    except (OSError, UnicodeError) as error:
        raise RuntimeError("reading previous DNS daemon identity failed") from error
    if not pid_text.isdecimal() or int(pid_text) <= 1:
        raise RuntimeError("validating previous DNS daemon PID failed")
    pid = int(pid_text)
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        DNS_PID.unlink(missing_ok=True)
        return
    try:
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        except FileNotFoundError:
            return
        values = dict(
            line.split(":", 1) for line in status.splitlines() if ":" in line
        )
        if (
            values.get("Uid", "").split() != [str(DNS_UID)] * 4
            or values.get("Gid", "").split() != [str(DNS_UID)] * 4
            or executable != Path(DNSMASQ).resolve(strict=True)
            or os.fsencode(f"--conf-file={DNS_CONFIG}") not in command
        ):
            raise RuntimeError("refusing to signal an unrelated DNS daemon PID")
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        if not select.select([descriptor], [], [], 5)[0]:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            if not select.select([descriptor], [], [], 5)[0]:
                raise RuntimeError("stopping previous DNS daemon timed out")
    except ProcessLookupError:
        pass
    except (OSError, UnicodeError) as error:
        raise RuntimeError("stopping previous DNS daemon failed") from error
    finally:
        os.close(descriptor)
    DNS_PID.unlink(missing_ok=True)


def start_dns(domains, dns_servers):
    try:
        DNS_DIRECTORY.mkdir(mode=0o700, exist_ok=True)
        directory = DNS_DIRECTORY.lstat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in (0, DNS_UID):
            raise RuntimeError("validating DNS runtime directory failed")
        os.chown(DNS_DIRECTORY, DNS_UID, DNS_UID)
        os.chmod(DNS_DIRECTORY, 0o700)
        # Replacing instead of following an existing config symlink.
        descriptor, temporary = tempfile.mkstemp(prefix=".config-", dir=DNS_DIRECTORY)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(dnsmasq_config(domains, dns_servers))
                os.fchown(stream.fileno(), DNS_UID, DNS_UID)
                os.fchmod(stream.fileno(), 0o400)
            os.replace(temporary, DNS_CONFIG)
        finally:
            Path(temporary).unlink(missing_ok=True)
        # In normal daemon mode dnsmasq's parent waits on its startup pipe:
        # status zero means configuration and socket binding succeeded.
        subprocess.run(
            [
                SETPRIV,
                f"--reuid={DNS_UID}",
                f"--regid={DNS_UID}",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
                "--",
                DNSMASQ,
                f"--conf-file={DNS_CONFIG}",
            ],
            capture_output=True,
            check=True,
            timeout=20,
        )
        if not DNS_PID.is_file():
            raise RuntimeError("DNS daemon initialized without a PID file")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise RuntimeError("starting isolated DNS daemon failed") from error


def install(config_path, feeds_path=DEFAULT_FEEDS):
    if os.geteuid() != 0:
        raise RuntimeError("installing network policy requires root")
    temporary = None
    try:
        # A previous success cannot authorize work after any failed reinstall.
        MARKER.unlink(missing_ok=True)
        dns_servers = resolver_addresses()
        try:
            config = read_policy(config_path)
        except (OSError, UnicodeError, ValueError) as error:
            raise RuntimeError("validating network policy configuration failed") from error
        try:
            snapshot = read_snapshot(feeds_path, config["feedMaxAgeHours"])
        except (OSError, UnicodeError, ValueError) as error:
            raise RuntimeError("validating feed snapshot integrity and freshness failed") from error
        policy_hash = hashlib.sha256(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if snapshot["manifest"]["policySha256"] != policy_hash:
            raise RuntimeError("feed snapshot does not match network policy")
        host, port = config["tailnetHost"], config["httpsPort"]
        apply_nft(lockdown_rules(dns_servers), "bootstrap")
        stop_dns()
        addresses = resolve_tailnet(host, port)
        start_dns(
            config["blockedDomainSuffixes"] + snapshot["domains"], dns_servers
        )
        apply_nft(
            nft_rules(
                addresses,
                dns_servers,
                port,
                snapshot["ipv4"],
                snapshot["ipv6"],
            ),
            "egress",
        )
        marker = {
            "tailnetHost": host,
            "httpsPort": port,
            "allowedIPv4": [str(address) for address in addresses if address.version == 4],
            "allowedIPv6": [str(address) for address in addresses if address.version == 6],
            "dnsServers": [str(address) for address in dns_servers],
            "policyVersion": POLICY_VERSION,
            "snapshotId": snapshot["manifest"]["snapshotId"],
            "dnsUid": DNS_UID,
            "dnsPort": DNS_PORT,
        }
        descriptor, temporary = tempfile.mkstemp(
            prefix=".sandbox-network-", dir=MARKER.parent
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(marker, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, MARKER)
    except Exception as error:
        # Withdraw all upstream/workload authority on every setup failure.
        try:
            MARKER.unlink(missing_ok=True)
            apply_nft(lockdown_rules(), "failure lockdown")
            stop_dns()
        except (OSError, RuntimeError) as cleanup_error:
            raise RuntimeError(
                f"{error}; withdrawing previous network authority also failed: {cleanup_error}"
            ) from cleanup_error
        if isinstance(error, RuntimeError):
            raise
        raise RuntimeError("installing guest network policy failed") from error
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main():
    if len(sys.argv) > 3:
        print("usage: vm-network.py [network.json [feeds-directory]]", file=sys.stderr)
        return 1
    try:
        install(
            Path(sys.argv[1]) if len(sys.argv) >= 2 else DEFAULT_CONFIG,
            Path(sys.argv[2]) if len(sys.argv) == 3 else DEFAULT_FEEDS,
        )
    except RuntimeError as error:
        print(f"network-policy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
