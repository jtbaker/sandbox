#!/usr/bin/python3
"""Install the VM's pinned egress policy before starting unprivileged work."""

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_CONFIG = Path("/opt/sandbox/network.json")
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


def load_config(path):
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError("reading network configuration failed") from error
    if not isinstance(config, dict):
        raise RuntimeError("validating network configuration failed: expected object")
    host = config.get("tailnetHost")
    port = config.get("httpsPort")
    if not isinstance(host, str) or not host or len(host) > 253:
        raise RuntimeError("validating tailnetHost failed")
    # Scoped IPv6 literals are not permitted: nft receives plain IP literals.
    if "%" in host:
        raise RuntimeError("validating tailnetHost failed")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.removesuffix(".").split(".")
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise RuntimeError("validating tailnetHost failed") from None
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError(f"validating TCP port for {host} failed")
    return host, port


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


def resolver_addresses(host):
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


def nft_rules(addresses, dns_servers, port):
    # Only fixed syntax, parsed IP literals and a validated integer enter nft.
    # Flushing our table and adding the entire policy is one nft transaction;
    # no other table is touched, and no intermediate open policy is visible.
    rules = [
        "add table inet sandbox",
        "flush table inet sandbox",
        "add chain inet sandbox egress { type filter hook output priority 0; policy drop; }",
        'add rule inet sandbox egress oifname "lo" accept',
    ]
    for address in dns_servers:
        family = "ip" if address.version == 4 else "ip6"
        for protocol in ("udp", "tcp"):
            rules.append(
                f"add rule inet sandbox egress {family} daddr {address} {protocol} dport 53 accept"
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


def install(config_path):
    if os.geteuid() != 0:
        raise RuntimeError("installing network policy requires root")
    # A previous success must never authorize a workload after a failed init.
    try:
        MARKER.unlink(missing_ok=True)
    except OSError as error:
        raise RuntimeError("removing previous network policy marker failed") from error
    host, port = load_config(config_path)
    addresses = resolve_tailnet(host, port)
    dns_servers = resolver_addresses(host)
    try:
        subprocess.run(
            ["nft", "-f", "-"],
            input=nft_rules(addresses, dns_servers, port),
            text=True,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        # Do not echo nft input or configuration data in diagnostics.
        raise RuntimeError(f"installing nft egress policy for {host} failed") from error
    marker = {
        "tailnetHost": host,
        "httpsPort": port,
        "allowedIPv4": [str(address) for address in addresses if address.version == 4],
        "allowedIPv6": [str(address) for address in addresses if address.version == 6],
        "dnsServers": [str(address) for address in dns_servers],
    }
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".sandbox-network-", dir=MARKER.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(marker, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, MARKER)
    except OSError as error:
        raise RuntimeError(
            f"writing network policy marker for {host} failed"
        ) from error
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main():
    if len(sys.argv) > 2:
        print("usage: vm-network.py [network.json]", file=sys.stderr)
        return 1
    try:
        install(Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_CONFIG)
    except RuntimeError as error:
        print(f"network-policy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
