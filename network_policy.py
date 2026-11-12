#!/usr/bin/env python3
"""Shared, dependency-free validation for host and guest network snapshots."""

import hashlib
import ipaddress
import json
import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

POLICY_VERSION = "baseline-v1"
DNS_UID = 65532
DNS_PORT = 5353
DEFAULT_SUFFIXES = (
    "alibaba.com", "alibabacloud.com", "alicloud.com", "aliyun.com",
    "aliyuncs.com", "aliyuncs.io", "alicdn.com", "npmmirror.com",
)
DEFAULT_ASNS = (45102, 37963)
MAX_DOMAINS = 1_000_000
MAX_PREFIXES = 250_000  # Per address family, before and after merging.
MAX_ASNS = 64
MAX_SUFFIXES = 4096
MAX_DOMAIN_BYTES = 64 * 1024 * 1024
MAX_PREFIX_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
DATA_FILES = ("domains.txt", "ipv4.txt", "ipv6.txt")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NONPUBLIC_V4 = tuple(map(ipaddress.ip_network, (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
)))
GLOBAL_V6 = ipaddress.ip_network("2000::/3")
NONPUBLIC_V6 = tuple(map(ipaddress.ip_network, (
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
)))


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def policy_sha256(policy):
    return sha256(canonical_json(policy))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def parse_json(data):
    try:
        return json.loads(data, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise RuntimeError(f"invalid JSON: {error}") from error


def read_regular_file(path, maximum, *, dir_fd=None):
    """Read bounded regular files without following a replaced final symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise RuntimeError(f"not a bounded regular file: {path}")
            data = source.read(maximum + 1)
        if len(data) > maximum:
            raise RuntimeError(f"file exceeds size limit: {path}")
        return data
    except OSError as error:
        raise RuntimeError(f"reading {path} failed: {error}") from error


def domain_name(value):
    """Validate an ASCII DNS suffix; return its lower-case canonical spelling."""
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or not value.isascii():
        raise RuntimeError(f"invalid domain: {value!r}")
    domain = value.lower()
    labels = domain.split(".")
    if (
        len(labels) < 2
        or not all(LABEL_RE.fullmatch(label) for label in labels)
        or not any(character.isalpha() for character in labels[-1])
    ):
        raise RuntimeError(f"invalid domain: {value!r}")
    return domain


def public_network(value, version):
    """Reject host bits, non-CIDRs, /0 and any special-purpose overlap."""
    if (
        not isinstance(value, str) or len(value) > 49 or value.count("/") != 1
        or "%" in value or not value.rsplit("/", 1)[1].isascii()
        or not value.rsplit("/", 1)[1].isdigit()
    ):
        raise RuntimeError(f"invalid IPv{version} CIDR: {value!r}")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise RuntimeError(f"invalid IPv{version} CIDR: {value!r}") from error
    if (
        network.version != version or network.prefixlen == 0
        or not network.network_address.is_global
        or not network.broadcast_address.is_global
    ):
        raise RuntimeError(f"nonpublic IPv{version} CIDR: {value!r}")
    excluded = NONPUBLIC_V4 if version == 4 else NONPUBLIC_V6
    if (version == 6 and not network.subnet_of(GLOBAL_V6)) or any(
        network.overlaps(other) for other in excluded
    ):
        raise RuntimeError(f"special-purpose IPv{version} CIDR: {value!r}")
    return network


def read_policy(path):
    """Return validated policy fields, including normalized optional defaults."""
    config = parse_json(read_regular_file(Path(path), 64 * 1024))
    if not isinstance(config, dict):
        raise RuntimeError("network configuration must be an object")
    known = {"tailnetHost", "httpsPort", "blockedDomainSuffixes", "blockedASNs", "feedMaxAgeHours"}
    if config.keys() - known:
        raise RuntimeError("unknown network configuration fields")
    host = config.get("tailnetHost")
    if not isinstance(host, str) or not host or len(host) > 253 or "%" in host:
        raise RuntimeError("invalid tailnetHost")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.removesuffix(".").lower()
        if not host.isascii() or not all(LABEL_RE.fullmatch(label) for label in host.split(".")):
            raise RuntimeError("invalid tailnetHost") from None
    port = config.get("httpsPort")
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError("httpsPort must be an integer from 1 to 65535")
    suffixes = config.get("blockedDomainSuffixes", list(DEFAULT_SUFFIXES))
    if not isinstance(suffixes, list) or len(suffixes) > MAX_SUFFIXES:
        raise RuntimeError(f"blockedDomainSuffixes must be a list of at most {MAX_SUFFIXES} domains")
    suffixes = sorted({domain_name(value) for value in suffixes})
    asns = config.get("blockedASNs", list(DEFAULT_ASNS))
    if not isinstance(asns, list) or len(asns) > MAX_ASNS or any(
        type(number) is not int or not 1 <= number <= 4294967295 for number in asns
    ):
        raise RuntimeError(f"blockedASNs must contain at most {MAX_ASNS} valid integer ASNs")
    max_age = config.get("feedMaxAgeHours", 168)
    if type(max_age) is not int or max_age <= 0:
        raise RuntimeError("feedMaxAgeHours must be a positive integer")
    return {
        "tailnetHost": host, "httpsPort": port,
        "blockedDomainSuffixes": suffixes, "blockedASNs": sorted(set(asns)),
        "feedMaxAgeHours": max_age,
    }


def https_url(value):
    if (
        not isinstance(value, str) or len(value) > 2048 or not value.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise RuntimeError("invalid source URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment or port == 0
        ):
            raise ValueError("HTTPS URL required")
    except ValueError as error:
        raise RuntimeError("source URL must use HTTPS without credentials or fragments") from error
    return value


def _digest(value):
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _snapshot_lines(data, maximum, name):
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeError as error:
        raise RuntimeError(f"non-ASCII snapshot data: {name}") from error
    if not lines or len(lines) > maximum or any(not line or line != line.strip() for line in lines):
        raise RuntimeError(f"empty, oversized or malformed snapshot data: {name}")
    return lines


def read_snapshot(directory, max_age_hours):
    """Verify a snapshot and return domains, IPv4/IPv6 networks and its manifest.

    The caller must also compare manifest.policySha256 with policy_sha256(policy).
    The mounted directory need not retain its content-addressed host basename.
    """
    if type(max_age_hours) is not int or max_age_hours <= 0:
        raise RuntimeError("snapshot maximum age must be a positive integer")
    try:
        fd = os.open(Path(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise RuntimeError(f"opening snapshot directory failed: {error}") from error
    try:
        manifest = parse_json(read_regular_file("manifest.json", MAX_MANIFEST_BYTES, dir_fd=fd))
        if not isinstance(manifest, dict) or manifest.get("version") != POLICY_VERSION:
            raise RuntimeError("unsupported snapshot policy version")
        snapshot_id = manifest.get("snapshotId")
        unsigned = {key: value for key, value in manifest.items() if key != "snapshotId"}
        if not _digest(snapshot_id) or sha256(canonical_json(unsigned)) != snapshot_id:
            raise RuntimeError("snapshot manifest identity mismatch")
        created = manifest.get("createdAt")
        now = time.time()
        if type(created) is not int or created <= 0 or created > now + 300 or now - created > max_age_hours * 3600:
            raise RuntimeError("snapshot is expired or has an invalid creation time")
        if not _digest(manifest.get("policySha256")):
            raise RuntimeError("invalid snapshot policy digest")
        files = manifest.get("files")
        if not isinstance(files, dict) or set(files) != set(DATA_FILES) or not all(_digest(value) for value in files.values()):
            raise RuntimeError("invalid snapshot file digests")
        sources = manifest.get("sources")
        if not isinstance(sources, list) or not 3 <= len(sources) <= MAX_ASNS + 3:
            raise RuntimeError("invalid snapshot source list")
        for source in sources:
            if not isinstance(source, dict) or set(source) != {"name", "url", "sha256", "license"}:
                raise RuntimeError("invalid snapshot source metadata")
            for field in ("name", "license"):
                if not isinstance(source[field], str) or not 1 <= len(source[field]) <= 256:
                    raise RuntimeError("invalid snapshot source identifier")
            https_url(source["url"])
            if not _digest(source["sha256"]):
                raise RuntimeError("invalid snapshot source digest")
        result = {"manifest": manifest}
        for filename, maximum, count, key, version in (
            ("domains.txt", MAX_DOMAIN_BYTES, MAX_DOMAINS, "domains", None),
            ("ipv4.txt", MAX_PREFIX_BYTES, MAX_PREFIXES, "ipv4", 4),
            ("ipv6.txt", MAX_PREFIX_BYTES, MAX_PREFIXES, "ipv6", 6),
        ):
            data = read_regular_file(filename, maximum, dir_fd=fd)
            if sha256(data) != files[filename]:
                raise RuntimeError(f"snapshot file digest mismatch: {filename}")
            lines = _snapshot_lines(data, count, filename)
            values = [domain_name(line) if version is None else public_network(line, version) for line in lines]
            if len(set(values)) != len(values) or any(str(value) != line for value, line in zip(values, lines)):
                raise RuntimeError(f"noncanonical or duplicate snapshot entries: {filename}")
            result[key] = values
        return result
    finally:
        os.close(fd)
