#!/usr/bin/env python3
"""Select or refresh immutable, validated network-denylist snapshots on the host."""

import argparse
import fcntl
import http.client
import ipaddress
import os
import shutil
import ssl
import stat
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from network_policy import (
    MAX_DOMAIN_BYTES, MAX_DOMAINS, MAX_MANIFEST_BYTES,
    MAX_PREFIX_BYTES, MAX_PREFIXES, POLICY_VERSION, SHA256_RE,
    canonical_json, domain_name, https_url, parse_json, policy_sha256,
    public_network, read_policy, read_regular_file, read_snapshot, sha256,
)

DOMAIN_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt"
DROP_URLS = {
    4: "https://www.spamhaus.org/drop/drop_v4.json",
    6: "https://www.spamhaus.org/drop/drop_v6.json",
}
ASN_URL = "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/{asn}/aggregated.json"
REFRESH_SECONDS = 24 * 3600
SOCKET_TIMEOUT = 30
DOWNLOAD_SECONDS = 120
REFRESH_DEADLINE_SECONDS = 600
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
USER_AGENT = "pi-sandbox-network-feeds/1 (baseline-v1; host denylist snapshot refresh)"
MACOS_CA_BUNDLE = Path("/etc/ssl/cert.pem")
# Spamhaus DROP has custom terms, not an SPDX license:
# https://www.spamhaus.org/drop/terms/
DROP_LICENSE = "LicenseRef-Spamhaus-DROP-Terms"


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        https_url(new_url)
        return super().redirect_request(request, response, code, message, headers, new_url)


def tls_context():
    # Framework Python may lack its own CA bundle even when macOS has one.
    # Explicit OpenSSL trust-store settings take precedence over the OS bundle.
    if (
        sys.platform == "darwin"
        and "SSL_CERT_FILE" not in os.environ
        and "SSL_CERT_DIR" not in os.environ
        and MACOS_CA_BUNDLE.is_file()
    ):
        return ssl.create_default_context(cafile=str(MACOS_CA_BUNDLE))
    return ssl.create_default_context()


def download(opener, url, maximum, deadline):
    https_url(url)
    deadline = min(deadline, time.monotonic() + DOWNLOAD_SECONDS)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("feed refresh deadline exceeded")
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept-Encoding": "identity",
    })
    with opener.open(request, timeout=min(SOCKET_TIMEOUT, remaining)) as response:
        https_url(response.geturl())
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP status for {url}: {response.status}")
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise RuntimeError(f"unexpected content encoding for {url}")
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                length = int(length)
            except ValueError as error:
                raise RuntimeError(f"invalid Content-Length for {url}") from error
            if length <= 0 or length > maximum:
                raise RuntimeError(f"response size exceeds limit for {url}")
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"download deadline exceeded for {url}")
            # read1 returns available bytes instead of waiting to fill an entire
            # chunk. A continuously trickling peer cannot bypass the deadline.
            chunk = response.read1(min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                raise RuntimeError(f"response size exceeds limit for {url}")
        if not data or (length is not None and len(data) != length):
            raise RuntimeError(f"empty or incomplete response for {url}")
        return bytes(data)


def parse_domains(data):
    try:
        text = data.decode("ascii")
    except UnicodeError as error:
        raise RuntimeError("domain feed is not ASCII") from error
    domains = []
    # Comments and empty lines are part of HaGeZi's documented plain format.
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        domains.append(domain_name(line))
        if len(domains) > MAX_DOMAINS:
            raise RuntimeError("domain feed exceeds entry limit")
    if not domains:
        raise RuntimeError("domain feed has no usable domains")
    return domains


def parse_drop(data, version):
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise RuntimeError("DROP feed is not UTF-8") from error
    if not 2 <= len(lines) <= MAX_PREFIXES + 1:
        raise RuntimeError("DROP feed is empty or exceeds entry limit")
    metadata = parse_json(lines[-1])
    if (
        not isinstance(metadata, dict) or metadata.get("type") != "metadata"
        or type(metadata.get("records")) is not int
        or metadata["records"] != len(lines) - 1
        or type(metadata.get("timestamp")) is not int
        or not 0 < metadata["timestamp"] <= time.time() + 300
        or type(metadata.get("size")) is not int or metadata["size"] <= 0
        or not isinstance(metadata.get("copyright"), str) or not metadata["copyright"]
        or metadata.get("terms") != "https://www.spamhaus.org/drop/terms/"
    ):
        raise RuntimeError("invalid final DROP metadata record")
    networks = []
    for line in lines[:-1]:
        record = parse_json(line)
        if (
            not isinstance(record, dict) or set(record) != {"cidr", "sblid", "rir"}
            or not isinstance(record["sblid"], str) or not record["sblid"].startswith("SBL")
            or not record["sblid"][3:].isdigit()
            or record["rir"] not in ("afrinic", "apnic", "arin", "lacnic", "ripencc")
        ):
            raise RuntimeError("invalid DROP data record")
        networks.append(public_network(record["cidr"], version))
    return networks


def parse_asn(data, asn):
    document = parse_json(data)
    if (
        not isinstance(document, dict) or type(document.get("asn")) is not int
        or document["asn"] != asn or not isinstance(document.get("metadata"), dict)
        or not document["metadata"] or not isinstance(document.get("prefixes"), dict)
        or set(document["prefixes"]) != {"ipv4", "ipv6"}
    ):
        raise RuntimeError(f"invalid or mismatched ASN metadata for AS{asn}")
    result = {}
    for version in (4, 6):
        prefixes = document["prefixes"][f"ipv{version}"]
        if not isinstance(prefixes, list) or len(prefixes) > MAX_PREFIXES:
            raise RuntimeError(f"invalid or oversized prefix list for AS{asn}")
        result[version] = [public_network(prefix, version) for prefix in prefixes]
    if not result[4] and not result[6]:
        raise RuntimeError(f"AS{asn} has no usable prefixes")
    return result


def collapse_domains(domains):
    domains = set(domains)
    if len(domains) > MAX_DOMAINS:
        raise RuntimeError("merged domains exceed entry limit")
    # A suffix already covers every descendant; keep only minimal suffixes.
    result = []
    for domain in sorted(domains):
        labels = domain.split(".")
        if not any(".".join(labels[index:]) in domains for index in range(1, len(labels) - 1)):
            result.append(domain)
    return result


def build_snapshot(policy):
    opener = urllib.request.build_opener(
        HTTPSRedirects(), urllib.request.HTTPSHandler(context=tls_context())
    )
    deadline = time.monotonic() + REFRESH_DEADLINE_SECONDS
    downloaded = 0
    sources = []

    def fetch(name, url, license_id, maximum):
        nonlocal downloaded
        maximum = min(maximum, MAX_DOWNLOAD_BYTES - downloaded)
        if maximum <= 0:
            raise RuntimeError("combined feed downloads exceed size limit")
        data = download(opener, url, maximum, deadline)
        downloaded += len(data)
        sources.append({"name": name, "url": url, "sha256": sha256(data), "license": license_id})
        return data

    domains = parse_domains(fetch("hagezi-tif-medium", DOMAIN_URL, "GPL-3.0", MAX_DOMAIN_BYTES))
    domains.extend(policy["blockedDomainSuffixes"])
    networks = {}
    for version in (4, 6):
        networks[version] = parse_drop(fetch(
            f"spamhaus-drop-v{version}", DROP_URLS[version], DROP_LICENSE, MAX_PREFIX_BYTES,
        ), version)
    for asn in policy["blockedASNs"]:
        parsed = parse_asn(fetch(
            f"ipverse-as{asn}", ASN_URL.format(asn=asn), "CC0-1.0", 8 * 1024 * 1024,
        ), asn)
        for version in (4, 6):
            networks[version].extend(parsed[version])
            if len(networks[version]) > MAX_PREFIXES:
                raise RuntimeError("combined prefixes exceed entry limit")
    domains = collapse_domains(domains)
    files = {"domains.txt": ("\n".join(domains) + "\n").encode("ascii")}
    for version in (4, 6):
        collapsed = ipaddress.collapse_addresses(networks[version])
        files[f"ipv{version}.txt"] = ("\n".join(str(network) for network in collapsed) + "\n").encode("ascii")
    for filename, data in files.items():
        maximum = MAX_DOMAIN_BYTES if filename == "domains.txt" else MAX_PREFIX_BYTES
        if len(data) > maximum:
            raise RuntimeError(f"merged {filename} exceeds size limit")
    manifest = {
        "version": POLICY_VERSION, "createdAt": int(time.time()),
        "policySha256": policy_sha256(policy),
        "files": {filename: sha256(data) for filename, data in files.items()},
        "sources": sources,
    }
    manifest["snapshotId"] = sha256(canonical_json(manifest))
    files["manifest.json"] = canonical_json(manifest) + b"\n"
    if len(files["manifest.json"]) > MAX_MANIFEST_BYTES:
        raise RuntimeError("manifest exceeds size limit")
    return files, manifest


def private_cache(path):
    path = path.expanduser().absolute()
    # Check path components before creating anything; do not permit a cache or
    # snapshot selection to be redirected through an existing symlink.
    for directory in (*reversed(path.parents), path):
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            directory.mkdir(mode=0o700)
            metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"cache path component is not a real directory: {directory}")
    if metadata.st_uid != os.getuid():
        raise RuntimeError("feed cache must be owned by the current user")
    os.chmod(path, 0o700)
    return path


def current_snapshot(cache, policy):
    pointer = cache / "current"
    if not pointer.exists() and not pointer.is_symlink():
        return None
    identifier = read_regular_file(pointer, 65).decode("ascii").removesuffix("\n")
    if not SHA256_RE.fullmatch(identifier):
        raise RuntimeError("invalid current snapshot pointer")
    directory = cache / identifier
    snapshot = read_snapshot(directory, policy["feedMaxAgeHours"])
    manifest = snapshot["manifest"]
    if manifest["snapshotId"] != identifier or manifest["policySha256"] != policy_sha256(policy):
        raise RuntimeError("cached snapshot does not match the configured policy")
    return directory, manifest


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_file(path, data):
    with path.open("xb") as destination:
        os.chmod(path, 0o600)
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(path, 0o400)


def publish_snapshot(cache, policy, files, manifest):
    stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=cache))
    try:
        for filename, data in files.items():
            write_file(stage / filename, data)
        # Validate exactly what guest code will consume before exposing a name.
        snapshot = read_snapshot(stage, policy["feedMaxAgeHours"])
        if snapshot["manifest"]["policySha256"] != policy_sha256(policy):
            raise RuntimeError("staged snapshot policy identity mismatch")
        sync_directory(stage)
        directory = cache / manifest["snapshotId"]
        if directory.exists() or directory.is_symlink():
            existing = read_snapshot(directory, policy["feedMaxAgeHours"])
            if existing["manifest"] != manifest:
                raise RuntimeError("existing immutable snapshot identity mismatch")
        else:
            stage.rename(directory)
            sync_directory(cache)
        fd, temporary = tempfile.mkstemp(prefix=".current-", dir=cache)
        try:
            with os.fdopen(fd, "wb") as pointer:
                pointer.write((manifest["snapshotId"] + "\n").encode("ascii"))
                pointer.flush()
                os.fsync(pointer.fileno())
            os.replace(temporary, cache / "current")
            sync_directory(cache)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return directory
    finally:
        # Remove only this invocation's unpublished stage, never old snapshots.
        if stage.exists():
            shutil.rmtree(stage)


def select_snapshot(cache, policy, refresh):
    cache = private_cache(cache)
    fd = os.open(cache / ".refresh.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        metadata = os.fstat(lock.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise RuntimeError("feed cache lock must be an owned regular file")
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            current = current_snapshot(cache, policy)
        except (RuntimeError, UnicodeError) as error:
            print(f"network-feeds: ignoring unusable current snapshot: {error}", file=sys.stderr)
            current = None
        if current is not None and not refresh and time.time() - current[1]["createdAt"] < REFRESH_SECONDS:
            return current[0]
        try:
            files, manifest = build_snapshot(policy)
            return publish_snapshot(cache, policy, files, manifest)
        except (OSError, RuntimeError, ValueError, http.client.HTTPException) as error:
            if current is None:
                raise RuntimeError(f"refresh failed and no valid cached snapshot is available: {error}") from error
            # A long failed download must not extend the permitted cache age.
            current = current_snapshot(cache, policy)
            print(f"network-feeds: refresh failed; using verified cached snapshot: {error}", file=sys.stderr)
            return current[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--refresh", action="store_true", help="attempt a refresh even before the 24-hour interval")
    args = parser.parse_args()
    try:
        policy = read_policy(args.config)
        directory = select_snapshot(args.cache_dir, policy, args.refresh)
        print(directory.resolve(strict=True))
    except (OSError, RuntimeError, ValueError, UnicodeError) as error:
        print(f"network-feeds: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
