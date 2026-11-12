import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import network_policy as policy

spec = importlib.util.spec_from_file_location("network_feeds", ROOT / "network-feeds.py")
feeds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feeds)


class NetworkPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="network-policy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        config = self.root / "policy.json"
        config.write_text(json.dumps({
            "tailnetHost": "100.64.0.10", "httpsPort": 443,
            "blockedDomainSuffixes": ["blocked.example"], "blockedASNs": [],
            "feedMaxAgeHours": 48,
        }))
        self.config = policy.read_policy(config)
        self.cache = self.root / "cache"

    def drop_data(self, version):
        prefix = "11.1.0.0/16" if version == 4 else "2606:4700:1111::/48"
        records = [
            {"cidr": prefix, "sblid": "SBL123", "rir": "arin"},
            {"type": "metadata", "records": 1, "timestamp": int(policy.time.time()),
             "size": 100, "copyright": "synthetic fixture",
             "terms": "https://www.spamhaus.org/drop/terms/"},
        ]
        return b"\n".join(json.dumps(record).encode() for record in records) + b"\n"

    def download(self, opener, url, maximum, deadline):
        if url == feeds.DOMAIN_URL:
            return b"# synthetic threat domains\nmalware.example\nchild.malware.example\n"
        for version, source in feeds.DROP_URLS.items():
            if url == source:
                return self.drop_data(version)
        raise AssertionError("unexpected network source")

    def publish(self):
        with patch.object(feeds, "download", side_effect=self.download):
            return feeds.select_snapshot(self.cache, self.config, False)

    def test_nonpublic_and_malformed_prefixes_cannot_enter_firewall_sets(self):
        for value, version in (
            ("0.0.0.0/0", 4), ("11.1.0.1/16", 4), ("10.0.0.0/8", 4),
            ("100.64.0.0/10", 4), ("11.0.0.0/7", 4),
            ("::/0", 6), ("fd00::/8", 6), ("2001:db8::/32", 6),
            ("11.1.0.0/16; flush ruleset", 4),
        ):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                policy.public_network(value, version)

    def test_domain_feed_rejects_config_injection_and_broad_tld_rules(self):
        for data in (b"com\n", b"malware.example\nserver=8.8.8.8\n", b"*.example\n", b"bad.example/\n"):
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                feeds.parse_domains(data)

    def test_truncated_drop_feed_is_rejected(self):
        lines = self.drop_data(4).splitlines()
        for data in (lines[0], lines[1], b"\n".join([lines[0], lines[0], lines[1]])):
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                feeds.parse_drop(data, 4)

    def test_snapshot_detects_data_tampering(self):
        snapshot = self.publish()
        (snapshot / "domains.txt").chmod(0o600)
        (snapshot / "domains.txt").write_text("safe.example\n")
        with self.assertRaises(RuntimeError):
            policy.read_snapshot(snapshot, self.config["feedMaxAgeHours"])

    def test_snapshot_rejects_symlinked_data(self):
        snapshot = self.publish()
        target = snapshot / "domains.txt"
        outside = self.root / "domains.txt"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(RuntimeError):
            policy.read_snapshot(snapshot, self.config["feedMaxAgeHours"])

    def test_failed_refresh_preserves_verified_snapshot_and_selection(self):
        snapshot = self.publish()
        before = {name: (snapshot / name).read_bytes() for name in (*policy.DATA_FILES, "manifest.json")}
        pointer = (self.cache / "current").read_bytes()
        with patch.object(feeds, "build_snapshot", side_effect=RuntimeError("invalid upstream data")):
            selected = feeds.select_snapshot(self.cache, self.config, True)
        self.assertEqual(selected, snapshot)
        self.assertEqual((self.cache / "current").read_bytes(), pointer)
        self.assertEqual({name: (snapshot / name).read_bytes() for name in before}, before)
        self.assertFalse(list(self.cache.glob(".stage-*")))

    def test_policy_change_cannot_reuse_an_old_snapshot_when_offline(self):
        self.publish()
        changed = dict(self.config, blockedDomainSuffixes=["new-policy.example"])
        with patch.object(feeds, "build_snapshot", side_effect=RuntimeError("offline")):
            with self.assertRaises(RuntimeError):
                feeds.select_snapshot(self.cache, changed, False)

    def test_expired_snapshot_cannot_be_used_when_refresh_fails(self):
        snapshot = self.publish()
        created = policy.read_snapshot(snapshot, 48)["manifest"]["createdAt"]
        with patch.object(policy.time, "time", return_value=created + 49 * 3600):
            with patch.object(feeds, "build_snapshot", side_effect=RuntimeError("offline")):
                with self.assertRaises(RuntimeError):
                    feeds.select_snapshot(self.cache, self.config, False)

    def test_new_snapshot_does_not_mutate_a_live_vm_snapshot(self):
        previous = self.publish()
        before = (previous / "domains.txt").read_bytes()
        def updated(opener, url, maximum, deadline):
            if url == feeds.DOMAIN_URL:
                return b"another-threat.example\n"
            return self.download(opener, url, maximum, deadline)
        with patch.object(feeds, "download", side_effect=updated):
            current = feeds.select_snapshot(self.cache, self.config, True)
        self.assertNotEqual(current, previous)
        self.assertEqual((previous / "domains.txt").read_bytes(), before)
        self.assertIn("another-threat.example", policy.read_snapshot(current, 48)["domains"])


@unittest.skipUnless(shutil.which("openssl"), "TLS fixtures require the openssl command")
class FeedTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="feed-tls-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.certificate = cls.root / "localhost.pem"
        cls.key = cls.root / "localhost.key"
        configuration = cls.root / "certificate.conf"
        configuration.write_text(
            "[req]\nprompt=no\ndistinguished_name=subject\nx509_extensions=extensions\n"
            "[subject]\nCN=localhost\n"
            "[extensions]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\n"
        )
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-config", str(configuration),
            "-keyout", str(cls.key), "-out", str(cls.certificate),
        ], check=True, capture_output=True, timeout=30)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"malware.example\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certificate, cls.key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server)
        cls.url = f"https://localhost:{cls.server.server_port}/feed"

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def fetch(self, url=None):
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            feeds.HTTPSRedirects(),
            urllib.request.HTTPSHandler(context=feeds.tls_context()),
        )
        return feeds.download(opener, url or self.url, 1024, time.monotonic() + 10)

    def test_macos_bundle_verifies_https_with_an_independent_python_store(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(feeds.sys, "platform", "darwin"):
            with patch.object(feeds, "MACOS_CA_BUNDLE", self.certificate):
                self.assertEqual(self.fetch(), b"malware.example\n")

    def test_explicit_ca_bundle_takes_precedence_over_macos_bundle(self):
        invalid = self.root / "invalid.pem"
        invalid.write_text("not a certificate")
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(self.certificate)}, clear=True):
            with patch.object(feeds.sys, "platform", "darwin"):
                with patch.object(feeds, "MACOS_CA_BUNDLE", invalid):
                    self.assertEqual(self.fetch(), b"malware.example\n")

    def test_untrusted_certificate_is_rejected(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(feeds.sys, "platform", "linux"):
            with self.assertRaises(urllib.error.URLError) as failure:
                self.fetch()
        self.assertIsInstance(failure.exception.reason, ssl.SSLCertVerificationError)

    def test_trusted_certificate_with_wrong_hostname_is_rejected(self):
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(self.certificate)}, clear=True):
            with self.assertRaises(urllib.error.URLError) as failure:
                self.fetch(self.url.replace("localhost", "127.0.0.1"))
        self.assertIsInstance(failure.exception.reason, ssl.SSLCertVerificationError)


if __name__ == "__main__":
    unittest.main()
