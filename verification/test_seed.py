import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vm_seed", ROOT / "vm-seed.py")
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class ConfigurationSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sandbox-seed-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.pi = self.root / "sources/pi"
        self.omp = self.root / "sources/omp"
        self.native = self.root / "native"
        for source in (self.pi, self.omp):
            (source / "agent").mkdir(parents=True)
        self.roots = (
            (self.pi, self.native / ".pi", {Path("agent/sessions")}),
            (self.omp, self.native / ".omp", {Path("agent/sessions"), Path("agent/blobs")}),
        )

    def write(self, source, name, contents):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def snapshot(self, source):
        output = self.root / "output" / source.name
        output.parent.mkdir(exist_ok=True)
        shared = next(shared for root, _, shared in self.roots if root == source)
        seed.copy_tree(source, output, shared=shared, roots=self.roots)
        return output

    def test_cross_agent_models_are_private_regular_files(self):
        models = {"providers": {"spark-vllm": {"baseUrl": "https://spark.example/v1"}, "other": {}}}
        original = self.write(self.pi, "agent/models.json", json.dumps(models))
        (self.omp / "agent/models.yml").symlink_to(self.native / ".pi/agent/models.json")
        copied = self.snapshot(self.omp) / "agent/models.yml"
        self.assertFalse(copied.is_symlink())
        self.assertEqual(json.loads(copied.read_text()), models)
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
        original.write_text('{"providers":{}}')
        self.assertEqual(json.loads(copied.read_text()), models)

    def test_relative_cross_agent_link_uses_native_root_mapping(self):
        self.write(self.pi, "agent/models.json", '{"providers":{"local":{}}}')
        (self.omp / "agent/models.yml").symlink_to("../../.pi/agent/models.json")
        copied = self.snapshot(self.omp) / "agent/models.yml"
        self.assertEqual(json.loads(copied.read_text()), {"providers": {"local": {}}})
        self.assertFalse(copied.is_symlink())

    def test_links_cannot_import_excluded_or_external_state(self):
        targets = [
            "trust.json", "history.db.backup", "sessions/transcript.jsonl",
            "blobs/image.png", "cache/state.json", "logs/state.json",
        ]
        for index, target in enumerate(targets):
            self.write(self.omp, f"agent/{target}", "excluded state")
            (self.omp / f"agent/alias-{index}.json").symlink_to(target)
        self.write(self.omp, "agent/config.json", "{}")
        (self.omp / "agent/trust.db").symlink_to("config.json")
        external = self.write(self.root, "outside/private.json", "private data")
        (self.omp / "agent/external.json").symlink_to(external)
        (self.omp / "agent/escape.json").symlink_to("../../outside/private.json")
        (self.omp / "agent/directory").symlink_to(".")
        (self.omp / "agent/broken.json").symlink_to("absent.json")
        (self.omp / "agent/cycle.json").symlink_to("cycle.json")
        copied = self.snapshot(self.omp) / "agent"
        self.assertEqual({entry.name for entry in copied.iterdir()}, {"config.json"})


if __name__ == "__main__":
    unittest.main()
