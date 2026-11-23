import unittest
from pathlib import Path


class GatewayPackagingTests(unittest.TestCase):
    def test_builds_bundle_gateway_dependencies(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("build_exe.ps1", "build_multi_exe.ps1"):
            with self.subTest(build=name):
                self.assertIn('"--hidden-import", "api_gateway"', (root / name).read_text(encoding="utf-8-sig"))

    def test_worker_deployment_keeps_gateway_available(self):
        source = (Path(__file__).resolve().parents[1] / "src" / "avatar_ui.py").read_text(encoding="utf-8")
        worker_files = source.split("_WORKER_FILES = (", 1)[1].split(")", 1)[0]
        self.assertIn('"api_gateway.py"', worker_files)
