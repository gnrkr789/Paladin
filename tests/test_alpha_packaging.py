"""Distribution boundary tests without building or installing dependencies."""

import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "build_private_alpha", Path(__file__).resolve().parents[1] / "scripts" / "build_private_alpha.py")
PACKAGING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGING)


class AlphaPackagingTests(unittest.TestCase):
    def test_private_alpha_version(self):
        self.assertEqual(PACKAGING.VERSION, "0.2.0a1")

    def test_distribution_requires_matching_runtime_asset_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"__init__.py": b'"""Fixture."""\n',
                     "resources/sandbox/Dockerfile": b"FROM python:3.12-slim\n"}
            for name, content in files.items():
                target = root / "src" / "paladin" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            wheel, sdist = root / "fixture.whl", root / "fixture.tar.gz"
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, content in files.items():
                    archive.writestr("paladin/" + name, content)
            with tarfile.open(sdist, "w:gz") as archive:
                archive.add(root / "src", arcname="fixture/src")
            report = PACKAGING.inspect_artifacts(wheel, sdist, root)
            self.assertEqual(report["wheel_files"], report["sdist_files"])
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("paladin/__init__.py", files["__init__.py"])
                archive.writestr("paladin/resources/sandbox/Dockerfile", b"changed")
            with self.assertRaisesRegex(ValueError, "Wheel source/resource"):
                PACKAGING.inspect_artifacts(wheel, sdist, root)

    def test_missing_sandbox_assets_fail_before_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src" / "paladin").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "Sandbox runtime resources"):
                PACKAGING.inspect_artifacts(root / "missing.whl", root / "missing.tar.gz", root)


if __name__ == "__main__":
    unittest.main()
