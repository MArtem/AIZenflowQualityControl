#!/usr/bin/env python3
"""Contract tests for the catalog-backed Python deterministic adapters."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ADAPTER = REPOSITORY_ROOT / "adapters" / "deterministic_checks.py"
CATALOG = REPOSITORY_ROOT / "policies" / "check-catalog.json"
MANIFEST_PATH = ".quality-control/generated-files.json"


class GeneratedOwnershipAdapterTests(unittest.TestCase):
    def run_check(self, files: dict[str, bytes], symlinks: dict[str, str] | None = None) -> tuple[int, dict]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for path, contents in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
            for path, target in (symlinks or {}).items():
                link = root / path
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target)
            subprocess.run(["git", "-C", str(root), "init", "--quiet"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
            subprocess.run(
                [
                    "git", "-C", str(root),
                    "-c", "user.name=fixture",
                    "-c", "user.email=fixture@example.invalid",
                    "commit", "--quiet", "-m", "fixture",
                ],
                check=True,
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ADAPTER),
                    "--repository-root", str(root),
                    "--catalog", str(CATALOG),
                    "--check", "QC.GENERATED.OWNERSHIP",
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                },
            )
            return result.returncode, json.loads(result.stdout)

    @staticmethod
    def manifest_for(path: str, contents: bytes, generator: str = "fixture-generator", version: str = "1.0.0") -> bytes:
        manifest = {
            "schemaVersion": 1,
            "files": [{
                "path": path,
                "generator": generator,
                "version": version,
                "sha256": hashlib.sha256(contents).hexdigest(),
            }],
        }
        return json.dumps(manifest, sort_keys=True).encode("utf-8")

    def test_matching_manifest_and_marker_pass(self) -> None:
        generated = b"// @generated-by generator=fixture-generator version=1.0.0\nstruct Safe {}\n"
        returncode, report = self.run_check({
            MANIFEST_PATH: self.manifest_for("Sources/Generated/Safe.swift", generated),
            "Sources/Generated/Safe.swift": generated,
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks"][0]["id"], "QC.GENERATED.OWNERSHIP")

    def test_unowned_marker_fails(self) -> None:
        generated = b"// @generated-by generator=fixture-generator version=1.0.0\nstruct Unowned {}\n"
        returncode, report = self.run_check({
            MANIFEST_PATH: b'{"schemaVersion":1,"files":[]}',
            "Sources/Generated/Unowned.swift": generated,
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["checks"][0]["findings"][0]["path"], "Sources/Generated/Unowned.swift")

    def test_malformed_marker_is_not_silent(self) -> None:
        generated = b"// @generated-by generator=fixture-generator\nstruct Malformed {}\n"
        returncode, report = self.run_check({
            MANIFEST_PATH: b'{"schemaVersion":1,"files":[]}',
            "Sources/Generated/Malformed.swift": generated,
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["checks"][0]["findings"][0]["path"], "Sources/Generated/Malformed.swift")

    def test_hash_or_marker_mismatch_fails(self) -> None:
        generated = b"// @generated-by generator=other-generator version=2.0.0\nstruct Changed {}\n"
        returncode, report = self.run_check({
            MANIFEST_PATH: self.manifest_for(
                "Sources/Generated/Changed.swift",
                b"// @generated-by generator=fixture-generator version=1.0.0\nstruct Changed {}\n",
            ),
            "Sources/Generated/Changed.swift": generated,
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertGreaterEqual(len(report["checks"][0]["findings"]), 2)

    def test_missing_manifest_is_blocked(self) -> None:
        returncode, report = self.run_check({"Sources/Generated/Safe.swift": b"struct Safe {}\n"})
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_manifest_traversal_is_blocked(self) -> None:
        generated = b"// @generated-by generator=fixture-generator version=1.0.0\nstruct Unsafe {}\n"
        returncode, report = self.run_check({
            MANIFEST_PATH: self.manifest_for("../Unsafe.swift", generated),
            "Unsafe.swift": generated,
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_manifest_symlink_is_blocked(self) -> None:
        generated = b"// @generated-by generator=fixture-generator version=1.0.0\nstruct Unsafe {}\n"
        returncode, report = self.run_check(
            {
                MANIFEST_PATH: self.manifest_for("Sources/Generated/Link.swift", generated),
                "Sources/Generated/Target.swift": generated,
            },
            symlinks={"Sources/Generated/Link.swift": "Target.swift"},
        )
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
