#!/usr/bin/env python3
"""Contract tests for the catalog-backed Python deterministic adapters."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
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


class DependencyLockDriftAdapterTests(unittest.TestCase):
    def run_check(self, files: dict[str, bytes]) -> tuple[int, dict]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for path, contents in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
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
                    "--check", "QC.DEPENDENCY.LOCK_DRIFT",
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
    def package_manifest(location: str = "https://github.com/example/fixture-package.git") -> bytes:
        return (
            "// swift-tools-version: 5.9\n"
            "import PackageDescription\n"
            "let package = Package(name: \"Fixture\", dependencies: [\n"
            f"    .package(url: \"{location}\", from: \"1.0.0\")\n"
            "], targets: [])\n"
        ).encode("utf-8")

    @staticmethod
    def resolved_v2(identity: str = "fixture-package", location: str = "https://github.com/example/fixture-package.git") -> bytes:
        return json.dumps({
            "pins": [{
                "identity": identity,
                "kind": "remoteSourceControl",
                "location": location,
                "state": {
                    "revision": "a" * 40,
                    "version": "1.0.0",
                },
            }],
            "version": 2,
        }).encode("utf-8")

    def test_local_only_package_without_lock_passes(self) -> None:
        returncode, report = self.run_check({
            "Package.swift": b"// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: \"Local\", targets: [])\n",
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")

    def test_matching_swiftpm_v2_lock_passes(self) -> None:
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": self.resolved_v2(),
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks"][0]["id"], "QC.DEPENDENCY.LOCK_DRIFT")

    def test_missing_lock_for_external_package_fails(self) -> None:
        returncode, report = self.run_check({"Package.swift": self.package_manifest()})
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["checks"][0]["findings"][0]["path"], "Package.swift")

    def test_unmatched_lock_pin_fails(self) -> None:
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": self.resolved_v2("different-package", "https://github.com/example/different-package.git"),
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")

    def test_matching_xcode_remote_declaration_passes(self) -> None:
        project = b'''/* Begin XCRemoteSwiftPackageReference section */
        repositoryURL = "https://github.com/example/fixture-package.git";
        /* End XCRemoteSwiftPackageReference section */
        '''
        returncode, report = self.run_check({
            "Fixture.xcodeproj/project.pbxproj": project,
            "Fixture.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved": self.resolved_v2(),
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")

    def test_swiftpm_v1_lock_passes(self) -> None:
        lock = json.dumps({
            "object": {"pins": [{
                "package": "fixture-package",
                "repositoryURL": "https://github.com/example/fixture-package.git",
                "state": {"branch": None, "revision": "a" * 40, "version": None},
            }]},
            "version": 1,
        }).encode("utf-8")
        returncode, report = self.run_check({"Package.swift": self.package_manifest(), "Package.resolved": lock})
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")

    def test_swiftpm_v3_lock_passes(self) -> None:
        lock = json.loads(self.resolved_v2().decode("utf-8"))
        lock["version"] = 3
        lock["originHash"] = "b" * 40
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": json.dumps(lock).encode("utf-8"),
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")

    def test_malformed_lock_is_blocked(self) -> None:
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": b"{not-json}",
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_duplicate_json_property_is_blocked(self) -> None:
        lock = (
            b'{"pins": [], "pins": [], "version": 2}'
        )
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": lock,
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_duplicate_pin_identity_is_blocked(self) -> None:
        lock = json.loads(self.resolved_v2().decode("utf-8"))
        lock["pins"].append(lock["pins"][0].copy())
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": json.dumps(lock).encode("utf-8"),
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_non_immutable_revision_is_blocked(self) -> None:
        lock = json.loads(self.resolved_v2().decode("utf-8"))
        lock["pins"][0]["state"]["revision"] = "main"
        returncode, report = self.run_check({
            "Package.swift": self.package_manifest(),
            "Package.resolved": json.dumps(lock).encode("utf-8"),
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")


class LocalizationCatalogAdapterTests(unittest.TestCase):
    def run_check(self, files: dict[str, bytes]) -> tuple[int, dict]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for path, contents in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
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
                    "--check", "QC.LOCALIZATION.CATALOG",
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
    def stringsdict() -> bytes:
        return plistlib.dumps({
            "item.count": {
                "NSStringLocalizedFormatKey": "%#@items@",
                "items": {
                    "NSStringFormatSpecTypeKey": "NSStringPluralRuleType",
                    "NSStringFormatValueTypeKey": "d",
                    "one": "%d item",
                    "other": "%d items",
                },
            },
        }, fmt=plistlib.FMT_XML)

    @staticmethod
    def xcstrings(localizations: dict[str, dict] | None = None) -> bytes:
        values = localizations or {
            "en": {"stringUnit": {"state": "translated", "value": "Welcome"}},
            "ru": {"stringUnit": {"state": "translated", "value": "Добро пожаловать"}},
        }
        return json.dumps({
            "sourceLanguage": "en",
            "strings": {"welcome.title": {"localizations": values}},
            "version": "1.0",
        }).encode("utf-8")

    def test_no_localization_resources_passes(self) -> None:
        returncode, report = self.run_check({"README.md": b"No localized resources.\n"})
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks"][0]["id"], "QC.LOCALIZATION.CATALOG")

    def test_matching_strings_locales_pass(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.strings": b'"welcome" = "Welcome";\n',
            "Resources/ru.lproj/Localizable.strings": '"welcome" = "Добро пожаловать";\n'.encode("utf-8"),
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")

    def test_strings_key_parity_fails(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.strings": b'"welcome" = "Welcome";\n"count" = "%d";\n',
            "Resources/ru.lproj/Localizable.strings": '"welcome" = "Добро пожаловать";\n'.encode("utf-8"),
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("count", report["checks"][0]["findings"][0]["message"])

    def test_duplicate_strings_key_blocked(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.strings": b'"welcome" = "One";\n"welcome" = "Two";\n',
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_malformed_strings_blocked(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.strings": b'"welcome" = "Welcome"\n',
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_matching_stringsdict_locales_pass(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.stringsdict": self.stringsdict(),
            "Resources/ru.lproj/Localizable.stringsdict": self.stringsdict(),
        })
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")

    def test_malformed_stringsdict_blocked(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.stringsdict": b"<?xml version=\"1.0\"?><plist><dict></dict>",
        })
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_stringsdict_without_plural_rule_is_blocked(self) -> None:
        malformed = plistlib.dumps({
            "item.count": {"NSStringLocalizedFormatKey": "%#@items@"},
        }, fmt=plistlib.FMT_XML)
        returncode, report = self.run_check({"Resources/en.lproj/Localizable.stringsdict": malformed})
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_duplicate_stringsdict_key_is_blocked(self) -> None:
        duplicate = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>item.count</key><dict><key>NSStringLocalizedFormatKey</key><string>%#@items@</string></dict>
<key>item.count</key><dict><key>NSStringLocalizedFormatKey</key><string>%#@items@</string></dict>
</dict></plist>'''
        returncode, report = self.run_check({"Resources/en.lproj/Localizable.stringsdict": duplicate})
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_empty_fallback_value_fails(self) -> None:
        returncode, report = self.run_check({
            "Resources/en.lproj/Localizable.strings": b'"welcome" = "";\n',
            "Resources/ru.lproj/Localizable.strings": '"welcome" = "Добро пожаловать";\n'.encode("utf-8"),
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("empty", report["checks"][0]["findings"][0]["message"])

    def test_matching_xcstrings_pass(self) -> None:
        returncode, report = self.run_check({"Resources/Localizable.xcstrings": self.xcstrings()})
        self.assertEqual(returncode, 0)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks"][0]["id"], "QC.LOCALIZATION.CATALOG")

    def test_xcstrings_missing_source_fallback_fails(self) -> None:
        returncode, report = self.run_check({
            "Resources/Localizable.xcstrings": self.xcstrings({
                "ru": {"stringUnit": {"state": "translated", "value": "Добро пожаловать"}},
            }),
        })
        self.assertEqual(returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("source-language fallback", report["checks"][0]["findings"][0]["message"])

    def test_duplicate_xcstrings_json_property_blocked(self) -> None:
        duplicate = b'{"sourceLanguage":"en","sourceLanguage":"en","strings":{},"version":"1.0"}'
        returncode, report = self.run_check({"Resources/Localizable.xcstrings": duplicate})
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")

    def test_unsupported_xcstrings_shape_blocked(self) -> None:
        unsupported = json.dumps({
            "sourceLanguage": "en",
            "strings": {},
            "version": "1.0",
            "unexpected": True,
        }).encode("utf-8")
        returncode, report = self.run_check({"Resources/Localizable.xcstrings": unsupported})
        self.assertEqual(returncode, 2)
        self.assertEqual(report["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
