#!/usr/bin/env python3
"""Bounded, repository-neutral deterministic check adapters.

The adapter reads only the authenticated Git HEAD of a clean checkout. It never writes the
repository, never treats an unavailable adapter as PASS, and keeps the catalog as the policy
authority. Each executable check has an explicit bounded contract and conservative failure
semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_CATALOG_BYTES = 1_000_000
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_GREP_OUTPUT_BYTES = 64 * 1024
MAX_TRACKED_FILES = 100_000
MAX_FINDINGS = 64
MAX_STRING_LENGTH = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_GENERATED_MANIFEST_BYTES = 512 * 1024
MAX_GENERATED_FILES = 256
MAX_GENERATED_FILE_BYTES = 4 * 1024 * 1024
MAX_GENERATED_TOTAL_BYTES = 16 * 1024 * 1024
GENERATED_MANIFEST_PATH = ".quality-control/generated-files.json"
MAX_DEPENDENCY_LOCKFILES = 64
MAX_DEPENDENCY_LOCKFILE_BYTES = 1 * 1024 * 1024
MAX_DEPENDENCY_PINS = 2_048
MAX_DEPENDENCY_DECLARATIONS = 256
MAX_DEPENDENCY_TEXT_BYTES = 1 * 1024 * 1024
SECRET_PATH_SUFFIXES = (".p12", ".pfx", ".mobileprovision")
SECRET_MARKER = re.compile(
    r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
    r"(ghp_|github_pat_|xox[baprs]-|sk_live_|AKIA[0-9A-Z]{16})"
)
TODO_MARKER = re.compile(r"(?:^|//|#|/\*|\*)\s*\b(?:TODO|FIXME)\b")
TODO_METADATA = re.compile(
    r"\b(?:TODO|FIXME)\b\s*\(\s*owner\s*[=:]\s*[A-Za-z0-9._-]+\s+"
    r"(?:ticket|issue)\s*[=:]\s*[A-Za-z0-9._-]+\s+expires\s*[=:]\s*\d{4}-\d{2}-\d{2}\s*\)"
)
GENERATED_MARKER = re.compile(
    r"@generated-by[ \t]+generator=(?P<generator>[A-Za-z0-9._/-]{1,128})[ \t]+"
    r"version=(?P<version>[A-Za-z0-9][A-Za-z0-9._+/-]{0,127})(?:[ \t]|$)",
    re.MULTILINE,
)
GENERATOR_NAME = re.compile(r"[A-Za-z0-9._/-]{1,128}")
GENERATOR_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_REVISION = re.compile(r"[0-9a-f]{40}")
PACKAGE_URL_DECLARATION = re.compile(
    r"\.package\s*\([^)]{0,4096}?\burl\s*:\s*\"(?P<location>[^\"]+)\"",
    re.DOTALL,
)
PBX_PACKAGE_URL_DECLARATION = re.compile(
    r"\brepositoryURL\s*=\s*\"(?P<location>[^\"]+)\"\s*;"
)


class AdapterError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise AdapterError(f"catalog is unreadable: {error}") from error
    if len(data) > MAX_CATALOG_BYTES:
        raise AdapterError("catalog exceeds the immutable byte limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, AdapterError) as error:
        raise AdapterError(f"catalog is malformed: {error}") from error
    if not isinstance(value, dict):
        raise AdapterError("catalog root must be an object")
    return value


def bounded_process(
    root: Path,
    arguments: list[str],
    maximum_bytes: int,
    allowed_returncodes: set[int] | None = None,
) -> bytes:
    environment = os.environ.copy()
    for key in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
    ):
        environment.pop(key, None)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
    })
    try:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=COMMAND_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AdapterError(f"bounded Git command failed: {error}") from error
    if len(result.stdout) > maximum_bytes or len(result.stderr) > MAX_GREP_OUTPUT_BYTES:
        raise AdapterError("Git command exceeded the immutable output limit")
    allowed = {0} if allowed_returncodes is None else allowed_returncodes
    if result.returncode not in allowed:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise AdapterError(detail[:MAX_STRING_LENGTH] or "Git command failed")
    return result.stdout


def git_text(root: Path, arguments: list[str], maximum_bytes: int) -> str:
    return bounded_process(root, arguments, maximum_bytes).decode("utf-8")


def clean_checkout(root: Path) -> None:
    reported_root = git_text(root, ["rev-parse", "--show-toplevel"], 4_096).strip()
    if Path(reported_root).resolve() != root:
        raise AdapterError("repository root is not the Git worktree root")
    status = git_text(root, ["status", "--porcelain=v1", "--untracked-files=all"], MAX_GREP_OUTPUT_BYTES)
    if status:
        raise AdapterError("repository checkout must be clean before deterministic checks")


def tracked_paths(root: Path) -> list[str]:
    output = bounded_process(root, ["ls-tree", "-r", "-z", "--name-only", "HEAD", "--"], MAX_GIT_OUTPUT_BYTES)
    paths = [value.decode("utf-8") for value in output.split(b"\0") if value]
    if len(paths) > MAX_TRACKED_FILES or any(
        not path or len(path) > MAX_STRING_LENGTH or Path(path).is_absolute() or ".." in Path(path).parts
        for path in paths
    ):
        raise AdapterError("tracked Git tree is malformed or exceeds its immutable limits")
    return sorted(paths)


def tracked_tree_entries(root: Path) -> dict[str, str]:
    """Return regular Git-tree paths and modes without consulting the mutable index."""
    output = bounded_process(root, ["ls-tree", "-r", "-z", "HEAD", "--"], MAX_GIT_OUTPUT_BYTES)
    entries: dict[str, str] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = header.split(b" ", 2)
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise AdapterError("tracked Git tree has a malformed generated-file entry") from error
        if not path or len(path) > MAX_STRING_LENGTH or path.startswith("/") or "\\" in path:
            raise AdapterError("tracked Git tree has an invalid path")
        if any(part in ("", ".", "..") for part in path.split("/")):
            raise AdapterError("tracked Git tree has a traversal or empty path")
        if (
            object_type != b"blob"
            or len(object_id) != 40
            or any(character not in b"0123456789abcdef" for character in object_id)
        ):
            raise AdapterError("tracked Git tree has an unsupported object entry")
        if path in entries:
            raise AdapterError("tracked Git tree contains a duplicate path")
        entries[path] = mode.decode("ascii")
    if len(entries) > MAX_TRACKED_FILES:
        raise AdapterError("tracked Git tree exceeds the immutable file limit")
    return entries


def current_revision(root: Path) -> str:
    revision = git_text(root, ["rev-parse", "HEAD"], 128).strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise AdapterError("Git HEAD is not a lowercase 40-character SHA")
    return revision


def catalog_entry(catalog: dict[str, Any], check_id: str) -> None:
    if set(catalog) != {"schemaVersion", "catalogVersion", "checks"}:
        raise AdapterError("catalog has an unsupported property set")
    if catalog.get("schemaVersion") != 1 or not isinstance(catalog.get("checks"), list):
        raise AdapterError("only catalog schemaVersion 1 is supported")
    matches = [entry for entry in catalog["checks"] if isinstance(entry, dict) and entry.get("id") == check_id]
    if len(matches) != 1:
        raise AdapterError(f"check is absent or duplicated in catalog: {check_id}")
    if matches[0].get("implementation") != "implemented":
        raise AdapterError(f"check adapter is not implemented: {check_id}")


def findings_for_secrets(root: Path, paths: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in paths:
        if path.lower().endswith(SECRET_PATH_SUFFIXES):
            findings.append({"path": path, "message": "Tracked credential-shaped binary must not be committed."})
            if len(findings) >= MAX_FINDINGS:
                return findings
    output = bounded_process(
        root, ["grep", "-n", "-I", "-E", "-e", SECRET_MARKER.pattern, "HEAD", "--"],
        MAX_GREP_OUTPUT_BYTES, allowed_returncodes={0, 1}
    )
    for record in output.decode("utf-8", errors="replace").splitlines():
        if len(findings) >= MAX_FINDINGS:
            break
        parts = record.split(":", 3)
        if len(parts) >= 3:
            findings.append({
                "path": parts[1][:MAX_STRING_LENGTH],
                "message": "Tracked high-confidence credential marker found in Git HEAD.",
            })
    return findings


def findings_for_todo_owner(root: Path) -> list[dict[str, str]]:
    output = bounded_process(
        root, ["grep", "-n", "-I", "-E", "-e", "TODO|FIXME", "HEAD", "--"],
        MAX_GREP_OUTPUT_BYTES, allowed_returncodes={0, 1}
    )
    findings: list[dict[str, str]] = []
    for record in output.decode("utf-8", errors="replace").splitlines():
        if len(findings) >= MAX_FINDINGS:
            break
        parts = record.split(":", 3)
        if len(parts) < 4 or not TODO_MARKER.search(parts[3]):
            continue
        if not TODO_METADATA.search(parts[3]):
            findings.append({
                "path": parts[1][:MAX_STRING_LENGTH],
                "message": "TODO/FIXME must include owner, ticket/issue, and YYYY-MM-DD expiry metadata.",
            })
    return findings


def normalized_dependency_identity(value: str) -> str:
    candidate = value.strip().split("?", 1)[0].split("#", 1)[0].rstrip("/")
    candidate = candidate.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if candidate.lower().endswith(".git"):
        candidate = candidate[:-4]
    candidate = candidate.lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", candidate):
        return ""
    return candidate


def normalized_dependency_location(value: str) -> str:
    candidate = value.strip().split("?", 1)[0].split("#", 1)[0].rstrip("/").lower()
    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    return candidate


def parse_dependency_json(data: bytes, label: str) -> Any:
    if len(data) > MAX_DEPENDENCY_LOCKFILE_BYTES:
        raise AdapterError(f"{label} exceeds the immutable byte limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, AdapterError) as error:
        raise AdapterError(f"{label} is malformed: {error}") from error


def dependency_lock_paths(paths: list[str]) -> list[str]:
    locks = sorted(path for path in paths if Path(path).name == "Package.resolved")
    if len(locks) > MAX_DEPENDENCY_LOCKFILES:
        raise AdapterError("tracked Package.resolved files exceed the immutable file limit")
    return locks


def external_dependency_declarations(root: Path, paths: list[str]) -> list[dict[str, str]]:
    declarations: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        if not (path.endswith("Package.swift") or path.endswith(".pbxproj")):
            continue
        data = bounded_process(root, ["show", f"HEAD:{path}"], MAX_DEPENDENCY_TEXT_BYTES)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AdapterError(f"dependency declaration must be UTF-8 text: {path}") from error
        matcher = PACKAGE_URL_DECLARATION if path.endswith("Package.swift") else PBX_PACKAGE_URL_DECLARATION
        for match in matcher.finditer(text):
            location = match.group("location").strip()
            identity = normalized_dependency_identity(location)
            if not identity or not location or any(character.isspace() for character in location):
                raise AdapterError(f"dependency declaration has an invalid location: {path}")
            key = (path, normalized_dependency_location(location))
            if key in seen:
                continue
            seen.add(key)
            declarations.append({"path": path, "identity": identity, "location": location})
            if len(declarations) > MAX_DEPENDENCY_DECLARATIONS:
                raise AdapterError("external dependency declarations exceed the immutable limit")
    return declarations


def normalized_lock_pins(data: bytes, path: str) -> list[dict[str, str]]:
    value = parse_dependency_json(data, path)
    if not isinstance(value, dict) or type(value.get("version")) is not int:
        raise AdapterError(f"{path} has an unsupported Package.resolved shape")
    version = value["version"]
    if version == 1:
        if set(value) != {"object", "version"} or not isinstance(value["object"], dict):
            raise AdapterError(f"{path} has an unsupported Package.resolved v1 shape")
        if set(value["object"]) != {"pins"}:
            raise AdapterError(f"{path} has an unsupported Package.resolved v1 object")
        if "pins" not in value["object"]:
            raise AdapterError(f"{path} is missing Package.resolved pins")
        pins = value["object"]["pins"]
        pin_shape = "v1"
    elif version in {2, 3}:
        allowed = {"pins", "version"} if version == 2 else {"originHash", "pins", "version"}
        if set(value) != allowed:
            raise AdapterError(f"{path} has an unsupported Package.resolved v{version} shape")
        if version == 3 and (not isinstance(value.get("originHash"), str) or not value["originHash"].strip()):
            raise AdapterError(f"{path} has an invalid Package.resolved originHash")
        if "pins" not in value:
            raise AdapterError(f"{path} is missing Package.resolved pins")
        pins = value["pins"]
        pin_shape = "v2+"
    else:
        raise AdapterError(f"{path} uses an unsupported Package.resolved version")
    if not isinstance(pins, list) or len(pins) > MAX_DEPENDENCY_PINS:
        raise AdapterError(f"{path} exceeds the immutable pin limit")

    normalized: list[dict[str, str]] = []
    seen_identities: set[str] = set()
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict):
            raise AdapterError(f"{path} pin {index} is not an object")
        if pin_shape == "v1":
            if set(pin) != {"package", "repositoryURL", "state"}:
                raise AdapterError(f"{path} pin {index} has an unsupported v1 shape")
            raw_identity = pin["package"]
            raw_location = pin["repositoryURL"]
        else:
            if set(pin) != {"identity", "kind", "location", "state"}:
                raise AdapterError(f"{path} pin {index} has an unsupported shape")
            raw_identity = pin["identity"]
            raw_location = pin["location"]
            if not isinstance(pin["kind"], str) or not pin["kind"].strip():
                raise AdapterError(f"{path} pin {index} has an invalid kind")
        if not isinstance(raw_identity, str) or not isinstance(raw_location, str):
            raise AdapterError(f"{path} pin {index} has an invalid identity or location")
        identity = normalized_dependency_identity(raw_identity)
        location = normalized_dependency_location(raw_location)
        if not identity or not location or any(character.isspace() for character in raw_location):
            raise AdapterError(f"{path} pin {index} has an invalid identity or location")
        state = pin["state"]
        if not isinstance(state, dict) or set(state) - {"branch", "revision", "version"}:
            raise AdapterError(f"{path} pin {index} has an unsupported state shape")
        revision = state.get("revision")
        if not isinstance(revision, str) or not GIT_REVISION.fullmatch(revision):
            raise AdapterError(f"{path} pin {index} has no immutable lowercase revision")
        for key in ("branch", "version"):
            if key in state and state[key] is not None and (
                not isinstance(state[key], str) or not state[key].strip()
            ):
                raise AdapterError(f"{path} pin {index} has an invalid {key} state")
        if identity in seen_identities:
            raise AdapterError(f"{path} contains duplicate dependency identity: {identity}")
        seen_identities.add(identity)
        normalized.append({"identity": identity, "location": location})
    return normalized


def findings_for_dependency_lock_drift(root: Path, paths: list[str]) -> list[dict[str, str]]:
    lock_paths = dependency_lock_paths(paths)
    declarations = external_dependency_declarations(root, paths)
    pins: list[dict[str, str]] = []
    for path in lock_paths:
        data = bounded_process(root, ["show", f"HEAD:{path}"], MAX_DEPENDENCY_LOCKFILE_BYTES)
        for pin in normalized_lock_pins(data, path):
            pins.append({**pin, "path": path})

    findings: list[dict[str, str]] = []
    if declarations and not lock_paths:
        for declaration in declarations[:MAX_FINDINGS]:
            findings.append({
                "path": declaration["path"],
                "message": "External Swift package declaration has no tracked Package.resolved lockfile.",
            })
        return findings
    for declaration in declarations:
        location = normalized_dependency_location(declaration["location"])
        if not any(pin["identity"] == declaration["identity"] or pin["location"] == location for pin in pins):
            findings.append({
                "path": declaration["path"],
                "message": "External dependency declaration has no matching immutable Package.resolved pin.",
            })
            if len(findings) >= MAX_FINDINGS:
                break
    return findings


def generated_manifest(root: Path) -> list[dict[str, str]]:
    try:
        data = bounded_process(
            root,
            ["show", f"HEAD:{GENERATED_MANIFEST_PATH}"],
            MAX_GENERATED_MANIFEST_BYTES,
        )
    except AdapterError as error:
        raise AdapterError(
            f"{GENERATED_MANIFEST_PATH} must be present and readable from Git HEAD"
        ) from error
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, AdapterError) as error:
        raise AdapterError(f"{GENERATED_MANIFEST_PATH} is malformed: {error}") from error
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "files"}:
        raise AdapterError(f"{GENERATED_MANIFEST_PATH} has an unsupported property set")
    if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise AdapterError(f"{GENERATED_MANIFEST_PATH} must use schemaVersion 1")
    files = value.get("files")
    if not isinstance(files, list) or len(files) > MAX_GENERATED_FILES:
        raise AdapterError(f"{GENERATED_MANIFEST_PATH} exceeds the immutable file-entry limit")

    declarations: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, entry in enumerate(files):
        if not isinstance(entry, dict) or set(entry) != {"path", "generator", "version", "sha256"}:
            raise AdapterError(f"generated file entry {index} has an unsupported property set")
        path = entry.get("path")
        generator = entry.get("generator")
        version = entry.get("version")
        digest = entry.get("sha256")
        if not isinstance(path, str) or not path or len(path) > MAX_STRING_LENGTH:
            raise AdapterError(f"generated file entry {index} has an invalid path")
        if path.startswith("/") or path.startswith("~") or "\\" in path:
            raise AdapterError(f"generated file entry {index} has an invalid path")
        if any(part in ("", ".", "..") for part in path.split("/")):
            raise AdapterError(f"generated file entry {index} has a traversal or empty path")
        if path == GENERATED_MANIFEST_PATH or path in seen:
            raise AdapterError(f"generated file entry {index} has a duplicate or reserved path")
        if not isinstance(generator, str) or not GENERATOR_NAME.fullmatch(generator):
            raise AdapterError(f"generated file entry {index} has an invalid generator")
        if not isinstance(version, str) or not GENERATOR_VERSION.fullmatch(version):
            raise AdapterError(f"generated file entry {index} has an invalid generator version")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise AdapterError(f"generated file entry {index} has an invalid sha256")
        seen.add(path)
        declarations.append({
            "path": path,
            "generator": generator,
            "version": version,
            "sha256": digest,
        })
    return declarations


def generated_marker_paths(root: Path) -> list[str]:
    output = bounded_process(
        root,
        [
            "grep", "-l", "-I", "-E",
            "-e", "@generated-by",
            "HEAD", "--",
        ],
        MAX_GREP_OUTPUT_BYTES,
        allowed_returncodes={0, 1},
    )
    try:
        decoded_output = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError("generated marker scan returned non-UTF-8 output") from error
    paths = [line.removeprefix("HEAD:") for line in decoded_output.splitlines() if line]
    if len(paths) > MAX_GENERATED_FILES:
        raise AdapterError("generated marker scan exceeded the immutable file-entry limit")
    if any(
        not path
        or len(path) > MAX_STRING_LENGTH
        or path.startswith("/")
        or "\\" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
        for path in paths
    ):
        raise AdapterError("generated marker scan returned an invalid path")
    return paths


def findings_for_generated_ownership(root: Path) -> list[dict[str, str]]:
    declarations = generated_manifest(root)
    entries = tracked_tree_entries(root)
    findings: list[dict[str, str]] = []
    declared_paths = {entry["path"] for entry in declarations}
    total_bytes = 0

    for declaration in declarations:
        path = declaration["path"]
        if path not in entries:
            raise AdapterError(f"generated manifest references an untracked path: {path}")
        if entries[path] not in {"100644", "100755"}:
            raise AdapterError(f"generated manifest references a non-regular path: {path}")
        data = bounded_process(root, ["show", f"HEAD:{path}"], MAX_GENERATED_FILE_BYTES)
        total_bytes += len(data)
        if total_bytes > MAX_GENERATED_TOTAL_BYTES:
            raise AdapterError("generated files exceed the immutable aggregate byte limit")
        if hashlib.sha256(data).hexdigest() != declaration["sha256"]:
            findings.append({"path": path, "message": "Declared SHA-256 does not match Git HEAD."})
            if len(findings) >= MAX_FINDINGS:
                return findings
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AdapterError(f"declared generated file must be UTF-8 text: {path}") from error
        markers = list(GENERATED_MARKER.finditer(text))
        if len(markers) != 1:
            findings.append({
                "path": path,
                "message": "Generated file must contain exactly one @generated-by marker.",
            })
        elif (
            markers[0].group("generator") != declaration["generator"]
            or markers[0].group("version") != declaration["version"]
        ):
            findings.append({
                "path": path,
                "message": "@generated-by marker does not match the declared generator and version.",
            })
        if len(findings) >= MAX_FINDINGS:
            return findings

    for path in generated_marker_paths(root):
        if path not in declared_paths:
            findings.append({
                "path": path,
                "message": "Generated marker is present but the path is absent from the ownership manifest.",
            })
            if len(findings) >= MAX_FINDINGS:
                break
    return findings


def report(check_id: str, revision: str, status: str, message: str, findings: list[dict[str, str]] | None = None) -> dict[str, Any]:
    check: dict[str, Any] = {"id": check_id, "status": status, "message": message}
    if findings:
        check["findings"] = findings
    return {"schemaVersion": 1, "command": "deterministic-checks", "status": status, "sourceRevision": revision, "checks": [check]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one catalog-backed deterministic quality check")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--check", required=True)
    arguments = parser.parse_args()
    root = Path(arguments.repository_root).resolve()
    try:
        if not root.is_dir():
            raise AdapterError("repository root must be a directory")
        catalog_entry(load_json(Path(arguments.catalog).resolve()), arguments.check)
        clean_checkout(root)
        revision = current_revision(root)
        paths = tracked_paths(root)
        if arguments.check == "QC.SECRETS.TRACKED":
            findings = findings_for_secrets(root, paths)
            if findings:
                result = report(arguments.check, revision, "FAIL", "Tracked secret-like material was found.", findings)
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 1
            result = report(arguments.check, revision, "PASS", "No high-confidence tracked credential material was found.")
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.check == "QC.TODO.OWNER":
            findings = findings_for_todo_owner(root)
            if findings:
                result = report(arguments.check, revision, "FAIL", "Tracked TODO/FIXME markers are missing ownership metadata.", findings)
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 1
            result = report(arguments.check, revision, "PASS", "All tracked TODO/FIXME markers carry bounded ownership metadata.")
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.check == "QC.GENERATED.OWNERSHIP":
            findings = findings_for_generated_ownership(root)
            if findings:
                result = report(
                    arguments.check,
                    revision,
                    "FAIL",
                    "Generated ownership declarations or markers are inconsistent.",
                    findings,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 1
            result = report(
                arguments.check,
                revision,
                "PASS",
                "All declared generated files have reproducible ownership markers and matching hashes.",
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.check == "QC.DEPENDENCY.LOCK_DRIFT":
            findings = findings_for_dependency_lock_drift(root, paths)
            if findings:
                result = report(
                    arguments.check,
                    revision,
                    "FAIL",
                    "Dependency declarations and lockfiles are inconsistent.",
                    findings,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 1
            result = report(
                arguments.check,
                revision,
                "PASS",
                "Tracked dependency lockfiles are valid and match external declarations.",
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        raise AdapterError(f"no executable adapter is registered for {arguments.check}")
    except AdapterError as error:
        result = report(arguments.check, "", "BLOCKED", str(error))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
