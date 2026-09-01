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
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError
from xml.etree import ElementTree


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
MAX_LOCALIZATION_FILES = 512
MAX_LOCALIZATION_FILE_BYTES = 2 * 1024 * 1024
MAX_LOCALIZATION_TOTAL_BYTES = 32 * 1024 * 1024
MAX_LOCALIZATION_KEYS = 8_192
MAX_LOCALIZATION_LOCALES = 64
MAX_LOCALIZATION_NESTING = 32
MAX_RESOURCE_CATALOGS = 256
MAX_RESOURCE_CONTENTS_FILES = 2_048
MAX_RESOURCE_CONTENTS_BYTES = 512 * 1024
MAX_RESOURCE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_RESOURCE_JSON_NODES = 20_000
MAX_RESOURCE_REFERENCES = 4_096
MAX_RESOURCE_SOURCE_BYTES = 1 * 1024 * 1024
MAX_RESOURCE_SOURCE_FILES = 4_096
ASSET_SET_SUFFIXES = (
    ".appiconset", ".colorset", ".dataset", ".imageset", ".imagestack", ".launchimage",
    ".stickerpack", ".symbolset", ".arreferenceimage", ".reality", ".texture", ".spriteatlas",
)
RESOURCE_BINARY_OUTPUT_SUFFIXES = (".app", ".car", ".dSYM", ".ipa", ".xcarchive", ".xcresult")
RESOURCE_IMAGE_FILE_SUFFIXES = (
    ".gif", ".heic", ".jpeg", ".jpg", ".pdf", ".png", ".svg", ".tif", ".tiff", ".webp",
)
RESOURCE_DATA_FILE_SUFFIXES = (".bin", ".json", ".mlmodel", ".plist", ".txt")
RESOURCE_SOURCE_SUFFIXES = (".h", ".m", ".mm", ".swift", ".storyboard", ".xib")
RESOURCE_SOURCE_EXCLUDED_COMPONENTS = {".build", ".git", ".quality-control", "docs", "fixture", "fixtures", "tests", "uitests"}
RESOURCE_JSON_ARRAY_KEYS = {"appearances", "colors", "data", "groups", "images", "items"}
RESOURCE_REFERENCE_SEARCH_PATTERN = r"(Image|Color|UIImage|NSImage|NSDataAsset)[[:space:]]*\("
RESOURCE_REFERENCE_PATTERNS = (
    ("Image", re.compile(r'\bImage\s*\(\s*"(?P<name>[^"\\\r\n]{0,256})"')),
    ("Image", re.compile(r'\bImage\s*\(\s*decorative\s*:\s*"(?P<name>[^"\\\r\n]{0,256})"')),
    ("Color", re.compile(r'\bColor\s*\(\s*"(?P<name>[^"\\\r\n]{0,256})"')),
    ("UIImage", re.compile(r'\bUIImage\s*\(\s*named\s*:\s*"(?P<name>[^"\\\r\n]{0,256})"')),
    ("NSImage", re.compile(r'\bNSImage\s*\(\s*named\s*:\s*"(?P<name>[^"\\\r\n]{0,256})"')),
    ("NSDataAsset", re.compile(r'\bNSDataAsset\s*\(\s*name\s*:\s*"(?P<name>[^"\\\r\n]{0,256})"')),
)
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


def localization_paths(paths: list[str]) -> list[str]:
    resources = sorted(
        path for path in paths
        if Path(path).suffix.lower() in {".strings", ".stringsdict", ".xcstrings"}
    )
    if len(resources) > MAX_LOCALIZATION_FILES:
        raise AdapterError("localization resources exceed the immutable file limit")
    return resources


def localization_resource_group(path: str) -> tuple[str, str]:
    parts = Path(path).parts
    for index, part in enumerate(parts):
        if part.lower().endswith(".lproj"):
            locale = part[:-6].strip()
            logical_parts = parts[:index] + parts[index + 1:]
            logical = "/".join(logical_parts) or Path(path).name
            return logical, locale or "default"
    return path, "default"


def parse_localization_json(data: bytes, label: str) -> Any:
    if len(data) > MAX_LOCALIZATION_FILE_BYTES:
        raise AdapterError(f"{label} exceeds the immutable byte limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, AdapterError) as error:
        raise AdapterError(f"{label} is malformed: {error}") from error


def quoted_localization_value(text: str, index: int, label: str) -> tuple[str, int]:
    if index >= len(text) or text[index] != '"':
        raise AdapterError(f"{label} has an invalid quoted string")
    index += 1
    characters: list[str] = []
    while index < len(text):
        character = text[index]
        index += 1
        if character == '"':
            return "".join(characters), index
        if character in "\r\n":
            raise AdapterError(f"{label} has an unterminated quoted string")
        if character != "\\":
            characters.append(character)
            continue
        if index >= len(text):
            raise AdapterError(f"{label} has an incomplete escape")
        escape = text[index]
        index += 1
        simple_escapes = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}
        if escape in simple_escapes:
            characters.append(simple_escapes[escape])
            continue
        width = 4 if escape == "u" else 8 if escape == "U" else 0
        if width:
            digits = text[index:index + width]
            if len(digits) != width or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                raise AdapterError(f"{label} has an invalid Unicode escape")
            codepoint = int(digits, 16)
            if codepoint > 0x10FFFF:
                raise AdapterError(f"{label} has an invalid Unicode code point")
            characters.append(chr(codepoint))
            index += width
            continue
        characters.append(escape)
    raise AdapterError(f"{label} has an unterminated quoted string")


def skip_localization_space(text: str, index: int, label: str) -> int:
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            index += 2
            depth = 1
            while index < len(text) and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise AdapterError(f"{label} has an unterminated comment")
            continue
        break
    return index


def parse_localization_strings(data: bytes, label: str) -> tuple[set[str], set[str]]:
    if len(data) > MAX_LOCALIZATION_FILE_BYTES:
        raise AdapterError(f"{label} exceeds the immutable byte limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError(f"{label} must be UTF-8 text") from error
    entries: dict[str, str] = {}
    index = 0
    while True:
        index = skip_localization_space(text, index, label)
        if index == len(text):
            break
        key, index = quoted_localization_value(text, index, label)
        if not key:
            raise AdapterError(f"{label} contains an empty localization key")
        if key in entries:
            raise AdapterError(f"{label} contains a duplicate localization key: {key}")
        index = skip_localization_space(text, index, label)
        if index >= len(text) or text[index] != "=":
            raise AdapterError(f"{label} is missing '=' after localization key")
        index = skip_localization_space(text, index + 1, label)
        value, index = quoted_localization_value(text, index, label)
        index = skip_localization_space(text, index, label)
        if index >= len(text) or text[index] != ";":
            raise AdapterError(f"{label} is missing ';' after localization value")
        entries[key] = value
        index += 1
        if len(entries) > MAX_LOCALIZATION_KEYS:
            raise AdapterError(f"{label} exceeds the immutable key limit")
    return set(entries), {key for key, value in entries.items() if not value.strip()}


def parse_localization_stringsdict(data: bytes, label: str) -> tuple[set[str], set[str]]:
    if len(data) > MAX_LOCALIZATION_FILE_BYTES:
        raise AdapterError(f"{label} exceeds the immutable byte limit")
    if data.lstrip().startswith(b"<"):
        try:
            xml_root = ElementTree.fromstring(data)
        except ElementTree.ParseError as error:
            raise AdapterError(f"{label} is malformed: {error}") from error

        def reject_duplicate_plist_keys(node: ElementTree.Element) -> None:
            if node.tag == "dict":
                children = list(node)
                keys = [child.text for child in children if child.tag == "key"]
                if len(keys) != len(set(keys)):
                    raise AdapterError(f"{label} contains duplicate stringsdict keys")
            for child in node:
                reject_duplicate_plist_keys(child)

        reject_duplicate_plist_keys(xml_root)
    try:
        value = plistlib.loads(data)
    except (ExpatError, plistlib.InvalidFileException, OverflowError, TypeError, ValueError) as error:
        raise AdapterError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict) or len(value) > MAX_LOCALIZATION_KEYS:
        raise AdapterError(f"{label} has an unsupported stringsdict shape")
    empty_keys: set[str] = set()
    for key, entry in value.items():
        if not isinstance(key, str) or not key:
            raise AdapterError(f"{label} has an invalid stringsdict key")
        format_value = entry.get("NSStringLocalizedFormatKey") if isinstance(entry, dict) else None
        if not isinstance(entry, dict) or not isinstance(format_value, str):
            raise AdapterError(f"{label} has an invalid localized format entry: {key}")
        if not format_value.strip():
            empty_keys.add(key)
        plural_entries = [
            child for child in entry.values()
            if isinstance(child, dict) and child.get("NSStringFormatSpecTypeKey") == "NSStringPluralRuleType"
        ]
        if not plural_entries:
            raise AdapterError(f"{label} has no plural rule entry: {key}")
        for plural_entry in plural_entries:
            categories = set(plural_entry) - {"NSStringFormatSpecTypeKey", "NSStringFormatValueTypeKey"}
            if not categories or any(not isinstance(plural_entry[category], str) for category in categories):
                raise AdapterError(f"{label} has an invalid plural category entry: {key}")
            if any(not plural_entry[category].strip() for category in categories):
                empty_keys.add(key)
    return {key for key in value if isinstance(key, str)}, empty_keys


def validate_xcstrings_node(node: Any, label: str, depth: int = 0) -> bool:
    if depth > MAX_LOCALIZATION_NESTING or not isinstance(node, dict):
        raise AdapterError(f"{label} has an unsupported xcstrings localization shape")
    if "stringUnit" in node:
        if set(node) != {"stringUnit"} or not isinstance(node["stringUnit"], dict):
            raise AdapterError(f"{label} has an unsupported xcstrings string unit")
        unit = node["stringUnit"]
        if set(unit) != {"state", "value"} or unit.get("state") not in {"translated", "needs_review", "new", "stale"}:
            raise AdapterError(f"{label} has an invalid xcstrings string unit")
        if not isinstance(unit.get("value"), str):
            raise AdapterError(f"{label} has an invalid xcstrings value")
        return bool(unit["value"].strip())
    if set(node) != {"variations"} or not isinstance(node.get("variations"), dict) or not node["variations"]:
        raise AdapterError(f"{label} has an unsupported xcstrings variation")
    has_nonempty_value = False
    for dimension, variants in node["variations"].items():
        if not isinstance(dimension, str) or not dimension or not isinstance(variants, dict) or not variants:
            raise AdapterError(f"{label} has an invalid xcstrings variation dimension")
        for variant, child in variants.items():
            if not isinstance(variant, str) or not variant:
                raise AdapterError(f"{label} has an invalid xcstrings variation key")
            has_nonempty_value = validate_xcstrings_node(child, label, depth + 1) or has_nonempty_value
    return has_nonempty_value


def parse_localization_xcstrings(data: bytes, path: str) -> tuple[set[str], list[dict[str, str]]]:
    value = parse_localization_json(data, path)
    if not isinstance(value, dict) or set(value) != {"sourceLanguage", "strings", "version"}:
        raise AdapterError(f"{path} has an unsupported xcstrings top-level shape")
    source_language = value["sourceLanguage"]
    strings = value["strings"]
    if not isinstance(source_language, str) or not source_language.strip() or not isinstance(value["version"], str):
        raise AdapterError(f"{path} has invalid xcstrings metadata")
    if not isinstance(strings, dict) or len(strings) > MAX_LOCALIZATION_KEYS:
        raise AdapterError(f"{path} exceeds the immutable xcstrings key limit")
    findings: list[dict[str, str]] = []
    keys: set[str] = set()
    for key, entry in strings.items():
        if not isinstance(key, str) or not key:
            raise AdapterError(f"{path} has an invalid xcstrings key")
        if not isinstance(entry, dict) or set(entry) - {"extractionState", "localizations"}:
            raise AdapterError(f"{path} has an unsupported xcstrings entry: {key}")
        localizations = entry.get("localizations")
        if not isinstance(localizations, dict) or len(localizations) > MAX_LOCALIZATION_LOCALES:
            raise AdapterError(f"{path} has an invalid xcstrings localization map: {key}")
        if source_language not in localizations:
            findings.append({"path": path, "message": f"xcstrings key has no source-language fallback: {key}"})
        for locale, node in localizations.items():
            if not isinstance(locale, str) or not locale:
                raise AdapterError(f"{path} has an invalid xcstrings locale: {key}")
            source_nonempty = validate_xcstrings_node(node, f"{path}:{key}:{locale}")
            if locale == source_language and not source_nonempty:
                findings.append({"path": path, "message": f"xcstrings source-language fallback is empty: {key}"})
        keys.add(key)
    return keys, findings


def findings_for_localization_catalog(root: Path, paths: list[str]) -> list[dict[str, str]]:
    resources = localization_paths(paths)
    groups: dict[str, dict[str, tuple[set[str], set[str]]]] = {}
    findings: list[dict[str, str]] = []
    total_bytes = 0
    for path in resources:
        data = bounded_process(root, ["show", f"HEAD:{path}"], MAX_LOCALIZATION_FILE_BYTES)
        total_bytes += len(data)
        if total_bytes > MAX_LOCALIZATION_TOTAL_BYTES:
            raise AdapterError("localization resources exceed the immutable aggregate byte limit")
        suffix = Path(path).suffix.lower()
        if suffix == ".strings":
            keys, empty = parse_localization_strings(data, path)
            group, locale = localization_resource_group(path)
            groups.setdefault(group, {})[locale] = (keys, empty)
        elif suffix == ".stringsdict":
            keys, empty = parse_localization_stringsdict(data, path)
            group, locale = localization_resource_group(path)
            groups.setdefault(group, {})[locale] = (keys, empty)
        else:
            _, xcstrings_findings = parse_localization_xcstrings(data, path)
            findings.extend(xcstrings_findings)
            if len(findings) >= MAX_FINDINGS:
                return findings[:MAX_FINDINGS]

    for group, locales in groups.items():
        if len(locales) > MAX_LOCALIZATION_LOCALES:
            raise AdapterError(f"localization resource group exceeds the locale limit: {group}")
        all_keys = set().union(*(facts[0] for facts in locales.values()))
        fallback_locale = next(
            (locale for locale in locales if locale.lower() in {"base", "en"}),
            sorted(locales)[0],
        )
        for locale, (keys, empty) in sorted(locales.items()):
            missing = sorted(all_keys - keys)
            extra = sorted(keys - all_keys)
            if missing or extra:
                detail = []
                if missing:
                    detail.append(f"missing {', '.join(missing[:8])}")
                if extra:
                    detail.append(f"unexpected {', '.join(extra[:8])}")
                findings.append({
                    "path": group,
                    "message": f"Locale {locale} does not match localization key parity ({'; '.join(detail)}).",
                })
            if locale == fallback_locale:
                for key in sorted(empty):
                    findings.append({
                        "path": group,
                        "message": f"Fallback localization value is empty: {key}",
                    })
            if len(findings) >= MAX_FINDINGS:
                return findings[:MAX_FINDINGS]
    return findings


def resource_catalog_root(path: str) -> str | None:
    components = path.split("/")
    for index, component in enumerate(components):
        if component.lower().endswith(".xcassets"):
            return "/".join(components[:index + 1])
    return None


def resource_catalog_roots(paths: list[str]) -> list[str]:
    roots = {root for path in paths if (root := resource_catalog_root(path)) is not None}
    if len(roots) > MAX_RESOURCE_CATALOGS:
        raise AdapterError("asset catalogs exceed the immutable catalog limit")
    return sorted(roots)


def resource_asset_set_path(path: str, root: str) -> str | None:
    if path == root or not path.startswith(root + "/"):
        return None
    relative_components = path[len(root) + 1:].split("/")
    current: list[str] = []
    for component in relative_components[:-1]:
        current.append(component)
        if component.lower().endswith(ASSET_SET_SUFFIXES):
            return root + "/" + "/".join(current)
    return None


def resource_asset_set_name(path: str) -> tuple[str, str]:
    name = path.rsplit("/", 1)[-1]
    for suffix in sorted(ASSET_SET_SUFFIXES, key=len, reverse=True):
        if name.lower().endswith(suffix):
            return name[:-len(suffix)], suffix
    return name, ""


def validate_resource_json(value: Any, label: str, depth: int = 0) -> int:
    if depth > MAX_LOCALIZATION_NESTING:
        raise AdapterError(f"{label} exceeds the immutable JSON nesting limit")
    if isinstance(value, dict):
        if len(value) > MAX_RESOURCE_JSON_NODES:
            raise AdapterError(f"{label} exceeds the immutable JSON object limit")
        count = 1
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > MAX_STRING_LENGTH:
                raise AdapterError(f"{label} has an invalid JSON property name")
            count += validate_resource_json(child, label, depth + 1)
            if count > MAX_RESOURCE_JSON_NODES:
                raise AdapterError(f"{label} exceeds the immutable JSON node limit")
        return count
    if isinstance(value, list):
        if len(value) > MAX_RESOURCE_JSON_NODES:
            raise AdapterError(f"{label} exceeds the immutable JSON array limit")
        count = 1
        for child in value:
            count += validate_resource_json(child, label, depth + 1)
            if count > MAX_RESOURCE_JSON_NODES:
                raise AdapterError(f"{label} exceeds the immutable JSON node limit")
        return count
    if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        raise AdapterError(f"{label} contains an oversized JSON string")
    if value is None or isinstance(value, (bool, int, float, str)):
        return 1
    raise AdapterError(f"{label} contains an unsupported JSON value")


def parse_resource_contents(data: bytes, label: str) -> list[str]:
    if len(data) > MAX_RESOURCE_CONTENTS_BYTES:
        raise AdapterError(f"{label} exceeds the immutable byte limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, AdapterError) as error:
        raise AdapterError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must have a JSON object root")
    validate_resource_json(value, label)
    for key in RESOURCE_JSON_ARRAY_KEYS:
        if key in value and not isinstance(value[key], list):
            raise AdapterError(f"{label} has an invalid {key} array")
    if "info" in value and not isinstance(value["info"], dict):
        raise AdapterError(f"{label} has an invalid info object")

    filenames: list[str] = []

    def collect(node: Any) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "filename":
                    if not isinstance(child, str) or not child.strip():
                        raise AdapterError(f"{label} has an invalid filename reference")
                    filenames.append(child)
                    if len(filenames) > MAX_RESOURCE_REFERENCES:
                        raise AdapterError(f"{label} exceeds the immutable filename reference limit")
                collect(child)
        elif isinstance(node, list):
            for child in node:
                collect(child)

    collect(value)
    return filenames


def resource_filename_target(contents_path: str, filename: str) -> str:
    if (
        not filename
        or len(filename) > MAX_STRING_LENGTH
        or filename.startswith(("/", "~"))
        or "\\" in filename
    ):
        raise AdapterError(f"{contents_path} has an unsafe filename reference")
    components = filename.split("/")
    if any(not component or component in {".", ".."} for component in components):
        raise AdapterError(f"{contents_path} has a traversal or empty filename reference")
    parent = contents_path.rsplit("/", 1)[0] if "/" in contents_path else ""
    return "/".join([component for component in (parent, *components) if component])


def resource_file_stem(path: str) -> str:
    basename = path.rsplit("/", 1)[-1]
    stem = basename.rsplit(".", 1)[0] if "." in basename else basename
    return re.sub(r"@[23]x$", "", stem, flags=re.IGNORECASE)


def resource_source_references(root: Path, paths: list[str]) -> list[tuple[str, str, str]]:
    references: list[tuple[str, str, str]] = []
    source_paths = {
        path for path in paths
        if Path(path).suffix.lower() in RESOURCE_SOURCE_SUFFIXES
        and not ({component.lower() for component in path.split("/")} & RESOURCE_SOURCE_EXCLUDED_COMPONENTS)
    }
    if len(source_paths) > MAX_RESOURCE_SOURCE_FILES:
        raise AdapterError("resource reference sources exceed the immutable file limit")
    if not source_paths:
        return references
    output = bounded_process(
        root,
        [
            "grep", "-l", "-I", "-E", "-e", RESOURCE_REFERENCE_SEARCH_PATTERN,
            "HEAD", "--",
            "*.swift", "*.m", "*.mm", "*.h", "*.storyboard", "*.xib",
            ":(exclude)**/Tests/**", ":(exclude)**/UITests/**", ":(exclude)**/tests/**",
            ":(exclude)**/uitests/**", ":(exclude)**/Fixtures/**", ":(exclude)**/fixtures/**",
            ":(exclude)docs/**", ":(exclude).quality-control/**",
        ],
        MAX_GREP_OUTPUT_BYTES,
        allowed_returncodes={0, 1},
    )
    try:
        candidate_paths = {
            line.removeprefix("HEAD:")
            for line in output.decode("utf-8").splitlines()
            if line
        }
    except UnicodeDecodeError as error:
        raise AdapterError("resource reference search returned non-UTF-8 output") from error
    if not candidate_paths.issubset(source_paths):
        raise AdapterError("resource reference search returned an unexpected source path")
    if len(candidate_paths) > MAX_RESOURCE_SOURCE_FILES:
        raise AdapterError("resource reference sources exceed the immutable file limit")
    total_bytes = 0
    for path in sorted(candidate_paths):
        data = bounded_process(root, ["show", f"HEAD:{path}"], MAX_RESOURCE_SOURCE_BYTES)
        total_bytes += len(data)
        if total_bytes > MAX_RESOURCE_TOTAL_BYTES:
            raise AdapterError("resource reference sources exceed the immutable aggregate byte limit")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AdapterError(f"resource reference source must be UTF-8 text: {path}") from error
        for kind, pattern in RESOURCE_REFERENCE_PATTERNS:
            for match in pattern.finditer(text):
                references.append((path, kind, match.group("name")))
                if len(references) > MAX_RESOURCE_REFERENCES:
                    raise AdapterError("resource references exceed the immutable reference limit")
    return references


def findings_for_resource_assets(root: Path, paths: list[str]) -> list[dict[str, str]]:
    entries = tracked_tree_entries(root)
    findings: list[dict[str, str]] = []

    def add_finding(path: str, message: str) -> bool:
        findings.append({"path": path, "message": message})
        return len(findings) < MAX_FINDINGS

    forbidden_suffixes = tuple(suffix.lower() for suffix in RESOURCE_BINARY_OUTPUT_SUFFIXES)
    for path in paths:
        if any(component.lower().endswith(forbidden) for component in path.split("/") for forbidden in forbidden_suffixes):
            if not add_finding(path, "Tracked build or release binary output must not be committed as a resource."):
                return findings[:MAX_FINDINGS]

    roots = resource_catalog_roots(paths)
    image_names: set[str] = set()
    color_names: set[str] = set()
    data_names: set[str] = set()
    referenced_paths: set[str] = set()
    total_bytes = 0
    contents_count = 0

    for root_path in roots:
        if root_path in entries:
            raise AdapterError(f"asset catalog path is a tracked file, not a directory: {root_path}")
        catalog_prefix = root_path + "/"
        catalog_files = [path for path in paths if path.startswith(catalog_prefix)]
        set_paths = sorted({
            set_path for path in catalog_files
            if (set_path := resource_asset_set_path(path, root_path)) is not None
        })
        root_contents = root_path + "/Contents.json"
        if root_contents not in entries:
            if not add_finding(root_path, "Asset catalog is missing its root Contents.json metadata."):
                return findings[:MAX_FINDINGS]

        contents_paths = [path for path in catalog_files if path.rsplit("/", 1)[-1] == "Contents.json"]
        contents_count += len(contents_paths)
        if contents_count > MAX_RESOURCE_CONTENTS_FILES:
            raise AdapterError("asset catalog Contents.json files exceed the immutable file limit")

        for set_path in set_paths:
            if set_path in entries:
                raise AdapterError(f"asset set path is a tracked file, not a directory: {set_path}")
            name, suffix = resource_asset_set_name(set_path)
            if not name:
                raise AdapterError(f"asset set has an empty logical name: {set_path}")
            if suffix == ".colorset":
                color_names.add(name)
            elif suffix == ".dataset":
                data_names.add(name)
            else:
                image_names.add(name)
            expected_contents = set_path + "/Contents.json"
            if expected_contents not in entries:
                if not add_finding(set_path, "Asset set is missing its Contents.json metadata."):
                    return findings[:MAX_FINDINGS]

        for contents_path in sorted(contents_paths):
            if entries.get(contents_path) not in {"100644", "100755"}:
                raise AdapterError(f"asset metadata path is not a regular file: {contents_path}")
            data = bounded_process(root, ["show", f"HEAD:{contents_path}"], MAX_RESOURCE_CONTENTS_BYTES)
            total_bytes += len(data)
            if total_bytes > MAX_RESOURCE_TOTAL_BYTES:
                raise AdapterError("asset resources exceed the immutable aggregate byte limit")
            filenames = parse_resource_contents(data, contents_path)
            for filename in filenames:
                target = resource_filename_target(contents_path, filename)
                if target in referenced_paths:
                    if not add_finding(contents_path, f"Asset filename is referenced more than once: {filename}"):
                        return findings[:MAX_FINDINGS]
                referenced_paths.add(target)
                mode = entries.get(target)
                if mode is None:
                    if not add_finding(contents_path, f"Asset filename is missing from Git HEAD: {filename}"):
                        return findings[:MAX_FINDINGS]
                elif mode not in {"100644", "100755"}:
                    raise AdapterError(f"asset filename resolves to a non-regular path: {target}")

        for path in catalog_files:
            if path.rsplit("/", 1)[-1] == "Contents.json":
                continue
            mode = entries.get(path)
            if mode not in {"100644", "100755"}:
                raise AdapterError(f"asset catalog contains an unsupported non-regular path: {path}")
            if path not in referenced_paths:
                if not add_finding(path, "Tracked asset file is not referenced by any Contents.json metadata."):
                    return findings[:MAX_FINDINGS]

    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix in RESOURCE_IMAGE_FILE_SUFFIXES:
            image_names.add(resource_file_stem(path))
        elif suffix in RESOURCE_DATA_FILE_SUFFIXES:
            data_names.add(resource_file_stem(path))

    for path, kind, name in resource_source_references(root, paths):
        if not name:
            if not add_finding(path, f"{kind} has an empty literal resource name."):
                return findings[:MAX_FINDINGS]
            continue
        candidates = color_names if kind == "Color" else data_names if kind == "NSDataAsset" else image_names
        if name not in candidates:
            if not add_finding(path, f"{kind} references a missing local resource: {name}"):
                return findings[:MAX_FINDINGS]
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
        if arguments.check == "QC.LOCALIZATION.CATALOG":
            findings = findings_for_localization_catalog(root, paths)
            if findings:
                result = report(
                    arguments.check,
                    revision,
                    "FAIL",
                    "Localization resources are malformed, incomplete, or missing fallback coverage.",
                    findings,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 1
            result = report(
                arguments.check,
                revision,
                "PASS",
                "Tracked localization resources are valid and have consistent key/fallback coverage.",
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.check == "QC.RESOURCES.ASSETS":
            findings = findings_for_resource_assets(root, paths)
            if findings:
                result = report(
                    arguments.check,
                    revision,
                    "FAIL",
                    "Asset catalogs, resource references, or tracked resource binaries are invalid.",
                    findings,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 1
            result = report(
                arguments.check,
                revision,
                "PASS",
                "Asset catalogs and statically discoverable resource references are valid.",
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
