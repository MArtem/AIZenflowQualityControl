#!/usr/bin/env python3
"""Bounded, repository-neutral deterministic check adapters.

The adapter reads only the authenticated Git HEAD of a clean checkout. It never writes the
repository, never treats an unavailable adapter as PASS, and keeps the catalog as the policy
authority. The initial adapter intentionally covers only high-confidence tracked credentials;
broader secret heuristics require separate fixtures and review.
"""

from __future__ import annotations

import argparse
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
SECRET_PATH_SUFFIXES = (".p12", ".pfx", ".mobileprovision")
SECRET_MARKER = re.compile(
    r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
    r"(ghp_|github_pat_|xox[baprs]-|sk_live_|AKIA[0-9A-Z]{16})"
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
        raise AdapterError(f"no executable adapter is registered for {arguments.check}")
    except AdapterError as error:
        result = report(arguments.check, "", "BLOCKED", str(error))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
