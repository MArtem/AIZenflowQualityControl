#!/usr/bin/env python3
"""Inventory and dry-run planner for the app-owned quality-control consumer layer.

The plan is declarative so reusable policy and project facts stay in their canonical owners. This
module never writes a project: it reports missing, exact, overlay, symlink, and conflict states for
an explicit source/destination plan. Applying a plan remains a separate, user-authorized phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


MAX_PLAN_BYTES = 1_000_000
MAX_ENTRIES = 256
MAX_STRING_LENGTH = 1_024
ALLOWED_KINDS = {"exact", "overlay"}


class PlanError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PlanError(f"plan is unreadable: {error}") from error
    if len(data) > MAX_PLAN_BYTES:
        raise PlanError("plan exceeds the immutable byte limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, PlanError) as error:
        raise PlanError(f"plan is malformed: {error}") from error
    if not isinstance(value, dict):
        raise PlanError("plan root must be an object")
    return value


def bounded_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_STRING_LENGTH:
        raise PlanError(f"{name} must be a non-empty bounded string")
    return value


def relative_path(value: Any, name: str) -> str:
    candidate = Path(bounded_string(value, name))
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise PlanError(f"{name} must be a normalized repository-relative path")
    return candidate.as_posix()


def contained(root: Path, relative: str) -> Path:
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise PlanError(f"path escapes its root: {relative}") from error
    return candidate


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_entries(plan: dict[str, Any]) -> list[dict[str, str]]:
    allowed = {"schemaVersion", "entries"}
    unknown = set(plan) - allowed
    if unknown:
        raise PlanError(f"unknown plan properties: {', '.join(sorted(unknown))}")
    if plan.get("schemaVersion") != 1:
        raise PlanError("only plan schemaVersion 1 is supported")
    entries = plan.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES:
        raise PlanError(f"entries must contain 1..{MAX_ENTRIES} items")

    parsed: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    seen_destinations: set[str] = set()
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            raise PlanError(f"entry {index} must be an object")
        if set(raw) != {"id", "source", "destination", "kind"}:
            raise PlanError(f"entry {index} has an invalid property set")
        entry_id = bounded_string(raw["id"], f"entry {index} id")
        source = relative_path(raw["source"], f"entry {index} source")
        destination = relative_path(raw["destination"], f"entry {index} destination")
        kind = bounded_string(raw["kind"], f"entry {index} kind")
        if kind not in ALLOWED_KINDS:
            raise PlanError(f"entry {index} kind must be exact or overlay")
        if entry_id in seen_ids or destination in seen_destinations:
            raise PlanError("entry ids and destinations must be unique")
        seen_ids.add(entry_id)
        seen_destinations.add(destination)
        parsed.append({"id": entry_id, "source": source, "destination": destination, "kind": kind})
    return sorted(parsed, key=lambda entry: (entry["destination"], entry["id"]))


def inspect_entry(
    entry: dict[str, str],
    baseline_root: Path,
    project_root: Path,
) -> dict[str, Any]:
    source = contained(baseline_root, entry["source"])
    destination = contained(project_root, entry["destination"])
    result: dict[str, Any] = {
        "id": entry["id"],
        "source": entry["source"],
        "destination": entry["destination"],
        "kind": entry["kind"],
    }
    if source.is_symlink() or not source.is_file():
        result.update({"state": "BLOCKED", "action": "none", "reason": "source is not a regular file"})
        return result
    result["sourceSHA256"] = digest(source)
    if destination.is_symlink():
        result.update({"state": "CONFLICT", "action": "none", "reason": "destination is a symlink"})
        return result
    if not destination.exists():
        action = "create" if entry["kind"] == "exact" else "review-overlay"
        result.update({"state": "MISSING", "action": action})
        return result
    if not destination.is_file():
        result.update({"state": "CONFLICT", "action": "none", "reason": "destination is not a regular file"})
        return result
    result["destinationSHA256"] = digest(destination)
    if destination.read_bytes() == source.read_bytes():
        result.update({"state": "EXACT", "action": "keep"})
    elif entry["kind"] == "overlay":
        result.update({"state": "OVERLAY_PRESENT", "action": "review-overlay"})
    else:
        result.update({"state": "CONFLICT", "action": "none", "reason": "exact file differs"})
    return result


def run(mode: str, plan_path: Path, baseline_root: Path, project_root: Path) -> tuple[int, dict[str, Any]]:
    try:
        plan = load_json(plan_path)
        entries = parse_entries(plan)
        baseline = baseline_root.resolve(strict=True)
        project = project_root.resolve(strict=True)
        if not baseline.is_dir() or not project.is_dir():
            raise PlanError("baseline and project roots must be directories")
        inventory = [inspect_entry(entry, baseline, project) for entry in entries]
    except (OSError, PlanError) as error:
        return 2, {
            "schemaVersion": 1,
            "command": mode,
            "status": "BLOCKED",
            "error": str(error),
            "entries": [],
            "apply": {"implemented": False, "requiredAuthorization": "USER"},
        }

    states = {entry["state"] for entry in inventory}
    if "BLOCKED" in states:
        status = "BLOCKED"
        exit_code = 2
    elif "CONFLICT" in states or "OVERLAY_PRESENT" in states:
        status = "REVIEW_REQUIRED"
        exit_code = 1 if mode == "dry-run" else 0
    else:
        status = "READY"
        exit_code = 0
    return exit_code, {
        "schemaVersion": 1,
        "command": mode,
        "status": status,
        "entries": inventory,
        "apply": {"implemented": False, "requiredAuthorization": "USER"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["inventory", "dry-run"])
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--baseline-root", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    exit_code, report = run(
        args.mode,
        args.plan,
        args.baseline_root,
        args.project_root,
    )
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
