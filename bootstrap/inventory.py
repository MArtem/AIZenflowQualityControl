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
import os
import sys
from pathlib import Path
from typing import Any


MAX_PLAN_BYTES = 1_000_000
MAX_ENTRIES = 256
MAX_STRING_LENGTH = 1_024
MAX_FILE_BYTES = 5_000_000
ALLOWED_KINDS = {"exact", "overlay"}
APPLY_AUTHORIZATION = "APPLY"
ROLLBACK_AUTHORIZATION = "ROLLBACK"


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
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise PlanError("file exceeds the immutable byte limit")
    except OSError:
        raise
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


def build_inventory(plan_path: Path, baseline_root: Path, project_root: Path) -> tuple[list[dict[str, Any]], Path, Path]:
    plan = load_json(plan_path)
    entries = parse_entries(plan)
    baseline = baseline_root.resolve(strict=True)
    project = project_root.resolve(strict=True)
    if not baseline.is_dir() or not project.is_dir():
        raise PlanError("baseline and project roots must be directories")
    return [inspect_entry(entry, baseline, project) for entry in entries], baseline, project


def status_for_inventory(inventory: list[dict[str, Any]], mode: str) -> tuple[str, int]:
    states = {entry["state"] for entry in inventory}
    if "BLOCKED" in states:
        return "BLOCKED", 2
    if "CONFLICT" in states or "OVERLAY_PRESENT" in states:
        return "REVIEW_REQUIRED", 1 if mode == "dry-run" else 0
    return "READY", 0


def base_report(mode: str, status: str, inventory: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "command": mode,
        "status": status,
        "entries": inventory,
        "apply": {
            "implemented": True,
            "requiredAuthorization": "USER",
            "commands": ["apply", "post-check", "rollback"],
        },
    }
    report.update(extra)
    return report


def journal_relative_path(value: Any) -> str:
    if isinstance(value, Path):
        value = value.as_posix()
    return relative_path(value, "journal")


def safe_parent_directories(project_root: Path, destination: str) -> list[str]:
    current = project_root
    created: list[str] = []
    parts = Path(destination).parts[:-1]
    relative_parts: list[str] = []
    for part in parts:
        relative_parts.append(part)
        current = current / part
        if current.is_symlink():
            raise PlanError(f"destination parent is a symlink: {Path(*relative_parts).as_posix()}")
        if current.exists():
            if not current.is_dir():
                raise PlanError(f"destination parent is not a directory: {Path(*relative_parts).as_posix()}")
            continue
        current.mkdir()
        created.append(Path(*relative_parts).as_posix())
    return created


def create_regular_file(destination: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_new_journal(path: Path, journal: dict[str, Any]) -> None:
    encoded = (json.dumps(journal, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_PLAN_BYTES:
        raise PlanError("journal exceeds the immutable byte limit")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def revert_created(project_root: Path, created: list[dict[str, str]], directories: list[str]) -> None:
    for entry in reversed(created):
        destination = contained(project_root, entry["destination"])
        if destination.is_symlink() or not destination.is_file():
            continue
        if digest(destination) == entry["createdSHA256"]:
            destination.unlink()
    for relative in sorted(directories, key=lambda value: len(Path(value).parts), reverse=True):
        directory = contained(project_root, relative)
        if directory.is_symlink() or not directory.is_dir():
            continue
        try:
            directory.rmdir()
        except OSError:
            pass


def load_journal(path: Path) -> dict[str, Any]:
    journal = load_json(path)
    if set(journal) != {"schemaVersion", "command", "planSHA256", "entries", "directories"}:
        raise PlanError("journal has an invalid property set")
    if journal["schemaVersion"] != 1 or journal["command"] != "apply-journal":
        raise PlanError("journal schema or command is unsupported")
    plan_hash = bounded_string(journal["planSHA256"], "journal planSHA256")
    if len(plan_hash) != 64 or any(character not in "0123456789abcdef" for character in plan_hash):
        raise PlanError("journal planSHA256 must be lowercase hexadecimal")
    entries = journal["entries"]
    directories = journal["directories"]
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise PlanError("journal entries exceed the immutable limit")
    if not isinstance(directories, list) or len(directories) > MAX_ENTRIES:
        raise PlanError("journal directories exceed the immutable limit")
    seen_ids: set[str] = set()
    seen_destinations: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"id", "destination", "createdSHA256"}:
            raise PlanError(f"journal entry {index} is malformed")
        entry_id = bounded_string(entry["id"], f"journal entry {index} id")
        destination = relative_path(entry["destination"], f"journal entry {index} destination")
        if entry_id in seen_ids or destination in seen_destinations:
            raise PlanError("journal entry ids and destinations must be unique")
        seen_ids.add(entry_id)
        seen_destinations.add(destination)
        created_hash = bounded_string(entry["createdSHA256"], f"journal entry {index} createdSHA256")
        if len(created_hash) != 64 or any(character not in "0123456789abcdef" for character in created_hash):
            raise PlanError(f"journal entry {index} hash is invalid")
    seen_directories: set[str] = set()
    for index, directory in enumerate(directories):
        normalized = relative_path(directory, f"journal directory {index}")
        if normalized in seen_directories:
            raise PlanError("journal directories must be unique")
        seen_directories.add(normalized)
    return journal


def run_apply(plan_path: Path, baseline_root: Path, project_root: Path, journal_path: Path | None, authorization: str | None) -> tuple[int, dict[str, Any]]:
    try:
        inventory, baseline, project = build_inventory(plan_path, baseline_root, project_root)
        status, _ = status_for_inventory(inventory, "dry-run")
        if status != "READY":
            return 1 if status == "REVIEW_REQUIRED" else 2, base_report("apply", status, inventory)
        if authorization != APPLY_AUTHORIZATION:
            return 2, base_report("apply", "BLOCKED", inventory, error="explicit --authorize APPLY is required")
        if journal_path is None:
            raise PlanError("apply requires --journal")
        journal_relative = journal_relative_path(journal_path)
        journal = contained(project, journal_relative)
        if journal.exists() or journal.is_symlink():
            raise PlanError("journal destination already exists")
        created: list[dict[str, str]] = []
        created_directories: list[str] = []
        for entry in inventory:
            if entry["state"] == "EXACT":
                continue
            if entry["state"] != "MISSING" or entry["kind"] != "exact":
                raise PlanError("apply can create only missing exact entries")
            source = contained(baseline, entry["source"])
            destination = contained(project, entry["destination"])
            created_directories.extend(safe_parent_directories(project, entry["destination"]))
            data = source.read_bytes()
            create_regular_file(destination, data)
            created_hash = digest(destination)
            if created_hash != entry["sourceSHA256"]:
                raise PlanError("created file digest did not match the source snapshot")
            created.append({"id": entry["id"], "destination": entry["destination"], "createdSHA256": created_hash})
        created_directories.extend(safe_parent_directories(project, journal_relative))
        journal_document = {
            "schemaVersion": 1,
            "command": "apply-journal",
            "planSHA256": digest(plan_path),
            "entries": created,
            "directories": sorted(set(created_directories)),
        }
        write_new_journal(journal, journal_document)
        return 0, base_report("apply", "READY", inventory, journal=journal_relative, created=created, createdDirectories=journal_document["directories"])
    except (OSError, PlanError) as error:
        if "created" in locals():
            try:
                revert_created(project, created, created_directories)
            except (OSError, PlanError):
                pass
        return 2, base_report("apply", "BLOCKED", [], error=str(error))


def run_post_check(plan_path: Path, baseline_root: Path, project_root: Path, journal_path: Path | None) -> tuple[int, dict[str, Any]]:
    try:
        inventory, _, project = build_inventory(plan_path, baseline_root, project_root)
        if journal_path is None:
            raise PlanError("post-check requires --journal")
        journal_relative = journal_relative_path(journal_path)
        document = load_journal(contained(project, journal_relative))
        if document["planSHA256"] != digest(plan_path):
            raise PlanError("journal does not match the supplied plan")
        by_destination = {entry["destination"]: entry for entry in inventory}
        checked: list[dict[str, str]] = []
        for record in document["entries"]:
            current = by_destination.get(record["destination"])
            if current is None or current["kind"] != "exact" or current["state"] != "EXACT" \
                    or current.get("sourceSHA256") != record["createdSHA256"] \
                    or current.get("destinationSHA256") != record["createdSHA256"]:
                raise PlanError(f"post-check failed for {record['destination']}")
            checked.append({"id": record["id"], "destination": record["destination"], "state": "EXACT"})
        return 0, base_report("post-check", "READY", inventory, journal=journal_relative, checked=checked)
    except (OSError, PlanError) as error:
        return 2, base_report("post-check", "BLOCKED", [], error=str(error))


def run_rollback(plan_path: Path, baseline_root: Path, project_root: Path, journal_path: Path | None, authorization: str | None) -> tuple[int, dict[str, Any]]:
    try:
        inventory, _, project = build_inventory(plan_path, baseline_root, project_root)
        if journal_path is None:
            raise PlanError("rollback requires --journal")
        if authorization != ROLLBACK_AUTHORIZATION:
            raise PlanError("explicit --authorize ROLLBACK is required")
        journal_relative = journal_relative_path(journal_path)
        document = load_journal(contained(project, journal_relative))
        if document["planSHA256"] != digest(plan_path):
            raise PlanError("journal does not match the supplied plan")
        by_destination = {entry["destination"]: entry for entry in inventory}
        recorded_destinations = {record["destination"] for record in document["entries"]}
        for record in document["entries"]:
            current = by_destination.get(record["destination"])
            if current is None or current["kind"] != "exact" or current.get("sourceSHA256") != record["createdSHA256"]:
                raise PlanError(f"journal entry is not bound to an exact plan source: {record['destination']}")
        journal_parent_paths = {parent.as_posix() for parent in Path(journal_relative).parents}
        for directory in document["directories"]:
            if directory in journal_parent_paths:
                continue
            if not any(directory in {parent.as_posix() for parent in Path(destination).parents} for destination in recorded_destinations):
                raise PlanError(f"journal directory is not bound to a created destination: {directory}")
        actions: list[dict[str, str]] = []
        for record in document["entries"]:
            destination = contained(project, record["destination"])
            if destination.is_symlink():
                raise PlanError(f"rollback refuses a symlink destination: {record['destination']}")
            if not destination.exists():
                actions.append({"id": record["id"], "destination": record["destination"], "action": "already-absent"})
                continue
            if not destination.is_file() or digest(destination) != record["createdSHA256"]:
                raise PlanError(f"rollback refuses a changed destination: {record['destination']}")
            destination.unlink()
            actions.append({"id": record["id"], "destination": record["destination"], "action": "removed"})
        for relative in sorted(document["directories"], key=lambda value: len(Path(value).parts), reverse=True):
            if relative in journal_parent_paths:
                actions.append({"id": relative, "destination": relative, "action": "preserved-journal-container"})
                continue
            directory = contained(project, relative)
            if directory.is_symlink():
                raise PlanError(f"rollback refuses a symlink directory: {relative}")
            if directory.is_dir():
                try:
                    directory.rmdir()
                    actions.append({"id": relative, "destination": relative, "action": "removed-directory"})
                except OSError as error:
                    raise PlanError(f"rollback preserved non-empty directory: {relative}") from error
        return 0, base_report("rollback", "READY", [], journal=journal_relative, actions=actions)
    except (OSError, PlanError) as error:
        return 2, base_report("rollback", "BLOCKED", [], error=str(error))


def run(mode: str, plan_path: Path, baseline_root: Path, project_root: Path) -> tuple[int, dict[str, Any]]:
    try:
        inventory, _, _ = build_inventory(plan_path, baseline_root, project_root)
    except (OSError, PlanError) as error:
        return 2, {
            "schemaVersion": 1,
            "command": mode,
            "status": "BLOCKED",
            "error": str(error),
            "entries": [],
            "apply": {"implemented": True, "requiredAuthorization": "USER", "commands": ["apply", "post-check", "rollback"]},
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
        "apply": {"implemented": True, "requiredAuthorization": "USER", "commands": ["apply", "post-check", "rollback"]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["inventory", "dry-run", "apply", "post-check", "rollback"])
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--baseline-root", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--authorize")
    args = parser.parse_args()

    if args.mode == "apply":
        exit_code, report = run_apply(args.plan, args.baseline_root, args.project_root, args.journal, args.authorize)
    elif args.mode == "post-check":
        exit_code, report = run_post_check(args.plan, args.baseline_root, args.project_root, args.journal)
    elif args.mode == "rollback":
        exit_code, report = run_rollback(args.plan, args.baseline_root, args.project_root, args.journal, args.authorize)
    else:
        exit_code, report = run(args.mode, args.plan, args.baseline_root, args.project_root)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
