"""Collision detection for a proposed plan.

Pure functions over in-memory operations and a snapshot of the TARGET inventory;
nothing here touches the filesystem.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from migrator import constants as C
from migrator.models import PlanOp

# blocker priority: the first matching code becomes `blocker_code`
PRIORITY = ["TARGET_EXISTS_DIFFERENT_CONTENT", "TARGET_PATH_IS_DIRECTORY", "TARGET_PARENT_IS_FILE",
            "TARGET_PATH_COLLISION", "TARGET_ALREADY_IDENTICAL", "CASEFOLD_TARGET_COLLISION"]

_POLICY_KEY = {
    "TARGET_PATH_COLLISION": "exact_path_collision",
    "CASEFOLD_TARGET_COLLISION": "casefold_path_collision",
    "TARGET_ALREADY_IDENTICAL": "existing_target_same_hash",
    "TARGET_EXISTS_DIFFERENT_CONTENT": "existing_target_different_hash",
}


@dataclass
class TargetIndex:
    """Snapshot of the TARGET inventory (files with hashes, and directories)."""

    files: dict[str, tuple[str | None, str]] = field(default_factory=dict)  # path -> (sha256, hash_status)
    dirs: set[str] = field(default_factory=set)
    _fold: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_file(self, path: str, sha256: str | None, hash_status: str) -> None:
        self.files[path] = (sha256, hash_status)
        self._fold[path.casefold()].add(path)

    def add_dir(self, path: str) -> None:
        self.dirs.add(path)

    def casefold_matches(self, path: str) -> set[str]:
        return self._fold.get(path.casefold(), set()) - {path}


def _ancestors(path: str, stop: str | None = None) -> Iterable[str]:
    p = os.path.dirname(path)
    while p and p != os.path.dirname(p):
        yield p
        p = os.path.dirname(p)


def _status(policy: dict[str, str], code: str) -> str:
    if code in ("TARGET_PATH_IS_DIRECTORY", "TARGET_PARENT_IS_FILE"):
        return C.PLAN_BLOCKED
    return C.PLAN_BLOCKED if policy[_POLICY_KEY[code]] == "block" else C.PLAN_REVIEW


def detect_collisions(ops: list[PlanOp], index: TargetIndex, policy: dict[str, str]) -> dict[str, int]:
    """Downgrade colliding READY operations in place.  Returns per-code counts.

    Never resolves a collision automatically and never proposes an overwrite.
    """
    ready = [o for o in ops if o.plan_status == C.PLAN_READY_STATUS and o.target_absolute_path]
    codes: dict[str, dict[str, object]] = defaultdict(dict)   # op_id -> {code: details}

    by_path: dict[str, list[PlanOp]] = defaultdict(list)
    by_fold: dict[str, dict[str, list[PlanOp]]] = defaultdict(lambda: defaultdict(list))
    for o in ready:
        by_path[o.target_absolute_path].append(o)
        by_fold[o.target_absolute_path.casefold()][o.target_absolute_path].append(o)

    # 1. two planned sources map to the exact same target path
    for path, group in by_path.items():
        if len(group) > 1:
            for o in group:
                codes[o.operation_id]["TARGET_PATH_COLLISION"] = {
                    "target": path,
                    "other_sources": sorted(x.source_absolute_path for x in group if x is not o)[:20]}

    # 2. a planned target is also a directory needed by another planned target
    needed_dirs: dict[str, PlanOp] = {}
    for o in ready:
        for a in _ancestors(o.target_absolute_path):
            needed_dirs.setdefault(a, o)
    for path, group in by_path.items():
        if path in needed_dirs:
            other = needed_dirs[path]
            for o in group:
                codes[o.operation_id]["TARGET_PATH_COLLISION"] = {
                    "target": path, "conflict": "file target is also a directory for another operation",
                    "other_source": other.source_absolute_path}
            codes[other.operation_id]["TARGET_PATH_COLLISION"] = {
                "target": other.target_absolute_path, "conflict": f"{path} is also planned as a file"}

    # 3. against the existing TARGET inventory
    for o in ready:
        t = o.target_absolute_path
        if t in index.dirs:
            codes[o.operation_id]["TARGET_PATH_IS_DIRECTORY"] = {"target": t}
        existing = index.files.get(t)
        if existing is not None:
            sha, hstatus = existing
            same = sha is not None and hstatus == C.HASH_HASHED and sha == o.expected_sha256
            codes[o.operation_id]["TARGET_ALREADY_IDENTICAL" if same else "TARGET_EXISTS_DIFFERENT_CONTENT"] = {
                "target": t, "existing_sha256": sha, "expected_sha256": o.expected_sha256}
        for a in _ancestors(t):
            if a in index.files:
                codes[o.operation_id]["TARGET_PARENT_IS_FILE"] = {"target": t, "file": a}
                break

    # 4. case-folded collisions (planned vs planned, planned vs existing)
    for fold, paths in by_fold.items():
        if len(paths) > 1:
            for path, group in paths.items():
                for o in group:
                    codes[o.operation_id]["CASEFOLD_TARGET_COLLISION"] = {
                        "target": path, "collides_with": sorted(p for p in paths if p != path)[:20]}
    for o in ready:
        clash = index.casefold_matches(o.target_absolute_path)
        if clash:
            codes[o.operation_id]["CASEFOLD_TARGET_COLLISION"] = {
                "target": o.target_absolute_path, "collides_with_existing": sorted(clash)[:20]}

    counts: dict[str, int] = defaultdict(int)
    for o in ready:
        found = codes.get(o.operation_id)
        if not found:
            continue
        ordered = [c for c in PRIORITY if c in found]
        statuses = [_status(policy, c) for c in ordered]
        o.plan_status = C.PLAN_BLOCKED if C.PLAN_BLOCKED in statuses else C.PLAN_REVIEW
        o.blocker_code = ordered[0]
        o.blocker_details = {"all_codes": ordered, **{c: found[c] for c in ordered}}
        for c in ordered:
            counts[c] += 1
    return dict(counts)
