"""Small in-memory records shared between modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DirNode:
    directory_id: str
    parent_id: str | None
    scan_root_id: str
    absolute_path: str
    relative_path: str
    basename: str
    depth: int
    children: list["DirNode"] = field(default_factory=list)
    parent: "DirNode | None" = None
    subtree_files: int = 0


@dataclass(frozen=True)
class Effective:
    """The effective (latest, preferring successful) decision of a subject."""

    decision_id: str
    subject_type: str
    subject_id: str
    source: str            # JEV / HUMAN
    status: str            # OK / API_FAILED
    choice: str | None
    confidence: float | None
    returned_model: str | None
    state_sha256: str
    applies_to_subtree: bool | None


@dataclass(frozen=True)
class Assign:
    """A subtree (or direct-files-only) routing produced by a directory decision."""

    target_id: str
    decision_id: str
    source: str
    confidence: float | None
    route_directory_id: str


@dataclass
class ClassifyTask:
    kind: str              # DIRECTORY / FILE
    subject_id: str
    state: dict[str, Any]
    question: dict[str, Any]
    file_trace_id: str | None = None
    state_sha256: str = ""
    criteria_sha256: str = ""
    cache_key: str = ""
    label: str = ""


@dataclass
class PlanOp:
    operation_id: str
    file_id: str
    trace_id: str
    decision_id: str | None
    source_absolute_path: str
    target_absolute_path: str | None
    expected_sha256: str | None
    expected_size_bytes: int
    target_id: str | None
    plan_status: str
    blocker_code: str | None = None
    blocker_details: dict[str, Any] | None = None
