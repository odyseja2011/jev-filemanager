"""Configuration loading, validation, normalization and snapshotting."""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from migrator.constants import RESERVED_TARGET_IDS, SUPPORTED_CHECKSUM_ALGORITHMS
from migrator.paths import canonical_json, is_within, sha256_hex


class ConfigError(ValueError):
    """Configuration is invalid.  `problems` lists every violation found."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid configuration:\n  - " + "\n  - ".join(problems))


DEFAULTS: dict[str, Any] = {
    "version": 1,
    "migration": {"name": None},
    "workspace": {"path": None},
    "database": {"dsn_env": "MIGRATOR_DATABASE_URL"},
    "openrouter": {
        "api_key_env": "OPENROUTER_API_KEY",
        "endpoint": "https://openrouter.ai/api/alpha/decisions",
        "model": "typesafe/jev-1.13",
        "timeout_seconds": 30,
        "concurrency": 8,
        "retries": 3,
    },
    "scope": {
        "allow_overlapping_sources": False,
        "allow_targets_in_sources": False,
        "sources": [],
        "targets": [],
    },
    "inventory": {
        "regular_files_only": True,
        "follow_symlinks": False,
        "cross_mounts_default": True,
        "checksum": {"algorithm": "sha256", "workers": 4, "read_block_mib": 8,
                     "stability_retries": 2},
        "hardlinks": {"action": "review"},
    },
    "routing": {
        "confidence_threshold": 0.90,
        "max_depth": 64,
        "samples": {"max_child_directory_names": 80, "max_file_names": 120,
                    "max_ancestor_names": 8, "max_state_characters": 24000},
        "directory_mapping": {"include_classified_directory_name": False},
        "low_confidence_directory_action": "descend",
        "low_confidence_file_action": "review",
        "cache_decisions": True,
    },
    "planning": {
        "exact_path_collision": "review",
        "casefold_path_collision": "review",
        "existing_target_same_hash": "review",
        "existing_target_different_hash": "block",
        "missing_checksum": "block",
        "changed_source": "block",
    },
    "batches": {
        "max_operations": 100,
        "use_absolute_paths": True,
        "copy_verify_delete": True,
        "use_reflink_auto": True,
        "remove_empty_source_directories": False,
        "overwrite_existing_targets": False,
    },
    "permissions": {
        "preserve_source_owner": False,
        "preserve_source_group": False,
        "preserve_source_mode": False,
        "preserve_source_acl": False,
        "preserve_source_xattrs": False,
        "inherit_destination_permissions": True,
    },
    "audit": {
        "postgres": True,
        "local_spool": True,
        "hash_chain": True,
        "require_durable_event_before_mutation": True,
    },
    "reconciliation": {"verify_sha256": True},
}

SOURCE_KEYS = {"id", "path", "cross_mounts", "include", "exclude"}
TARGET_KEYS = {"id", "path", "description", "cross_mounts"}
POLICY_CHOICES = {"review", "block"}


@dataclass(frozen=True)
class SourceRoot:
    id: str
    path: str
    cross_mounts: bool
    include: tuple[str, ...]
    exclude: tuple[str, ...]


@dataclass(frozen=True)
class TargetRoot:
    id: str
    path: str
    description: str
    cross_mounts: bool


@dataclass(frozen=True)
class Config:
    """Normalized, validated configuration (`data` is the canonical dict)."""

    data: dict[str, Any]

    # -- convenience accessors ------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    @property
    def name(self) -> str:
        return self.data["migration"]["name"]

    @property
    def workspace(self) -> str:
        return self.data["workspace"]["path"]

    @property
    def model(self) -> str:
        return self.data["openrouter"]["model"]

    @property
    def sources(self) -> list[SourceRoot]:
        return [SourceRoot(s["id"], s["path"], s["cross_mounts"],
                           tuple(s["include"]), tuple(s["exclude"]))
                for s in self.data["scope"]["sources"]]

    @property
    def targets(self) -> list[TargetRoot]:
        return [TargetRoot(t["id"], t["path"], t["description"], t["cross_mounts"])
                for t in self.data["scope"]["targets"]]

    @property
    def target_ids(self) -> list[str]:
        return [t["id"] for t in self.data["scope"]["targets"]]

    def target(self, target_id: str) -> TargetRoot:
        for t in self.targets:
            if t.id == target_id:
                return t
        raise KeyError(target_id)

    @property
    def migration_roots(self) -> list[str]:
        return [s.path for s in self.sources] + [t.path for t in self.targets]

    @property
    def threshold(self) -> float:
        return float(self.data["routing"]["confidence_threshold"])

    def sha256(self) -> str:
        return sha256_hex(canonical_json(self.data))

    def canonical(self) -> str:
        return canonical_json(self.data)


def _deep_merge(base: dict, override: dict, path: str, problems: list[str]) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if k not in base:
            problems.append(f"unknown configuration key: {path}{k}")
            continue
        if isinstance(base[k], dict) and base[k] and isinstance(v, dict):
            out[k] = _deep_merge(base[k], v, f"{path}{k}.", problems)
        elif isinstance(base[k], dict) and base[k] and not isinstance(v, dict):
            problems.append(f"{path}{k} must be a mapping")
        else:
            out[k] = v
    return out


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def normalize_and_validate(raw: dict[str, Any]) -> Config:
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise ConfigError(["top level of the configuration must be a mapping"])
    cfg = _deep_merge(DEFAULTS, raw, "", problems)
    scope_raw = raw.get("scope") if isinstance(raw.get("scope"), dict) else {}

    if cfg["version"] != 1:
        problems.append(f"unsupported config version: {cfg['version']!r} (expected 1)")

    name = cfg["migration"]["name"]
    if not isinstance(name, str) or not name.strip():
        problems.append("migration.name is required")

    ws = cfg["workspace"]["path"]
    if not isinstance(ws, str) or not os.path.isabs(ws):
        problems.append("workspace.path must be an absolute path")
    else:
        cfg["workspace"]["path"] = os.path.normpath(ws)

    for key in ("dsn_env",):
        if not isinstance(cfg["database"][key], str) or not cfg["database"][key]:
            problems.append(f"database.{key} must name an environment variable")
    orr = cfg["openrouter"]
    if not isinstance(orr["api_key_env"], str) or not orr["api_key_env"]:
        problems.append("openrouter.api_key_env must name an environment variable")
    if not isinstance(orr["model"], str) or not orr["model"]:
        problems.append("openrouter.model is required")
    elif any(ord(c) < 32 for c in orr["model"]):
        problems.append("openrouter.model contains control characters")
    if not isinstance(orr["endpoint"], str) or not orr["endpoint"].startswith(("http://", "https://")):
        problems.append("openrouter.endpoint must be an http(s) URL")
    for key, lo in (("timeout_seconds", 0), ("concurrency", 1), ("retries", 0)):
        v = orr[key]
        if not _is_num(v) or v < lo or (key != "timeout_seconds" and not _is_int(v)) or (key == "timeout_seconds" and v <= 0):
            problems.append(f"openrouter.{key} is invalid: {v!r}")

    # ---- scope -------------------------------------------------------------
    scope = cfg["scope"]
    sources_raw = scope_raw.get("sources", [])
    targets_raw = scope_raw.get("targets", [])
    if not isinstance(sources_raw, list) or not sources_raw:
        problems.append("scope.sources must be a non-empty list")
        sources_raw = []
    if not isinstance(targets_raw, list) or not targets_raw:
        problems.append("scope.targets must be a non-empty list")
        targets_raw = []
    for flag in ("allow_overlapping_sources", "allow_targets_in_sources"):
        if not isinstance(scope[flag], bool):
            problems.append(f"scope.{flag} must be a boolean")

    cross_default = cfg["inventory"]["cross_mounts_default"]
    if not isinstance(cross_default, bool):
        problems.append("inventory.cross_mounts_default must be a boolean")
        cross_default = True

    sources: list[dict] = []
    seen_src: set[str] = set()
    for i, s in enumerate(sources_raw):
        where = f"scope.sources[{i}]"
        if not isinstance(s, dict):
            problems.append(f"{where} must be a mapping")
            continue
        for k in s:
            if k not in SOURCE_KEYS:
                problems.append(f"unknown key {where}.{k}")
        sid, path = s.get("id"), s.get("path")
        if not isinstance(sid, str) or not sid:
            problems.append(f"{where}.id is required")
            continue
        if sid in seen_src:
            problems.append(f"duplicate source id: {sid}")
        seen_src.add(sid)
        if not isinstance(path, str) or not os.path.isabs(path):
            problems.append(f"source {sid}: path must be absolute, got {path!r}")
            continue
        cm = s.get("cross_mounts", cross_default)
        if not isinstance(cm, bool):
            problems.append(f"source {sid}: cross_mounts must be a boolean")
            cm = True
        inc = s.get("include", ["**/*"]) or ["**/*"]
        exc = s.get("exclude", []) or []
        if not (isinstance(inc, list) and all(isinstance(x, str) for x in inc)):
            problems.append(f"source {sid}: include must be a list of glob strings")
            inc = ["**/*"]
        if not (isinstance(exc, list) and all(isinstance(x, str) for x in exc)):
            problems.append(f"source {sid}: exclude must be a list of glob strings")
            exc = []
        sources.append({"id": sid, "path": os.path.normpath(path), "cross_mounts": cm,
                        "include": list(inc), "exclude": list(exc)})

    targets: list[dict] = []
    seen_tgt: set[str] = set()
    seen_tpath: set[str] = set()
    for i, t in enumerate(targets_raw):
        where = f"scope.targets[{i}]"
        if not isinstance(t, dict):
            problems.append(f"{where} must be a mapping")
            continue
        for k in t:
            if k not in TARGET_KEYS:
                problems.append(f"unknown key {where}.{k}")
        tid, path = t.get("id"), t.get("path")
        if not isinstance(tid, str) or not tid:
            problems.append(f"{where}.id is required")
            continue
        if tid in RESERVED_TARGET_IDS:
            problems.append(f"target id {tid!r} is reserved")
        if tid in seen_tgt:
            problems.append(f"duplicate target id: {tid}")
        seen_tgt.add(tid)
        if not isinstance(path, str) or not os.path.isabs(path):
            problems.append(f"target {tid}: path must be absolute, got {path!r}")
            continue
        npath = os.path.normpath(path)
        if npath in seen_tpath:
            problems.append(f"duplicate destination path: {npath} (target {tid})")
        seen_tpath.add(npath)
        desc = t.get("description")
        if not isinstance(desc, str) or not desc.strip():
            problems.append(f"target {tid}: description is required (Jev routes by it)")
            desc = ""
        cm = t.get("cross_mounts", cross_default)
        if not isinstance(cm, bool):
            problems.append(f"target {tid}: cross_mounts must be a boolean")
            cm = True
        targets.append({"id": tid, "path": npath, "description": " ".join(desc.split()),
                        "cross_mounts": cm})

    # ---- overlap rules -----------------------------------------------------------
    if not scope["allow_overlapping_sources"]:
        for i, a in enumerate(sources):
            for b in sources[i + 1:]:
                if is_within(a["path"], b["path"]) or is_within(b["path"], a["path"]):
                    problems.append(f"source roots overlap: {a['id']} ({a['path']}) and "
                                    f"{b['id']} ({b['path']}); set scope.allow_overlapping_sources to permit")
    if not scope["allow_targets_in_sources"]:
        for t in targets:
            for s in sources:
                if is_within(t["path"], s["path"]):
                    problems.append(f"target {t['id']} ({t['path']}) is nested inside source "
                                    f"{s['id']} ({s['path']}); set scope.allow_targets_in_sources to permit")
                elif is_within(s["path"], t["path"]):
                    problems.append(f"source {s['id']} ({s['path']}) is nested inside target "
                                    f"{t['id']} ({t['path']})")
    for i, a in enumerate(targets):
        for b in targets[i + 1:]:
            if a["path"] != b["path"] and (is_within(a["path"], b["path"]) or is_within(b["path"], a["path"])):
                problems.append(f"target roots overlap: {a['id']} and {b['id']}")
    if isinstance(cfg["workspace"]["path"], str) and os.path.isabs(cfg["workspace"]["path"]):
        for label, p in [("source", s["path"]) for s in sources] + [("target", t["path"]) for t in targets]:
            if is_within(cfg["workspace"]["path"], p) or is_within(p, cfg["workspace"]["path"]):
                problems.append(f"workspace overlaps {label} root {p}; the workspace must be separate")
    scope["sources"], scope["targets"] = sources, targets

    # ---- inventory ---------------------------------------------------------------
    inv = cfg["inventory"]
    if inv["regular_files_only"] is not True:
        problems.append("inventory.regular_files_only must be true")
    if inv["follow_symlinks"] is not False:
        problems.append("inventory.follow_symlinks must be false")
    ck = inv["checksum"]
    if ck["algorithm"] not in SUPPORTED_CHECKSUM_ALGORITHMS:
        problems.append(f"unsupported checksum algorithm: {ck['algorithm']!r} "
                        f"(supported: {', '.join(SUPPORTED_CHECKSUM_ALGORITHMS)})")
    for k, lo in (("workers", 1), ("read_block_mib", 1), ("stability_retries", 0)):
        if not _is_int(ck[k]) or ck[k] < lo:
            problems.append(f"inventory.checksum.{k} must be an integer >= {lo}")
    if inv["hardlinks"]["action"] not in POLICY_CHOICES:
        problems.append("inventory.hardlinks.action must be 'review' or 'block'")

    # ---- routing -----------------------------------------------------------------
    r = cfg["routing"]
    th = r["confidence_threshold"]
    if not _is_num(th) or not (0.0 < th <= 1.0):
        problems.append(f"routing.confidence_threshold must be in (0, 1], got {th!r}")
    if not _is_int(r["max_depth"]) or r["max_depth"] < 1:
        problems.append("routing.max_depth must be an integer >= 1")
    for k, v in r["samples"].items():
        if not _is_int(v) or v < (1 if k == "max_state_characters" else 0):
            problems.append(f"routing.samples.{k} is invalid: {v!r}")
    if r["low_confidence_directory_action"] != "descend":
        problems.append("routing.low_confidence_directory_action: only 'descend' is supported")
    if r["low_confidence_file_action"] != "review":
        problems.append("routing.low_confidence_file_action: only 'review' is supported")
    if not isinstance(r["directory_mapping"]["include_classified_directory_name"], bool):
        problems.append("routing.directory_mapping.include_classified_directory_name must be a boolean")
    if not isinstance(r["cache_decisions"], bool):
        problems.append("routing.cache_decisions must be a boolean")

    for k, v in cfg["planning"].items():
        if v not in POLICY_CHOICES:
            problems.append(f"planning.{k} must be 'review' or 'block', got {v!r}")

    b = cfg["batches"]
    if not _is_int(b["max_operations"]) or b["max_operations"] < 1:
        problems.append(f"batches.max_operations must be an integer >= 1, got {b['max_operations']!r}")
    if b["use_absolute_paths"] is not True:
        problems.append("batches.use_absolute_paths must be true")
    if b["copy_verify_delete"] is not True:
        problems.append("batches.copy_verify_delete must be true (blind mv is never generated)")
    if b["overwrite_existing_targets"] is not False:
        problems.append("batches.overwrite_existing_targets must be false: NO OVERWRITE, EVER")
    if b["remove_empty_source_directories"] is not False:
        problems.append("batches.remove_empty_source_directories must be false in v1")

    p = cfg["permissions"]
    for k in ("preserve_source_owner", "preserve_source_group", "preserve_source_mode",
              "preserve_source_acl", "preserve_source_xattrs"):
        if p[k] is not False:
            problems.append(f"permissions.{k} must be false in v1")
    if p["inherit_destination_permissions"] is not True:
        problems.append("permissions.inherit_destination_permissions must be true")

    a = cfg["audit"]
    for k in ("postgres", "local_spool", "hash_chain", "require_durable_event_before_mutation"):
        if a[k] is not True:
            problems.append(f"audit.{k} must be true in v1")
    if cfg["reconciliation"]["verify_sha256"] is not True:
        problems.append("reconciliation.verify_sha256 must be true in v1")

    if problems:
        raise ConfigError(problems)
    return Config(cfg)


def parse_config_text(text: str) -> Config:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError([f"YAML parse error: {exc}"]) from exc
    return normalize_and_validate(raw)


def load_config(path: str | os.PathLike) -> tuple[Config, bytes]:
    """Returns (config, exact raw YAML bytes) so the snapshot is byte-exact."""
    raw = Path(path).read_bytes()
    return parse_config_text(raw.decode("utf-8")), raw
