"""Plan creation: route expansion, target paths, revalidation, collisions, immutable revisions."""

from __future__ import annotations

import json
import os
import stat as statmod
import uuid
from typing import Any

from migrator import audit as A
from migrator import constants as C
from migrator import db
from migrator.classifier import load_source_dirs, resolve_routes
from migrator.collisions import TargetIndex, detect_collisions
from migrator.config import Config
from migrator.logs import get_logger
from migrator.models import PlanOp
from migrator.paths import (PathSafetyError, canonical_json, relative_to, safe_join, sha256_hex,
                            write_new_file)
from migrator.runs import RunContext

log = get_logger("planner")


class PlanError(RuntimeError):
    pass


def build_target_path(cfg: Config, target_id: str, *, origin: str | None, source_path: str,
                      source_basename: str, route_dir_path: str | None,
                      route_dir_basename: str | None) -> str:
    """Deterministic target path.  Jev only chose `target_id`; the rest is computed here.

    * directly routed file        -> <target>/<basename>
    * inherited directory route   -> <target>/<path relative to the classified directory>
      (optionally prefixed by the classified directory's own name)
    Names are preserved exactly; the result must stay beneath the target root.
    """
    root = cfg.target(target_id).path
    if origin == C.ROUTE_INHERITED and route_dir_path is not None:
        rel = relative_to(source_path, route_dir_path)
        if not rel:
            raise PathSafetyError("source equals its classified directory")
        parts = [rel]
        if cfg["routing"]["directory_mapping"]["include_classified_directory_name"] and route_dir_basename:
            parts.insert(0, route_dir_basename)
        return safe_join(root, *parts)
    return safe_join(root, source_basename)


def temp_name(target_path: str, operation_id: str) -> str:
    """Temporary sibling name inside the final destination directory."""
    d, base = os.path.dirname(target_path), os.path.basename(target_path)
    name = f".{base}.migrator-{operation_id}.partial"
    if len(name.encode("utf-8")) > 255:     # NAME_MAX: fall back to a short unique name
        name = f".migrator-{operation_id}.partial"
    return os.path.join(d, name)


def _policy_status(cfg: Config, key: str) -> str:
    return C.PLAN_BLOCKED if cfg["planning"][key] == "block" else C.PLAN_REVIEW


def _load_target_index(ctx: RunContext) -> TargetIndex:
    idx = TargetIndex()
    for r in ctx.conn.execute(
            """SELECT d.absolute_path FROM directory_inventory d JOIN scan_root s USING (scan_root_id)
               WHERE d.run_id = %s AND s.root_type = 'TARGET'""", (ctx.run_id,)):
        idx.add_dir(r["absolute_path"])
    last = ""
    while True:
        page = ctx.conn.execute(
            """SELECT absolute_path, sha256, hash_status FROM file_inventory
               WHERE run_id = %s AND root_type = 'TARGET' AND absolute_path > %s
               ORDER BY absolute_path LIMIT 10000""", (ctx.run_id, last)).fetchall()
        if not page:
            break
        last = page[-1]["absolute_path"]
        for r in page:
            idx.add_file(r["absolute_path"], None if r["sha256"] is None else r["sha256"].strip(),
                         r["hash_status"])
    return idx


def _revalidate_source(row: dict[str, Any]) -> dict[str, Any] | None:
    """Re-stat a source file; returns change details, or None when unchanged.
    The hash is deliberately NOT recomputed: the inventory snapshot stays immutable."""
    try:
        st = os.lstat(row["absolute_path"])
    except OSError as exc:
        return {"reason": f"{type(exc).__name__}: {exc}"}
    if not statmod.S_ISREG(st.st_mode):
        return {"reason": "no longer a regular file"}
    now = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    then = (row["st_dev"], row["st_ino"], row["size_bytes"], row["mtime_ns"])
    if now != then:
        return {"reason": "stat changed", "inventory": list(then), "current": list(now)}
    return None


def compute_operations(ctx: RunContext, *, revalidate: bool = True) -> tuple[list[PlanOp], dict[str, int]]:
    cfg, conn = ctx.cfg, ctx.conn
    dirs = load_source_dirs(ctx)
    ops: list[PlanOp] = []
    seen_files: set[str] = set()
    last = ""
    while True:
        page = conn.execute(
            """SELECT f.file_id, f.trace_id, f.absolute_path, f.basename, f.size_bytes, f.mtime_ns,
                      f.st_dev, f.st_ino, f.sha256, f.hash_status,
                      r.route_status, r.reason_code, r.target_id, r.route_origin_type,
                      r.route_directory_id, r.decision_id
               FROM file_inventory f LEFT JOIN file_route r ON r.file_id = f.file_id AND r.run_id = f.run_id
               WHERE f.run_id = %s AND f.root_type = 'SOURCE' AND f.absolute_path > %s
               ORDER BY f.absolute_path LIMIT 5000""", (ctx.run_id, last)).fetchall()
        if not page:
            break
        last = page[-1]["absolute_path"]
        for r in page:
            fid = str(r["file_id"])
            if fid in seen_files:
                raise PlanError(f"file {fid} would appear in two operations")
            seen_files.add(fid)
            sha = None if r["sha256"] is None else r["sha256"].strip()
            op = PlanOp(str(uuid.uuid4()), fid, str(r["trace_id"]),
                        None if r["decision_id"] is None else str(r["decision_id"]),
                        r["absolute_path"], None, sha, r["size_bytes"], r["target_id"], C.PLAN_REVIEW)
            ops.append(op)
            rs = r["route_status"]
            if rs is None:
                op.plan_status, op.blocker_code = C.PLAN_REVIEW, "NO_ROUTE"
                continue
            if rs != C.ROUTE_READY:
                op.plan_status = C.PLAN_BLOCKED if rs == C.ROUTE_BLOCKED else C.PLAN_REVIEW
                op.blocker_code = r["reason_code"] or "ROUTE_REVIEW"
                if op.blocker_code in ("HASH_FAILED", "HASH_PENDING"):
                    op.blocker_code = "MISSING_CHECKSUM"
                    op.plan_status = _policy_status(cfg, "missing_checksum")
                op.target_id = r["target_id"]
                continue
            if sha is None or r["hash_status"] != C.HASH_HASHED:
                op.plan_status, op.blocker_code = _policy_status(cfg, "missing_checksum"), "MISSING_CHECKSUM"
                continue
            if revalidate:
                changed = _revalidate_source(r)
                if changed is not None:
                    op.plan_status = _policy_status(cfg, "changed_source")
                    op.blocker_code, op.blocker_details = "SOURCE_CHANGED_SINCE_INVENTORY", changed
                    continue
            rd = dirs.get(str(r["route_directory_id"])) if r["route_directory_id"] else None
            try:
                op.target_absolute_path = build_target_path(
                    cfg, r["target_id"], origin=r["route_origin_type"], source_path=r["absolute_path"],
                    source_basename=r["basename"], route_dir_path=rd.absolute_path if rd else None,
                    route_dir_basename=rd.basename if rd else None)
            except PathSafetyError as exc:
                op.plan_status, op.blocker_code = C.PLAN_BLOCKED, "TARGET_PATH_UNSAFE"
                op.blocker_details = {"error": str(exc)}
                continue
            if op.target_absolute_path == op.source_absolute_path:
                op.plan_status, op.blocker_code = C.PLAN_NOOP, "SOURCE_IS_TARGET"
                continue
            op.plan_status = C.PLAN_READY_STATUS
    counts = detect_collisions(ops, _load_target_index(ctx), cfg["planning"])
    return ops, counts


def _sort_key(o: PlanOp) -> tuple:
    return (o.target_id or "", o.target_absolute_path or "", o.source_absolute_path, o.operation_id)


def operation_record(o: PlanOp) -> dict[str, Any]:
    return {"operation_id": o.operation_id, "trace_id": o.trace_id, "file_id": o.file_id,
            "decision_id": o.decision_id, "operation_type": C.OP_SAFE_MOVE,
            "source_absolute_path": o.source_absolute_path,
            "target_absolute_path": o.target_absolute_path, "expected_sha256": o.expected_sha256,
            "expected_size_bytes": o.expected_size_bytes, "target_id": o.target_id,
            "plan_status": o.plan_status, "blocker_code": o.blocker_code}


def serialize_plan(ops: list[PlanOp]) -> bytes:
    """Canonical JSONL of the sorted operations: this is what `plan_sha256` covers."""
    return "".join(canonical_json(operation_record(o)) + "\n"
                   for o in sorted(ops, key=_sort_key)).encode("ascii")


def create_plan(ctx: RunContext, *, revalidate: bool = True) -> dict[str, Any]:
    conn, cfg = ctx.conn, ctx.cfg
    db.require_state(ctx.refresh(), C.CLASSIFIED, C.REVIEW_REQUIRED, C.PLANNING, C.PLAN_READY,
                    C.BATCHES_GENERATED)
    A.require_spool_synced(conn, ctx.run_id, ctx.spool)
    with conn.transaction():
        db.transition(conn, ctx.run_id, C.PLANNING)
    routes = resolve_routes(ctx)
    ops, collisions = compute_operations(ctx, revalidate=revalidate)
    ready_ids = [o.file_id for o in ops if o.plan_status == C.PLAN_READY_STATUS]
    assert len(ready_ids) == len(set(ready_ids)), "one READY source file <= one migration operation"
    data = serialize_plan(ops)
    plan_sha = sha256_hex(data)
    counts = {s: sum(1 for o in ops if o.plan_status == s)
              for s in (C.PLAN_READY_STATUS, C.PLAN_REVIEW, C.PLAN_BLOCKED, C.PLAN_NOOP)}
    plan_id = uuid.uuid4()
    revision = conn.execute("SELECT COALESCE(max(revision), 0) + 1 AS n FROM plan_revision WHERE run_id = %s",
                            (ctx.run_id,)).fetchone()["n"]
    name = f"plan-{revision:04d}"
    plan_files = [ctx.path("plan", f"{name}.jsonl"), ctx.path("plan", f"{name}.sha256")]
    try:
        with conn.transaction():
            write_new_file(plan_files[0], data, guard=ctx.guard)
            write_new_file(plan_files[1], f"{plan_sha}  {name}.jsonl\n".encode(), guard=ctx.guard)
            conn.execute(
                """INSERT INTO plan_revision (plan_id, run_id, revision, plan_sha256, operation_count,
                       ready_count, review_count, blocked_count, noop_count) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (str(plan_id), ctx.run_id, revision, plan_sha, len(ops), counts[C.PLAN_READY_STATUS],
                 counts[C.PLAN_REVIEW], counts[C.PLAN_BLOCKED], counts[C.PLAN_NOOP]))
            ordered = sorted(ops, key=_sort_key)
            for i in range(0, len(ordered), 2000):
                chunk = ordered[i:i + 2000]
                with conn.cursor() as cur:
                    cur.executemany(
                        """INSERT INTO plan_operation (operation_id, plan_id, run_id, file_id, trace_id, decision_id,
                               operation_type, source_absolute_path, target_absolute_path, expected_sha256,
                               expected_size_bytes, target_id, plan_status, blocker_code, blocker_details)
                           VALUES (%s,%s,%s,%s,%s,%s,'SAFE_MOVE',%s,%s,%s,%s,%s,%s,%s,%s)""",
                        [(o.operation_id, str(plan_id), ctx.run_id, o.file_id, o.trace_id, o.decision_id,
                          o.source_absolute_path, o.target_absolute_path, o.expected_sha256,
                          o.expected_size_bytes, o.target_id, o.plan_status, o.blocker_code,
                          None if o.blocker_details is None else db.jsonb(o.blocker_details)) for o in chunk])
                A.append_events(conn, ctx.run_id, [A.EventSpec(
                    uuid.UUID(o.trace_id), "PLAN_OPERATION_CREATED", "migrator", C.SRC_PYTHON, {
                        "plan_id": str(plan_id), "revision": revision, "plan_sha256": plan_sha,
                        "operation_id": o.operation_id, "plan_status": o.plan_status,
                        "blocker_code": o.blocker_code, "target_absolute_path": o.target_absolute_path},
                    file_id=uuid.UUID(o.file_id), operation_id=uuid.UUID(o.operation_id)) for o in chunk])
            A.append_event(conn, ctx.run_id, A.EventSpec(
                uuid.UUID(str(ctx.run["run_trace_id"])), "PLAN_CREATED", "migrator", C.SRC_PYTHON,
                {"plan_id": str(plan_id), "revision": revision, "plan_sha256": plan_sha, **counts}))
            db.transition(conn, ctx.run_id, C.PLAN_READY)
    except Exception:
        for f in plan_files:
            try:
                f.unlink()
            except OSError:
                pass
        raise
    log.info("plan revision %d created: %s", revision, counts, extra={"run_id": ctx.run_id})
    return {"plan_id": str(plan_id), "revision": revision, "plan_sha256": plan_sha,
            "counts": counts, "collisions": collisions, "routes": routes}


def latest_plan(conn, run_id: str) -> dict[str, Any] | None:
    return conn.execute("SELECT * FROM plan_revision WHERE run_id = %s ORDER BY revision DESC LIMIT 1",
                        (run_id,)).fetchone()
