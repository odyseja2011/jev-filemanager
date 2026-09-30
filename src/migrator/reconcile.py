"""Post-execution reconciliation.

Read-only against migration paths: it stats and hashes files, nothing else.
Filesystem state plus SHA-256 is authoritative; Bash exit status never is.
"""

from __future__ import annotations

import csv
import io
import os
import stat as statmod
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from migrator import audit as A
from migrator import constants as C
from migrator import db
from migrator.hashing import HashResult, hash_file
from migrator.logs import get_logger
from migrator.paths import write_replaceable_file
from migrator.planner import latest_plan
from migrator.runs import RunContext

log = get_logger("reconcile")

ABSENT, REGULAR, OTHER = "ABSENT", "REGULAR", "OTHER"


class ReconcileError(RuntimeError):
    pass


def path_state(path: str) -> str:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return ABSENT
    except OSError:
        return OTHER
    return REGULAR if statmod.S_ISREG(st.st_mode) else OTHER


def classify_outcome(src_state: str, tgt_state: str, expected: str,
                     src_sha: str | None, tgt_sha: str | None) -> str:
    """Pure decision table for one READY operation."""
    if src_state == OTHER:
        return C.REC_SOURCE_CHANGED
    if src_state == ABSENT:
        if tgt_state == REGULAR:
            return C.REC_VERIFIED_MOVED if tgt_sha == expected else C.REC_TARGET_MISMATCH
        if tgt_state == ABSENT:
            return C.REC_BOTH_MISSING
        return C.REC_TARGET_MISMATCH
    # source present
    if tgt_state == ABSENT:
        return C.REC_NOT_EXECUTED if src_sha == expected else C.REC_SOURCE_CHANGED
    if tgt_state == REGULAR and tgt_sha == expected:
        return C.REC_BOTH_PRESENT
    return C.REC_TARGET_MISMATCH


def reconcile(ctx: RunContext, *, hasher: Callable[..., HashResult] = hash_file) -> dict[str, Any]:
    conn, cfg = ctx.conn, ctx.cfg
    db.require_state(ctx.refresh(), C.BATCHES_GENERATED, C.EXTERNAL_EXECUTION_OBSERVED, C.RECONCILING,
                     C.RECONCILED)
    plan = latest_plan(conn, ctx.run_id)
    if plan is None:
        raise ReconcileError("no plan exists")
    plan_id = str(plan["plan_id"])
    # Bring locally spooled Bash events into PostgreSQL first so the chains stay linear.
    try:
        A.require_spool_synced(conn, ctx.run_id, ctx.spool)
    except A.AuditError as exc:
        raise ReconcileError(str(exc)) from exc
    with conn.transaction():
        if ctx.run["state"] == C.BATCHES_GENERATED:
            db.transition(conn, ctx.run_id, C.EXTERNAL_EXECUTION_OBSERVED, "observed by reconcile")
        db.transition(conn, ctx.run_id, C.RECONCILING)
    pass_id = str(uuid.uuid4())
    conn.execute("INSERT INTO reconciliation_pass (pass_id, run_id, plan_id) VALUES (%s,%s,%s)",
                 (pass_id, ctx.run_id, plan_id))
    rows = conn.execute(
        """SELECT po.operation_id, po.file_id, po.trace_id, po.plan_status, po.blocker_code,
                  po.source_absolute_path, po.target_absolute_path, po.expected_sha256,
                  bo.temp_absolute_path
           FROM plan_operation po LEFT JOIN batch_operation bo USING (operation_id)
           WHERE po.plan_id = %s ORDER BY po.source_absolute_path COLLATE "C" """, (plan_id,)).fetchall()
    last_bash = {str(r["operation_id"]): r["event_type"] for r in conn.execute(
        """SELECT DISTINCT ON (operation_id) operation_id, event_type FROM audit_event
           WHERE run_id = %s AND source = 'BASH' AND operation_id IS NOT NULL
           ORDER BY operation_id, event_time DESC, sequence_no DESC""", (ctx.run_id,))}
    workers = cfg["inventory"]["checksum"]["workers"]
    block = cfg["inventory"]["checksum"]["read_block_mib"] * 1024 * 1024
    retries = cfg["inventory"]["checksum"]["stability_retries"]

    def inspect(r: dict) -> dict[str, Any]:
        src, tgt = r["source_absolute_path"], r["target_absolute_path"]
        ss, ts = path_state(src), path_state(tgt)
        s_res = hasher(src, block_size=block, retries=retries) if ss == REGULAR else None
        t_res = hasher(tgt, block_size=block, retries=retries) if ts == REGULAR else None
        s_sha = s_res.sha256 if s_res and s_res.status == C.HASH_HASHED else None
        t_sha = t_res.sha256 if t_res and t_res.status == C.HASH_HASHED else None
        outcome = classify_outcome(ss, ts, r["expected_sha256"].strip(), s_sha, t_sha)
        details: dict[str, Any] = {"last_bash_event": last_bash.get(str(r["operation_id"]))}
        if s_res and s_res.error:
            details["source_error"] = s_res.error
        if t_res and t_res.error:
            details["target_error"] = t_res.error
        if r["temp_absolute_path"] and path_state(r["temp_absolute_path"]) != ABSENT:
            details["partial_file_present"] = r["temp_absolute_path"]
        return {"row": r, "outcome": outcome, "ss": ss, "ts": ts, "s_sha": s_sha, "t_sha": t_sha,
                "details": details}

    ready = [r for r in rows if r["plan_status"] == C.PLAN_READY_STATUS]
    counts: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i in range(0, len(ready), 500):
            chunk = ready[i:i + 500]
            res = list(pool.map(inspect, chunk))
            specs: list[A.EventSpec] = []
            with conn.transaction():
                for x in res:
                    r = x["row"]
                    counts[x["outcome"]] = counts.get(x["outcome"], 0) + 1
                    base = dict(file_id=r["file_id"], operation_id=r["operation_id"])
                    specs.append(A.EventSpec(r["trace_id"], "RECONCILIATION_STARTED", "reconciler",
                                             C.SRC_RECONCILER, {"pass_id": pass_id}, **base))
                    etype = ("RECONCILIATION_VERIFIED" if x["outcome"] == C.REC_VERIFIED_MOVED
                             else "RECONCILIATION_DISCREPANCY")
                    specs.append(A.EventSpec(r["trace_id"], etype, "reconciler", C.SRC_RECONCILER, {
                        "pass_id": pass_id, "outcome": x["outcome"], "source_state": x["ss"],
                        "target_state": x["ts"], "source_sha256": x["s_sha"], "target_sha256": x["t_sha"],
                        "expected_sha256": r["expected_sha256"].strip()}, **base))
                    conn.execute(
                        """INSERT INTO reconciliation_result (pass_id, operation_id, outcome, source_state,
                               target_state, source_sha256, target_sha256, details)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (pass_id, str(r["operation_id"]), x["outcome"], x["ss"], x["ts"], x["s_sha"],
                         x["t_sha"], db.jsonb(x["details"])))
                A.append_events(conn, ctx.run_id, specs)
            results.extend(res)
            log.info("reconciled %d/%d operations", min(i + 500, len(ready)), len(ready),
                     extra={"run_id": ctx.run_id})
    not_ready = [r for r in rows if r["plan_status"] != C.PLAN_READY_STATUS]
    with conn.transaction():
        for r in not_ready:
            conn.execute(
                """INSERT INTO reconciliation_result (pass_id, operation_id, outcome, details)
                   VALUES (%s,%s,'BLOCKED',%s)""",
                (pass_id, str(r["operation_id"]),
                 db.jsonb({"plan_status": r["plan_status"], "blocker_code": r["blocker_code"]})))
        counts[C.REC_BLOCKED] = len(not_ready)
        conn.execute("UPDATE reconciliation_pass SET completed_at = now() WHERE pass_id = %s", (pass_id,))
        A.append_event(conn, ctx.run_id, A.EventSpec(
            uuid.UUID(str(ctx.run["run_trace_id"])), "RECONCILIATION_COMPLETE", "reconciler",
            C.SRC_RECONCILER, {"pass_id": pass_id, "plan_id": plan_id, "outcomes": counts}))
        db.transition(conn, ctx.run_id, C.RECONCILED)
    write_reconciliation_csv(ctx, results, not_ready)
    return {"pass_id": pass_id, "plan_id": plan_id, "outcomes": counts}


def write_reconciliation_csv(ctx: RunContext, results: list[dict[str, Any]], not_ready: list[dict]) -> None:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["operation_id", "trace_id", "outcome", "source", "target", "source_state", "target_state",
                "expected_sha256", "target_sha256", "last_bash_event"])
    for x in results:
        r = x["row"]
        w.writerow([r["operation_id"], r["trace_id"], x["outcome"], r["source_absolute_path"],
                    r["target_absolute_path"], x["ss"], x["ts"], r["expected_sha256"].strip(),
                    x["t_sha"] or "", x["details"].get("last_bash_event") or ""])
    for r in not_ready:
        w.writerow([r["operation_id"], r["trace_id"], C.REC_BLOCKED, r["source_absolute_path"],
                    r["target_absolute_path"] or "", "", "", (r["expected_sha256"] or "").strip(), "",
                    r["blocker_code"] or ""])
    write_replaceable_file(ctx.path("reports", "reconciliation.csv"), buf.getvalue().encode(), ctx.guard)
