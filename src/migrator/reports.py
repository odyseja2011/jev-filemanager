"""Run summary, plan and conflict reports."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from migrator import constants as C
from migrator.audit import Spool
from migrator.paths import write_replaceable_file
from migrator.planner import latest_plan
from migrator.runs import RunContext


def _one(conn, sql: str, params: tuple = ()) -> dict[str, Any]:
    return conn.execute(sql, params).fetchone() or {}


def run_summary(ctx: RunContext) -> dict[str, Any]:
    conn, rid = ctx.conn, ctx.run_id
    run = ctx.refresh()

    def inv(root_type: str) -> dict[str, Any]:
        r = _one(conn, """SELECT count(*) AS files, COALESCE(sum(size_bytes),0) AS bytes,
                 count(*) FILTER (WHERE hash_status = 'HASHED') AS hashed,
                 count(*) FILTER (WHERE hash_status = 'FAILED') AS hash_failures,
                 count(*) FILTER (WHERE hash_status = 'UNSTABLE') AS unstable,
                 count(*) FILTER (WHERE hash_status = 'BLOCKED_HARDLINK') AS hardlinks_blocked
                 FROM file_inventory WHERE run_id = %s AND root_type = %s""", (rid, root_type))
        sk = _one(conn, """SELECT COALESCE(sum(symlink_skipped_count),0) AS s,
                 COALESCE(sum(undecodable_skipped_count),0) AS u, COALESCE(sum(directory_count),0) AS d
                 FROM scan_root WHERE run_id = %s AND root_type = %s""", (rid, root_type))
        return {"regular_files": r["files"], "bytes": int(r["bytes"]), "hashed": r["hashed"],
                "hash_failures": r["hash_failures"], "unstable_files": r["unstable"],
                "hardlinks_blocked": r["hardlinks_blocked"], "symlinks_skipped": int(sk["s"]),
                "undecodable_names_skipped": int(sk["u"]), "directories": int(sk["d"])}

    d = _one(conn, """SELECT
        count(*) FILTER (WHERE subject_type='DIRECTORY' AND decision_source='JEV' AND cached_from_decision_id IS NULL) AS dir_calls,
        count(*) FILTER (WHERE subject_type='FILE' AND decision_source='JEV' AND cached_from_decision_id IS NULL) AS file_calls,
        count(*) FILTER (WHERE cached_from_decision_id IS NOT NULL) AS cache_hits,
        count(*) FILTER (WHERE decision_source='HUMAN') AS human,
        count(*) FILTER (WHERE decision_status='API_FAILED') AS api_failed,
        avg(confidence) FILTER (WHERE decision_source='JEV' AND decision_status='OK') AS avg_conf
        FROM route_decision WHERE run_id = %s""", (rid,))
    routes = {r["route_status"]: r["n"] for r in conn.execute(
        "SELECT route_status, count(*) AS n FROM file_route WHERE run_id = %s GROUP BY 1", (rid,))}
    summary: dict[str, Any] = {
        "run_id": rid, "name": run["name"], "state": run["state"],
        "config_sha256": run["config_sha256"].strip(), "requested_jev_model": run["requested_jev_model"],
        "source_inventory": inv(C.ROOT_SOURCE), "target_inventory": inv(C.ROOT_TARGET),
        "classification": {
            "directory_jev_calls": d["dir_calls"], "file_jev_calls": d["file_calls"],
            "cache_hits": d["cache_hits"], "api_failures": d["api_failed"],
            "auto_routed_files": routes.get(C.ROUTE_READY, 0),
            "review_files": routes.get(C.ROUTE_REVIEW, 0),
            "blocked_files": routes.get(C.ROUTE_BLOCKED, 0),
            "human_overrides": d["human"],
            "average_confidence": None if d["avg_conf"] is None else round(float(d["avg_conf"]), 4)},
    }
    plan = latest_plan(conn, rid)
    if plan is None:
        summary["plan"] = None
        summary["batches"] = None
    else:
        pid = str(plan["plan_id"])
        codes = {r["blocker_code"]: r["n"] for r in conn.execute(
            "SELECT blocker_code, count(*) AS n FROM plan_operation WHERE plan_id = %s "
            "AND blocker_code IS NOT NULL GROUP BY 1", (pid,))}
        summary["plan"] = {
            "revision": plan["revision"], "plan_id": pid, "plan_sha256": plan["plan_sha256"].strip(),
            "ready_operations": plan["ready_count"], "review_operations": plan["review_count"],
            "blocked_operations": plan["blocked_count"], "noop_operations": plan["noop_count"],
            "exact_collisions": codes.get("TARGET_PATH_COLLISION", 0),
            "casefold_collisions": codes.get("CASEFOLD_TARGET_COLLISION", 0),
            "existing_targets": codes.get("TARGET_ALREADY_IDENTICAL", 0)
            + codes.get("TARGET_EXISTS_DIFFERENT_CONTENT", 0),
            "blockers": codes}
        bs = conn.execute("SELECT batch_number, operation_count, script_sha256 FROM batch WHERE plan_id = %s "
                          "ORDER BY batch_number", (pid,)).fetchall()
        summary["batches"] = {"count": len(bs),
                              "operations_per_batch": [b["operation_count"] for b in bs],
                              "script_sha256": {f"batch_{b['batch_number']:06d}.sh": b["script_sha256"].strip()
                                                for b in bs}}
        ex = conn.execute(
            """SELECT count(*) FILTER (WHERE done) AS completed,
                      count(*) FILTER (WHERE failed AND NOT done) AS failed,
                      count(*) FILTER (WHERE NOT started) AS not_started
               FROM (SELECT po.operation_id,
                            COALESCE(bool_or(e.event_type = ANY(%s)), false) AS done,
                            COALESCE(bool_or(e.event_type = ANY(%s)), false) AS failed,
                            COALESCE(bool_or(e.event_type = 'BATCH_OPERATION_STARTED'), false) AS started
                     FROM plan_operation po
                     LEFT JOIN audit_event e ON e.operation_id = po.operation_id AND e.source = 'BASH'
                     WHERE po.plan_id = %s AND po.plan_status = 'READY' GROUP BY po.operation_id) x""",
            (sorted(C.BASH_SUCCESS_EVENTS), sorted(C.BASH_FAILURE_EVENTS), pid)).fetchone()
        spool = Spool(ctx.run_dir / "audit-spool").counts()
        summary["execution_observations"] = {
            "completed": ex["completed"], "failed": ex["failed"], "not_started": ex["not_started"],
            "audit_events_waiting_for_sync": spool["pending"]}
        rp = _one(conn, "SELECT pass_id FROM reconciliation_pass WHERE run_id = %s AND plan_id = %s "
                        "AND completed_at IS NOT NULL ORDER BY completed_at DESC LIMIT 1", (rid, pid))
        if rp:
            oc = {r["outcome"]: r["n"] for r in conn.execute(
                "SELECT outcome, count(*) AS n FROM reconciliation_result WHERE pass_id = %s GROUP BY 1",
                (str(rp["pass_id"]),))}
            summary["reconciliation"] = {
                "outcomes": oc, "verified_moved": oc.get(C.REC_VERIFIED_MOVED, 0),
                "source_still_present": oc.get(C.REC_NOT_EXECUTED, 0) + oc.get(C.REC_BOTH_PRESENT, 0),
                "target_mismatches": oc.get(C.REC_TARGET_MISMATCH, 0),
                "missing_data": oc.get(C.REC_BOTH_MISSING, 0)}
        else:
            summary["reconciliation"] = None
    return summary


def write_summary(ctx: RunContext) -> dict[str, Any]:
    s = run_summary(ctx)
    write_replaceable_file(ctx.path("reports", "summary.json"),
                           (json.dumps(s, indent=2, sort_keys=True) + "\n").encode(), ctx.guard)
    return s


def format_summary(s: dict[str, Any]) -> str:
    lines = [f"Run {s['run_id']}  [{s['state']}]  {s['name']}",
             f"Config SHA-256 {s['config_sha256']}  model {s['requested_jev_model']}", ""]

    def section(title: str, d: dict | None) -> None:
        lines.append(title)
        if d is None:
            lines.append("  (not available yet)")
        else:
            for k, v in d.items():
                if isinstance(v, (dict, list)) and len(json.dumps(v)) > 120:
                    lines.append(f"  {k}: ...")
                else:
                    lines.append(f"  {k}: {v}")
        lines.append("")

    section("SOURCE INVENTORY", s["source_inventory"])
    section("TARGET INVENTORY", s["target_inventory"])
    section("CLASSIFICATION", s["classification"])
    section("PLAN", s["plan"])
    section("BATCHES", s["batches"])
    section("EXECUTION OBSERVATIONS", s.get("execution_observations"))
    section("RECONCILIATION", s.get("reconciliation"))
    return "\n".join(lines)


def plan_blockers(ctx: RunContext) -> list[dict[str, Any]]:
    plan = latest_plan(ctx.conn, ctx.run_id)
    if plan is None:
        return []
    return ctx.conn.execute(
        """SELECT operation_id, trace_id, plan_status, blocker_code, source_absolute_path,
                  target_absolute_path, blocker_details FROM plan_operation
           WHERE plan_id = %s AND plan_status <> 'READY' ORDER BY blocker_code, source_absolute_path COLLATE "C" """,
        (str(plan["plan_id"]),)).fetchall()


def write_conflicts_csv(ctx: RunContext) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["operation_id", "trace_id", "plan_status", "blocker_code", "source", "target", "details"])
    for r in plan_blockers(ctx):
        w.writerow([r["operation_id"], r["trace_id"], r["plan_status"], r["blocker_code"] or "",
                    r["source_absolute_path"], r["target_absolute_path"] or "",
                    json.dumps(r["blocker_details"], sort_keys=True) if r["blocker_details"] else ""])
    path = ctx.path("reports", "conflicts.csv")
    write_replaceable_file(path, buf.getvalue().encode(), ctx.guard)
    return str(path)
