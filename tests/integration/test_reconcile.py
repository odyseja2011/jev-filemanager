import shutil
from pathlib import Path

import pytest

from migrator import audit as A, batches, constants as C, reconcile, reports
from migrator.db import InvalidTransition
from tests.integration.conftest import ready_run

pytestmark = pytest.mark.postgres


@pytest.fixture()
def env(bare_env):
    return bare_env


def rules(s, q):
    return ("REVIEW", 0.9) if s["file_name"] == "review.bin" else ("MOVIES", 0.99)


def test_every_state_combination(env):
    files = {n: n.encode() for n in ["moved", "notexec", "both_ok", "both_wrong", "srcgone_wrong", "bothmissing",
                                     "srcchanged", "review.bin"]}
    ctx, _ = ready_run(env, files, rules=rules)
    batches.generate_batches(ctx)
    m = env.lib / "MOVIES"
    src = env.src
    # simulate what was (or was not) done externally
    shutil.copy(src / "moved", m / "moved"); (src / "moved").unlink()
    shutil.copy(src / "both_ok", m / "both_ok")
    (m / "both_wrong").write_bytes(b"WRONG")
    (m / "srcgone_wrong").write_bytes(b"WRONG"); (src / "srcgone_wrong").unlink()
    (src / "bothmissing").unlink()
    (src / "srcchanged").write_bytes(b"changed!")
    res = reconcile.reconcile(ctx)
    got = {r["source_absolute_path"].rsplit("/", 1)[1]: r["outcome"] for r in ctx.conn.execute(
        """SELECT po.source_absolute_path, rr.outcome FROM reconciliation_result rr JOIN plan_operation po USING (operation_id)
           WHERE rr.pass_id=%s""", (res["pass_id"],))}
    assert got == {"moved": "VERIFIED_MOVED", "notexec": "NOT_EXECUTED", "both_ok": "TARGET_PRESENT_SOURCE_PRESENT",
                   "both_wrong": "TARGET_HASH_MISMATCH", "srcgone_wrong": "TARGET_HASH_MISMATCH",
                   "bothmissing": "SOURCE_MISSING_TARGET_MISSING", "srcchanged": "SOURCE_CHANGED", "review.bin": "BLOCKED"}
    assert ctx.refresh()["state"] == C.RECONCILED
    # events land on the same per-file trace
    ev = [e["event_type"] for e in ctx.conn.execute(
        "SELECT event_type FROM audit_event e JOIN file_inventory f USING (trace_id) WHERE f.basename='moved' ORDER BY sequence_no")]
    assert ev[-2:] == ["RECONCILIATION_STARTED", "RECONCILIATION_VERIFIED"]
    ev = [e["event_type"] for e in ctx.conn.execute(
        "SELECT event_type FROM audit_event e JOIN file_inventory f USING (trace_id) WHERE f.basename='notexec' ORDER BY sequence_no")]
    assert ev[-1] == "RECONCILIATION_DISCREPANCY"
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok
    s = reports.run_summary(ctx)["reconciliation"]
    assert (s["verified_moved"], s["source_still_present"], s["target_mismatches"], s["missing_data"]) == (1, 2, 2, 1)
    csv = (ctx.run_dir / "reports" / "reconciliation.csv").read_text()
    assert "VERIFIED_MOVED" in csv and "SOURCE_MISSING_TARGET_MISSING" in csv
    # reconciling again is allowed and appends new events
    res2 = reconcile.reconcile(ctx)
    assert res2["pass_id"] != res["pass_id"] and ctx.refresh()["state"] == C.RECONCILED
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok


def test_success_is_decided_by_sha256_not_exit_status(env):
    ctx, _ = ready_run(env, {"a.mkv": b"payload"}, rules=rules)
    g = batches.generate_batches(ctx)
    assert env.run_batch(Path(g["batches"][0]["script"])).returncode == 0     # bash says success ...
    (env.lib / "MOVIES" / "a.mkv").write_bytes(b"bit-rot")                    # ... but the data was corrupted later
    res = reconcile.reconcile(ctx)
    assert res["outcomes"] == {"TARGET_HASH_MISMATCH": 1, "BLOCKED": 0} or res["outcomes"]["TARGET_HASH_MISMATCH"] == 1


def test_reconcile_imports_spool_first_and_requires_a_plan_state(env):
    ctx, _ = ready_run(env, {"a.mkv": b"payload"}, rules=rules)
    with pytest.raises(InvalidTransition):
        reconcile.reconcile(ctx)                       # batches were never generated
    g = batches.generate_batches(ctx)
    env.run_batch(Path(g["batches"][0]["script"]), MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    assert ctx.spool.counts()["pending"] > 0
    res = reconcile.reconcile(ctx)
    assert res["outcomes"]["VERIFIED_MOVED"] == 1 and ctx.spool.counts()["pending"] == 0
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok
    s = reports.run_summary(ctx)
    assert s["execution_observations"]["completed"] == 1 and s["execution_observations"]["not_started"] == 0


def test_partial_files_are_reported_but_never_removed(env):
    ctx, _ = ready_run(env, {"a.mkv": b"payload"}, rules=rules)
    g = batches.generate_batches(ctx)
    bo = ctx.conn.execute("SELECT temp_absolute_path FROM batch_operation").fetchone()
    Path(bo["temp_absolute_path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(bo["temp_absolute_path"]).write_bytes(b"half")
    reconcile.reconcile(ctx)
    assert Path(bo["temp_absolute_path"]).exists()      # reconcile is read-only
    d = ctx.conn.execute("SELECT details FROM reconciliation_result WHERE outcome='NOT_EXECUTED'").fetchone()["details"]
    assert d["partial_file_present"] == bo["temp_absolute_path"]
