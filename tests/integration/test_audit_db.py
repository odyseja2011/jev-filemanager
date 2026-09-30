import json
import os
import threading
import uuid
from pathlib import Path

import psycopg
import pytest

from migrator import audit as A, batches, classifier, constants as C, db, inventory, planner
from migrator.runs import open_run
from tests.integration.conftest import all_movies, ready_run

pytestmark = pytest.mark.postgres


@pytest.fixture()
def env(bare_env):
    return bare_env


def one_file_run(env, name="a.mkv", data=b"payload", generate=True):
    ctx, fake = ready_run(env, {name: data}, rules=all_movies)
    gen = batches.generate_batches(ctx) if generate else None
    return ctx, gen


def trace_events(ctx, basename=None):
    q = """SELECT e.* FROM audit_event e JOIN file_inventory f USING (trace_id)
           WHERE f.run_id=%s {} ORDER BY e.trace_id, e.sequence_no"""
    if basename:
        return ctx.conn.execute(q.format("AND f.basename=%s"), (ctx.run_id, basename)).fetchall()
    return ctx.conn.execute(q.format(""), (ctx.run_id,)).fetchall()


def test_events_are_append_only_at_the_database(env):
    ctx, _ = one_file_run(env, generate=False)
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("UPDATE audit_event SET actor='x' WHERE run_id=%s", (ctx.run_id,))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("DELETE FROM audit_event WHERE run_id=%s", (ctx.run_id,))


def test_chain_order_and_verification_after_planning(env):
    ctx, _ = one_file_run(env)
    evs = trace_events(ctx, "a.mkv")
    assert [e["sequence_no"] for e in evs] == list(range(1, len(evs) + 1))
    assert [e["event_type"] for e in evs] == [
        "FILE_DISCOVERED", "FILE_HASH_STARTED", "FILE_HASHED", "CLASSIFICATION_REQUESTED",
        "CLASSIFICATION_RECEIVED", "ROUTE_ASSIGNED", "PLAN_OPERATION_CREATED", "BATCH_ASSIGNED"]
    assert evs[0]["previous_event_hash"].strip() == C.ZERO_HASH
    for a, b in zip(evs, evs[1:]):
        assert b["previous_event_hash"] == a["event_hash"]
    head = ctx.conn.execute("SELECT * FROM trace_head WHERE trace_id=%s", (evs[0]["trace_id"],)).fetchone()
    assert (head["sequence_no"], head["event_hash"]) == (evs[-1]["sequence_no"], evs[-1]["event_hash"])
    rep = A.verify_run_chain(ctx.conn, ctx.run_id)
    assert rep.ok and rep.traces_checked == 2 and rep.events_checked >= 9    # file trace + run trace


def test_concurrent_appends_to_one_trace_stay_linear(env):
    ctx, _ = one_file_run(env, generate=False)
    trace = ctx.conn.execute("SELECT trace_id, file_id FROM file_inventory WHERE run_id=%s", (ctx.run_id,)).fetchone()
    errors = []

    def worker(i):
        try:
            with db.connect(env.dsn) as c:
                for j in range(15):
                    with c.transaction():
                        A.append_event(c, ctx.run_id, A.EventSpec(trace["trace_id"], "PLAN_CREATED", f"w{i}", C.SRC_PYTHON, {"j": j}))
        except Exception as exc:                      # pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok


def _without_trigger(conn, fn):
    conn.execute("ALTER TABLE audit_event DISABLE TRIGGER audit_event_append_only")
    try:
        fn()
    finally:
        conn.execute("ALTER TABLE audit_event ENABLE TRIGGER audit_event_append_only")


def test_mutated_event_is_detected(env):
    ctx, _ = one_file_run(env)
    victim = trace_events(ctx, "a.mkv")[2]
    _without_trigger(ctx.conn, lambda: ctx.conn.execute(
        "UPDATE audit_event SET payload = payload || '{\"forged\": true}' WHERE event_id=%s", (str(victim["event_id"]),)))
    rep = A.verify_run_chain(ctx.conn, ctx.run_id)
    assert not rep.ok and "MUTATED_EVENT" in {p.kind for p in rep.problems}


def test_missing_event_is_detected(env):
    ctx, _ = one_file_run(env)
    victim = trace_events(ctx, "a.mkv")[3]
    _without_trigger(ctx.conn, lambda: ctx.conn.execute("DELETE FROM audit_event WHERE event_id=%s", (str(victim["event_id"]),)))
    kinds = {p.kind for p in A.verify_run_chain(ctx.conn, ctx.run_id).problems}
    assert "GAP" in kinds and "BROKEN_LINK" in kinds


def test_truncated_tail_is_detected_via_trace_head(env):
    ctx, _ = one_file_run(env)
    last = trace_events(ctx, "a.mkv")[-1]
    _without_trigger(ctx.conn, lambda: ctx.conn.execute("DELETE FROM audit_event WHERE event_id=%s", (str(last["event_id"]),)))
    assert "HEAD_MISMATCH" in {p.kind for p in A.verify_run_chain(ctx.conn, ctx.run_id).problems}


def test_file_without_events_is_reported(env):
    ctx, _ = one_file_run(env, generate=False)
    _without_trigger(ctx.conn, lambda: ctx.conn.execute("DELETE FROM audit_event WHERE run_id=%s AND file_id IS NOT NULL", (ctx.run_id,)))
    assert "NO_EVENTS" in {p.kind for p in A.verify_run_chain(ctx.conn, ctx.run_id).problems}


def event_types(ctx, name):
    return [e["event_type"] for e in trace_events(ctx, name)]


def test_full_event_history_of_a_moved_file(env):
    from migrator import reconcile
    ctx, gen = one_file_run(env)
    assert env.run_batch(Path(gen["batches"][0]["script"])).returncode == 0
    reconcile.reconcile(ctx)
    assert event_types(ctx, "a.mkv") == [
        "FILE_DISCOVERED", "FILE_HASH_STARTED", "FILE_HASHED", "CLASSIFICATION_REQUESTED", "CLASSIFICATION_RECEIVED",
        "ROUTE_ASSIGNED", "PLAN_OPERATION_CREATED", "BATCH_ASSIGNED", "BATCH_OPERATION_STARTED", "SOURCE_PRECHECK_OK",
        "COPY_STARTED", "COPY_FINISHED", "TEMP_TARGET_HASH_VERIFIED", "TARGET_COMMIT_STARTED", "TARGET_COMMITTED",
        "FINAL_TARGET_HASH_VERIFIED", "SOURCE_DELETE_STARTED", "SOURCE_DELETED", "OPERATION_COMPLETED",
        "RECONCILIATION_STARTED", "RECONCILIATION_VERIFIED"]
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok
    srcs = {e["source"] for e in trace_events(ctx, "a.mkv")}
    assert srcs == {"PYTHON", "BASH", "RECONCILER"}


def test_postgres_outage_keeps_events_in_spool_and_sync_imports_them(env):
    from migrator import reconcile
    ctx, gen = one_file_run(env)
    r = env.run_batch(Path(gen["batches"][0]["script"]), MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    assert r.returncode == 0, r.stderr                              # execution not blocked by the outage
    assert not (env.lib / "MOVIES" / "a.mkv").exists() is False
    counts = ctx.spool.counts()
    assert counts["events"] == 11 and counts["pending"] == 11
    assert "BATCH_OPERATION_STARTED" not in event_types(ctx, "a.mkv")     # DB has not seen them yet
    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert rep.ok and rep.imported == 11 and rep.bash_events_imported == 11
    assert ctx.spool.counts()["pending"] == 0
    assert "OPERATION_COMPLETED" in event_types(ctx, "a.mkv")
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok
    # importing again is idempotent
    before = len(trace_events(ctx))
    rep2 = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert rep2.ok and rep2.imported == 0 and len(trace_events(ctx)) == before
    # spool files are kept as historical evidence
    assert ctx.spool.counts()["events"] == 11


def test_events_are_pushed_directly_when_database_is_up(env):
    ctx, gen = one_file_run(env)
    assert env.run_batch(Path(gen["batches"][0]["script"])).returncode == 0
    assert ctx.spool.counts()["pending"] == 0
    assert "OPERATION_COMPLETED" in event_types(ctx, "a.mkv")


def test_sync_rejects_chains_that_do_not_connect_or_are_tampered(env):
    ctx, gen = one_file_run(env)
    env.run_batch(Path(gen["batches"][0]["script"]), MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    trace = ctx.spool.traces()[0]
    files = ctx.spool.event_files(trace)
    # 1) tampered payload
    p = files[3]
    d = json.loads(p.read_text())
    d["payload"]["forged"] = "yes"
    p.write_text(json.dumps(d))
    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert not rep.ok and "MUTATED_EVENT" in {x.kind for x in rep.problems}
    assert "OPERATION_COMPLETED" not in event_types(ctx, "a.mkv")        # nothing imported from a bad chain


def test_sync_reports_gap_when_a_spool_event_is_missing(env):
    ctx, gen = one_file_run(env)
    env.run_batch(Path(gen["batches"][0]["script"]), MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    trace = ctx.spool.traces()[0]
    ctx.spool.event_files(trace)[4].unlink()
    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert not rep.ok and rep.imported == 0 and "GAP" in {x.kind for x in rep.problems}


def test_sync_rejects_events_for_unknown_traces_and_divergent_chains(env):
    ctx, gen = one_file_run(env)
    spool = ctx.spool
    A.emit_event(spool, run_id=ctx.run_id, trace_id=str(uuid.uuid4()), event_type="COPY_STARTED", actor="x",
                 expect_sequence=1, expect_hash="a" * 64)
    trace = ctx.conn.execute("SELECT trace_id FROM file_inventory WHERE run_id=%s", (ctx.run_id,)).fetchone()["trace_id"]
    A.emit_event(spool, run_id=ctx.run_id, trace_id=str(trace), event_type="COPY_STARTED", actor="x",
                 expect_sequence=8, expect_hash="b" * 64)            # wrong previous hash
    rep = A.sync_spool(ctx.conn, ctx.run_id, spool)
    kinds = {p.kind for p in rep.problems}
    assert {"UNKNOWN_TRACE", "DIVERGED"} <= kinds and rep.imported == 0


def test_stale_batch_cannot_start_after_a_newer_plan(env):
    ctx, gen = one_file_run(env)
    planner.create_plan(ctx)                                        # revision 2 moves the trace heads on
    r = env.run_batch(Path(gen["batches"][0]["script"]))
    assert r.returncode == 2 and "stale" in r.stderr
    assert (env.src / "a.mkv").exists() and not (env.lib / "MOVIES" / "a.mkv").exists()
    assert not list(env.lib.rglob("*.partial"))


def test_audit_emit_cli_records_spool_then_database(env, monkeypatch):
    from typer.testing import CliRunner
    from migrator.cli import app
    ctx, gen = one_file_run(env)
    bo = ctx.conn.execute("""SELECT bo.*, po.trace_id, po.file_id FROM batch_operation bo JOIN plan_operation po USING (operation_id)""").fetchone()
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", env.dsn)
    args = ["audit", "emit", "--run", ctx.run_id, "--run-dir", str(ctx.run_dir), "--trace", str(bo["trace_id"]),
            "--operation", str(bo["operation_id"]), "--event", "COPY_STARTED", "--expect-sequence",
            str(bo["trace_head_sequence"]), "--expect-hash", bo["trace_head_hash"].strip(), "--kv", "temp=/x"]
    r = CliRunner().invoke(app, args)
    assert r.exit_code == 0, r.output
    ev = trace_events(ctx, "a.mkv")[-1]
    assert ev["event_type"] == "COPY_STARTED" and ev["source"] == "BASH" and ev["payload"] == {"temp": "/x"}
    assert ev["sequence_no"] == bo["trace_head_sequence"] + 1
    bad = CliRunner().invoke(app, ["audit", "emit", "--run", ctx.run_id, "--run-dir", str(ctx.run_dir), "--trace",
                                   str(bo["trace_id"]), "--event", "ROUTE_ASSIGNED", "--expect-sequence", "1",
                                   "--expect-hash", "a" * 64])
    assert bad.exit_code == 4
    st = CliRunner().invoke(app, ["audit", "status", "--run", ctx.run_id])
    assert st.exit_code == 0 and '"BASH": 1' in st.output


def test_audit_emit_does_not_touch_migration_files(env, monkeypatch):
    from tests.helpers import snapshot_tree
    ctx, gen = one_file_run(env)
    before = snapshot_tree(env.src, env.lib)
    bo = ctx.conn.execute("SELECT bo.*, po.trace_id FROM batch_operation bo JOIN plan_operation po USING (operation_id)").fetchone()
    A.emit_event(ctx.spool, run_id=ctx.run_id, trace_id=str(bo["trace_id"]), event_type="COPY_STARTED", actor="x",
                 expect_sequence=bo["trace_head_sequence"], expect_hash=bo["trace_head_hash"].strip(), dsn=env.dsn)
    assert snapshot_tree(env.src, env.lib) == before
