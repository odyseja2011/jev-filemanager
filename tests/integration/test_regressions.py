"""Regression tests for bugs found in code review."""
import csv
import shutil
from pathlib import Path

import pytest

from migrator import audit as A, batches, classifier, constants as C, db, inventory, planner, reconcile
from tests.fake_jev import FakeJev
from tests.integration.conftest import all_movies, ready_run

pytestmark = pytest.mark.postgres


@pytest.fixture()
def env(bare_env):
    return bare_env


def test_superseded_batch_cannot_run_even_after_it_touched_the_file(env):
    """Bug 1: the stale check ran only while the spool had no events for the trace."""
    ctx, _ = ready_run(env, {"a.mkv": b"payload"}, rules=all_movies)
    script = Path(batches.generate_batches(ctx)["batches"][0]["script"])
    # the batch starts, then is blocked (target exists with other content) -> spool now has events
    tgt = env.lib / "MOVIES" / "a.mkv"
    tgt.write_bytes(b"other")
    assert env.run_batch(script).returncode == 1
    tgt.unlink()
    planner.create_plan(ctx)                            # revision 2 supersedes the batch
    r = env.run_batch(script, VERIFY_SELF="0")         # skip the offline check to hit the DB check
    assert r.returncode == 2 and "stale" in r.stderr
    assert (env.src / "a.mkv").exists() and not tgt.exists()
    r = env.run_batch(script)                           # default preflight also refuses, even offline
    assert r.returncode == 2 and "superseded" in r.stderr
    r = env.run_batch(script, MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    assert r.returncode == 2 and (env.src / "a.mkv").exists()


def test_rerun_of_current_batch_after_reconcile_still_works(env):
    ctx, _ = ready_run(env, {"a.mkv": b"1", "b.mkv": b"2"}, rules=all_movies)
    script = Path(batches.generate_batches(ctx)["batches"][0]["script"])
    (env.src / "b.mkv").write_bytes(b"X")               # b blocked on the first pass
    env.run_batch(script)
    reconcile.reconcile(ctx)
    (env.src / "b.mkv").write_bytes(b"2")               # restored
    r = env.run_batch(script)
    assert "Already complete: 1" in r.stdout and "Success: 1" in r.stdout, r.stderr
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok


def test_interrupted_reconcile_can_be_retried(env):
    """Bug 2: a crash left the run in RECONCILING and every retry was rejected."""
    ctx, _ = ready_run(env, {"a.mkv": b"1"}, rules=all_movies)
    batches.generate_batches(ctx)

    def boom(*a, **k):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        reconcile.reconcile(ctx, hasher=boom)
    assert ctx.refresh()["state"] == C.RECONCILING
    res = reconcile.reconcile(ctx)
    assert res["outcomes"]["NOT_EXECUTED"] == 1 and ctx.refresh()["state"] == C.RECONCILED


def _review_csv(ctx, path, edits):
    classifier.export_review_csv(ctx, path)
    rows = list(csv.DictReader(path.open()))
    for r in rows:
        for name, (target, sid) in edits.items():
            if r["absolute_path"].endswith("/" + name):
                r["human_target"] = target
                if sid is not None:
                    r["subject_id"] = sid
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=classifier.REVIEW_COLUMNS)
        w.writeheader()
        w.writerows(rows)


def test_review_import_is_all_or_nothing(env, tmp_path):
    """Bug 3: a bad subject_id late in the file left earlier rows committed."""
    ctx, _ = ready_run(env, {"a.bin": b"1", "b.bin": b"2"}, rules=lambda s, q: ("REVIEW", 0.9))
    out = tmp_path / "r.csv"
    _review_csv(ctx, out, {"a.bin": ("BOOKS", None), "b.bin": ("BOOKS", "00000000-0000-0000-0000-000000000000")})
    before = ctx.conn.execute("SELECT count(*) AS n FROM route_decision").fetchone()["n"]
    with pytest.raises(classifier.ClassifyError, match="nothing was applied"):
        classifier.import_review_csv(ctx, out)
    assert ctx.conn.execute("SELECT count(*) AS n FROM route_decision").fetchone()["n"] == before
    _review_csv(ctx, out, {"a.bin": ("BOOKS", None), "b.bin": ("BOOKS", "not-a-uuid")})
    with pytest.raises(classifier.ClassifyError):
        classifier.import_review_csv(ctx, out)
    assert ctx.conn.execute("SELECT count(*) AS n FROM route_decision").fetchone()["n"] == before


@pytest.mark.parametrize("subtree", [False, True])
def test_human_decision_on_a_source_root_is_honoured(env, subtree):
    """Bug 4: decisions on a configured root were silently ignored."""
    from tests.helpers import write_files
    write_files(env.src, {"top.bin": b"1", "sub/deep.bin": b"2"})
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    fake = FakeJev(lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("REVIEW", 0.9))
    classifier.run_classification(ctx, fake)
    root = str(ctx.conn.execute("SELECT d.directory_id FROM directory_inventory d JOIN scan_root r USING (scan_root_id) "
                                "WHERE d.run_id=%s AND d.depth=0 AND r.root_type='SOURCE'",
                                (ctx.run_id,)).fetchone()["directory_id"])
    classifier.set_directory_target(ctx, root, "BOOKS", subtree=subtree)
    got = {r["basename"]: (r["route_status"], r["target_id"]) for r in ctx.conn.execute(
        "SELECT f.basename, fr.route_status, fr.target_id FROM file_route fr JOIN file_inventory f USING (file_id)")}
    assert got["top.bin"] == ("READY", "BOOKS")
    assert got["deep.bin"] == (("READY", "BOOKS") if subtree else ("REVIEW", None))
    n = len(fake.requests)
    classifier.run_classification(ctx, fake)
    assert not [q for q in fake.requests[n:] if q["state"].get("file_name") == "top.bin"]


def test_planning_before_audit_sync_imports_the_spool_first(env):
    """Bug 5: plan create before audit sync forked the chains permanently."""
    ctx, _ = ready_run(env, {"a.mkv": b"payload", "b.mkv": b"x"}, rules=all_movies)
    script = Path(batches.generate_batches(ctx)["batches"][0]["script"])
    (env.src / "b.mkv").write_bytes(b"y")               # keeps one file in play for a later plan
    env.run_batch(script, MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    assert ctx.spool.counts()["pending"] > 0
    planner.create_plan(ctx)                           # would previously fork the traces
    assert ctx.spool.counts()["pending"] == 0
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok
    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert rep.ok, rep.problems                         # previously: DIVERGED, forever


def test_unsyncable_spool_blocks_python_appends(env):
    ctx, _ = ready_run(env, {"a.mkv": b"payload"}, rules=all_movies)
    script = Path(batches.generate_batches(ctx)["batches"][0]["script"])
    env.run_batch(script, MIGRATOR_DATABASE_URL="host=/nonexistent dbname=x")
    f = ctx.spool.event_files(ctx.spool.traces()[0])[2]
    f.write_text(f.read_text().replace("COPY_STARTED", "COPY_FINISHED"))       # tampered
    with pytest.raises(A.AuditError):
        planner.create_plan(ctx)
    assert ctx.refresh()["state"] == C.BATCHES_GENERATED


def test_manifest_round_trips_backslash_t(env):
    """Bug 6: 'a\\tb' came back as 'a<TAB>b'."""
    names = {"a\\tb.mkv": b"1", "c\td.mkv": b"2", "e\\\\f.mkv": b"3", "g\\.mkv": b"4"}
    from tests.helpers import write_files
    write_files(env.src, names)
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    got = {r["relative_path"] for r in inventory.read_manifest(ctx.run_dir / "source-manifest.tsv0.gz")}
    assert got == set(names)
