"""RELEASE-BLOCKING: every Python command leaves source and target trees byte-for-byte unchanged.
Only the generated Bash, executed by a human, changes them."""
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from migrator import cli
from migrator.cli import app
from tests.fake_jev import FakeJev, standard_rules
from tests.helpers import snapshot_tree

pytestmark = pytest.mark.postgres

runner = CliRunner()


def test_python_never_mutates_migration_files(env, monkeypatch):
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", env.dsn)
    fake = FakeJev(standard_rules)
    monkeypatch.setattr(cli, "make_jev_client", lambda cfg: fake)
    (env.src / "MULTIMEDIA" / "Unsorted" / "extra.bin").write_bytes(b"x")
    baseline = snapshot_tree(env.src, env.lib)
    assert baseline

    def step(*args, ok=(0,)):
        r = runner.invoke(app, list(map(str, args)))
        assert r.exit_code in ok, (args, r.output, r.exception)
        after = snapshot_tree(env.src, env.lib)
        assert after == baseline, f"{args[0]} {args[1] if len(args) > 1 else ''} mutated migration files"
        return r

    r = step("run", "create", "--config", env.config)
    run_id = next(l.split("=", 1)[1] for l in r.output.splitlines() if l.startswith("RUN_ID="))
    step("run", "status", "--run", run_id)
    step("inventory", "--run", run_id)
    step("run", "summary", "--run", run_id)
    step("classify", "--run", run_id)
    step("review", "list", "--run", run_id)
    review_csv = env.tmp / "review-out" / "review.csv"
    step("review", "export", "--run", run_id, "--output", review_csv)
    step("review", "import", "--run", run_id, "--input", review_csv)
    ctx = cli._open(run_id)
    fid = str(ctx.conn.execute("SELECT file_id FROM file_inventory WHERE run_id=%s AND basename='weird.bin'",
                               (run_id,)).fetchone()["file_id"])
    did = str(ctx.conn.execute("SELECT directory_id FROM directory_inventory WHERE run_id=%s AND basename='Lowconf'",
                               (run_id,)).fetchone()["directory_id"])
    step("review", "set", "--run", run_id, "--file", fid, "--target", "BOOKS")
    step("review", "set-directory", "--run", run_id, "--directory", did, "--target", "MUSIC", "--subtree")
    step("plan", "create", "--run", run_id)
    step("plan", "show", "--run", run_id)
    step("plan", "conflicts", "--run", run_id)
    step("batches", "generate", "--run", run_id)
    step("batches", "list", "--run", run_id)
    step("batches", "verify", "--run", run_id)
    bo = ctx.conn.execute("SELECT bo.*, po.trace_id FROM batch_operation bo JOIN plan_operation po USING (operation_id) LIMIT 1").fetchone()
    step("audit", "emit", "--run", run_id, "--run-dir", ctx.run_dir, "--trace", bo["trace_id"], "--operation", bo["operation_id"],
         "--event", "COPY_STARTED", "--expect-sequence", bo["trace_head_sequence"], "--expect-hash", bo["trace_head_hash"].strip())
    step("audit", "status", "--run", run_id)
    step("audit", "sync", "--run", run_id)
    step("audit", "verify-chain", "--run", run_id)
    step("reconcile", "--run", run_id)
    step("run", "summary", "--run", run_id)
    step("audit", "verify-chain", "--run", run_id)

    # Only now does anything change: a human executes the generated batch.
    scripts = sorted((ctx.run_dir / "batches").glob("batch_*.sh"))
    assert scripts
    r = env.run_batch(scripts[0])
    assert snapshot_tree(env.src, env.lib) != baseline
    assert r.returncode in (0, 1), r.stderr


def test_prepare_convenience_command_never_executes_batches(env, monkeypatch):
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", env.dsn)
    monkeypatch.setattr(cli, "make_jev_client", lambda cfg: FakeJev(standard_rules))
    baseline = snapshot_tree(env.src, env.lib)
    r = runner.invoke(app, ["prepare", "--config", str(env.config)])
    assert r.exit_code == 0, (r.output, r.exception)
    for label in ("Run ID", "Files discovered", "Files hashed", "Files routed automatically", "Files awaiting review",
                  "Files blocked", "Operations ready", "Generated batches", "Batch directory"):
        assert label in r.output
    assert "Nothing was executed" in r.output
    assert snapshot_tree(env.src, env.lib) == baseline


def test_workspace_is_the_only_place_python_writes(env, monkeypatch):
    """Everything the application creates lives under the workspace (plus the review CSV path the operator chose)."""
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", env.dsn)
    monkeypatch.setattr(cli, "make_jev_client", lambda cfg: FakeJev(standard_rules))
    before = {p for p in env.tmp.rglob("*")}
    r = runner.invoke(app, ["prepare", "--config", str(env.config)])
    assert r.exit_code == 0
    new = {p for p in env.tmp.rglob("*")} - before
    assert new and all(str(env.ws) in str(p) for p in new), [str(p) for p in new if str(env.ws) not in str(p)]


def test_a_guarded_writer_refuses_paths_under_migration_roots(env):
    from migrator.paths import PathSafetyError, write_new_file
    ctx = env.new_run()
    with pytest.raises(PathSafetyError):
        write_new_file(env.src / "x", b"1", guard=ctx.guard)
    with pytest.raises(PathSafetyError):
        write_new_file(env.lib / "MOVIES" / "x", b"1", guard=ctx.guard)
