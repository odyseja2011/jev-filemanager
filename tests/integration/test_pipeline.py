import os
from pathlib import Path

import pytest

from migrator import audit as A
from migrator import batches, classifier, constants as C, inventory, planner, reconcile, reports
from migrator.runs import open_run

pytestmark = pytest.mark.postgres


def full_prepare(env, fake, **kw):
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    classifier.run_classification(ctx, fake)
    return ctx


def test_inventory_counts_symlinks_hardlinks(env):
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    s = reports.run_summary(ctx)["source_inventory"]
    assert s["regular_files"] == 11
    assert s["symlinks_skipped"] == 2
    assert s["hardlinks_blocked"] == 2
    assert s["hashed"] == 9
    assert ctx.refresh()["state"] == C.INVENTORY_COMPLETE
    for name in ("source-manifest.tsv0.gz", "source-manifest.sha256", "target-manifest.tsv0.gz"):
        assert (ctx.run_dir / name).exists()
    rows = list(inventory.read_manifest(ctx.run_dir / "source-manifest.tsv0.gz"))
    assert {r["relative_path"] for r in rows} >= {"loose book.epub"}
    assert all(os.path.isabs(r["absolute_path"]) for r in rows)


def test_classification_routes(env, fake):
    ctx = full_prepare(env, fake)
    routes = {r["absolute_path"].removeprefix(str(env.src) + "/"): r for r in ctx.conn.execute(
        "SELECT f.absolute_path, fr.* FROM file_route fr JOIN file_inventory f USING (file_id) WHERE fr.run_id=%s",
        (ctx.run_id,))}
    assert routes["MULTIMEDIA/FILMY/Dune/Dune.mkv"]["target_id"] == "MOVIES"
    assert routes["MULTIMEDIA/FILMY/Dune/Dune.mkv"]["route_origin_type"] == C.ROUTE_INHERITED
    assert routes["MULTIMEDIA/SERIALE/Show/S01E01.mkv"]["target_id"] == "SERIES"
    assert routes["MULTIMEDIA/Unsorted/Blade Runner (2017).mkv"]["route_origin_type"] == C.ROUTE_DIRECT
    assert routes["MULTIMEDIA/Unsorted/weird.bin"]["route_status"] == C.ROUTE_REVIEW
    assert routes["MULTIMEDIA/Unsorted/maybe.mkv"]["reason_code"] == "LOW_CONFIDENCE"
    assert routes["loose book.epub"]["target_id"] == "BOOKS"
    # low-confidence directory was descended; its files were classified individually
    assert routes["Lowconf/song.mp3"]["target_id"] == "MUSIC"
    assert routes["hard_a.bin"]["route_status"] == C.ROUTE_REVIEW
    assert routes["hard_a.bin"]["reason_code"] == "BLOCKED_HARDLINK"
    # FILMY was classified as a subtree: no Jev calls below it
    assert not [r for r in fake.directory_requests if r["state"]["current_directory"] in ("Dune", "Alien")]
    assert ctx.refresh()["state"] == C.REVIEW_REQUIRED


def test_full_lifecycle_with_real_bash(env, fake):
    ctx = full_prepare(env, fake)
    res = planner.create_plan(ctx)
    assert res["counts"]["READY"] == 7
    gen = batches.generate_batches(ctx)
    assert len(gen["batches"]) == 1
    assert gen["excluded_operations"]["REVIEW"] == 4
    assert batches.verify_batches(ctx) == []
    target_dune = env.lib / "MOVIES" / "Dune" / "Dune.mkv"
    assert not target_dune.exists()

    script = Path(gen["batches"][0]["script"])
    r = env.run_batch(script)
    assert r.returncode == 0, r.stderr
    assert "Success: 7" in r.stdout
    assert target_dune.read_bytes() == b"dune-data"
    assert not (env.src / "MULTIMEDIA/FILMY/Dune/Dune.mkv").exists()
    assert (env.src / "MULTIMEDIA/Unsorted/weird.bin").exists()   # review file untouched
    assert (env.lib / "MOVIES" / "Blade Runner (2017).mkv").exists()
    assert not list(env.lib.rglob("*.partial"))

    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert rep.ok, rep.problems
    rec = reconcile.reconcile(ctx)
    assert rec["outcomes"][C.REC_VERIFIED_MOVED] == 7
    chain = A.verify_run_chain(ctx.conn, ctx.run_id)
    assert chain.ok, [str(p) for p in chain.problems]

    # rerun is idempotent
    r2 = env.run_batch(script)
    assert r2.returncode == 0 and "Already complete: 7" in r2.stdout
    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    assert rep.ok
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok
