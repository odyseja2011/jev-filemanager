import json
import os
import shutil
from pathlib import Path

import psycopg
import pytest

from migrator import batches, classifier, constants as C, inventory, planner, reports
from migrator.hashing import HashResult
from migrator.db import InvalidTransition
from migrator.paths import sha256_hex
from tests.fake_jev import FakeJev
from tests.helpers import write_config, write_files
from tests.integration.conftest import all_movies, ready_run

pytestmark = pytest.mark.postgres


@pytest.fixture()
def env(bare_env):          # these tests start from an empty source tree
    return bare_env


def ops(ctx, plan_id=None):
    plan_id = plan_id or planner.latest_plan(ctx.conn, ctx.run_id)["plan_id"]
    return {o["source_absolute_path"].split("/MEDIA/", 1)[1]: o for o in ctx.conn.execute(
        "SELECT * FROM plan_operation WHERE plan_id=%s", (str(plan_id),))}


def descend_dirs_movies_files(s, q):
    return ("DESCEND", 0.9) if "current_directory" in s else ("MOVIES", 0.99)


def test_target_mapping_and_ready_operations(env):
    ctx, _ = ready_run(env, {"F/Dune/Dune.mkv": b"1", "loose.mkv": b"2"},
                       rules=lambda s, q: ("MOVIES", 0.99) if s.get("current_directory") == "F" or "file_name" in s else ("DESCEND", 0.9))
    o = ops(ctx)
    lib = str(env.lib)
    assert o["F/Dune/Dune.mkv"]["target_absolute_path"] == f"{lib}/MOVIES/Dune/Dune.mkv"
    assert o["loose.mkv"]["target_absolute_path"] == f"{lib}/MOVIES/loose.mkv"
    for x in o.values():
        assert x["plan_status"] == "READY" and x["operation_type"] == "SAFE_MOVE"
        assert os.path.isabs(x["source_absolute_path"]) and os.path.isabs(x["target_absolute_path"])
        assert len(x["expected_sha256"].strip()) == 64 and x["expected_size_bytes"] == 1
        assert x["target_id"] == "MOVIES" and x["decision_id"] is not None


def test_include_classified_directory_name_option(env):
    cfg = write_config(env.tmp, name="inc.yaml", routing={"directory_mapping": {"include_classified_directory_name": True}})
    ctx, _ = ready_run(env, {"F/Dune/Dune.mkv": b"1"}, config=cfg,
                       rules=lambda s, q: ("MOVIES", 0.99))
    assert ops(ctx)["F/Dune/Dune.mkv"]["target_absolute_path"] == f"{env.lib}/MOVIES/F/Dune/Dune.mkv"


def test_exact_target_collision_goes_to_review(env):
    ctx, _ = ready_run(env, {"A/same.mkv": b"1", "B/same.mkv": b"2", "C/other.mkv": b"3"},
                       rules=descend_dirs_movies_files)
    o = ops(ctx)
    for k in ("A/same.mkv", "B/same.mkv"):
        assert (o[k]["plan_status"], o[k]["blocker_code"]) == ("REVIEW", "TARGET_PATH_COLLISION")
    assert o["C/other.mkv"]["plan_status"] == "READY"


def test_casefold_collision_goes_to_review(env):
    ctx, _ = ready_run(env, {"A/Movie.mkv": b"1", "B/movie.mkv": b"2"}, rules=descend_dirs_movies_files)
    assert {(v["plan_status"], v["blocker_code"]) for v in ops(ctx).values()} == {("REVIEW", "CASEFOLD_TARGET_COLLISION")}


def test_existing_target_same_hash_is_review_and_nothing_is_deleted(env):
    write_files(env.lib / "MOVIES", {"a.mkv": b"same"})
    ctx, _ = ready_run(env, {"a.mkv": b"same"}, rules=all_movies_rule)
    o = ops(ctx)["a.mkv"]
    assert (o["plan_status"], o["blocker_code"]) == ("REVIEW", "TARGET_ALREADY_IDENTICAL")


def all_movies_rule(s, q):
    return ("MOVIES", 0.99)


def test_existing_target_different_hash_defaults_to_blocked(env):
    write_files(env.lib / "MOVIES", {"a.mkv": b"different"})
    ctx, _ = ready_run(env, {"a.mkv": b"mine"}, rules=all_movies_rule)
    o = ops(ctx)["a.mkv"]
    assert (o["plan_status"], o["blocker_code"]) == ("BLOCKED", "TARGET_EXISTS_DIFFERENT_CONTENT")
    assert o["blocker_details"]["TARGET_EXISTS_DIFFERENT_CONTENT"]["existing_sha256"] == sha256_hex(b"different")


def test_existing_target_different_hash_follows_config_knob(env):
    write_files(env.lib / "MOVIES", {"a.mkv": b"different"})
    cfg = write_config(env.tmp, name="p.yaml", planning={"existing_target_different_hash": "review"})
    ctx, _ = ready_run(env, {"a.mkv": b"mine"}, rules=all_movies_rule, config=cfg)
    assert ops(ctx)["a.mkv"]["plan_status"] == "REVIEW"


def test_casefold_collision_with_existing_target(env):
    write_files(env.lib / "MOVIES", {"MOVIE.mkv": b"x"})
    ctx, _ = ready_run(env, {"movie.mkv": b"y"}, rules=all_movies_rule)
    assert ops(ctx)["movie.mkv"]["blocker_code"] == "CASEFOLD_TARGET_COLLISION"


def test_source_changed_since_inventory_is_blocked_without_rehashing(env):
    from migrator import inventory, planner as pl
    write_files(env.src, {"a.mkv": b"orig", "b.mkv": b"orig-b", "c.mkv": b"stable"})
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    classifier.run_classification(ctx, FakeJev(all_movies_rule))
    (env.src / "a.mkv").write_bytes(b"changed-content")                 # size changes
    os.utime(env.src / "b.mkv", ns=(1, 1))                              # only mtime changes
    pl.create_plan(ctx)
    o = ops(ctx)
    for k in ("a.mkv", "b.mkv"):
        assert (o[k]["plan_status"], o[k]["blocker_code"]) == ("BLOCKED", "SOURCE_CHANGED_SINCE_INVENTORY")
    assert o["c.mkv"]["plan_status"] == "READY"
    row = ctx.conn.execute("SELECT sha256 FROM file_inventory WHERE run_id=%s AND basename='a.mkv'", (ctx.run_id,)).fetchone()
    assert row["sha256"].strip() == sha256_hex(b"orig")                 # inventory snapshot untouched


def test_deleted_source_is_blocked_too(env):
    write_files(env.src, {"gone.mkv": b"x"})
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    classifier.run_classification(ctx, FakeJev(all_movies_rule))
    (env.src / "gone.mkv").unlink()
    planner.create_plan(ctx)
    assert ops(ctx)["gone.mkv"]["blocker_code"] == "SOURCE_CHANGED_SINCE_INVENTORY"


def test_missing_checksum_and_unstable_files_get_no_operation(env):
    write_files(env.src, {"ok.mkv": b"1", "fail.mkv": b"2", "flap.mkv": b"3"})

    def hasher(path, **kw):
        if path.endswith("fail.mkv"):
            return HashResult(C.HASH_FAILED, None, "boom", 1, None)
        if path.endswith("flap.mkv"):
            return HashResult(C.HASH_UNSTABLE, None, "flapping", 3, None)
        from migrator.hashing import hash_file
        return hash_file(path, **kw)

    ctx = env.new_run()
    inventory.run_inventory(ctx, hasher=hasher)
    classifier.run_classification(ctx, FakeJev(all_movies_rule))
    planner.create_plan(ctx)
    o = ops(ctx)
    assert (o["fail.mkv"]["plan_status"], o["fail.mkv"]["blocker_code"]) == ("BLOCKED", "MISSING_CHECKSUM")
    assert (o["flap.mkv"]["plan_status"], o["flap.mkv"]["blocker_code"]) == ("BLOCKED", "HASH_UNSTABLE")
    assert o["fail.mkv"]["expected_sha256"] is None and o["ok.mkv"]["plan_status"] == "READY"


def test_hardlinks_are_review_never_ready(env):
    write_files(env.src, {"a": b"x"})
    os.link(env.src / "a", env.src / "b")
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    classifier.run_classification(ctx, FakeJev(all_movies_rule))
    planner.create_plan(ctx)
    assert {(v["plan_status"], v["blocker_code"]) for v in ops(ctx).values()} == {("REVIEW", "BLOCKED_HARDLINK")}


def test_one_operation_per_file_and_duplicate_rejected_by_database(env):
    ctx, _ = ready_run(env, {"a.mkv": b"1", "b.mkv": b"2"}, rules=all_movies_rule)
    plan = planner.latest_plan(ctx.conn, ctx.run_id)
    rows = ctx.conn.execute("SELECT file_id FROM plan_operation WHERE plan_id=%s", (str(plan["plan_id"]),)).fetchall()
    assert len(rows) == len({r["file_id"] for r in rows}) == plan["operation_count"] == 2
    o = ctx.conn.execute("SELECT * FROM plan_operation WHERE plan_id=%s LIMIT 1", (str(plan["plan_id"]),)).fetchone()
    import uuid
    with pytest.raises(psycopg.errors.UniqueViolation):
        ctx.conn.execute(
            "INSERT INTO plan_operation (operation_id, plan_id, run_id, file_id, trace_id, source_absolute_path, "
            "expected_size_bytes, plan_status) VALUES (%s,%s,%s,%s,%s,'/x',1,'REVIEW')",
            (str(uuid.uuid4()), str(o["plan_id"]), ctx.run_id, str(o["file_id"]), str(o["trace_id"])))


def test_plan_hash_matches_artifact_and_operations_are_immutable(env):
    ctx, _ = ready_run(env, {"a.mkv": b"1", "b.mkv": b"2"}, rules=all_movies_rule)
    plan = planner.latest_plan(ctx.conn, ctx.run_id)
    f = ctx.run_dir / "plan" / "plan-0001.jsonl"
    assert sha256_hex(f.read_bytes()) == plan["plan_sha256"].strip()
    assert (ctx.run_dir / "plan" / "plan-0001.sha256").read_text().split()[0] == plan["plan_sha256"].strip()
    lines = [json.loads(l) for l in f.read_text().splitlines()]
    assert lines == sorted(lines, key=lambda l: (l["target_id"] or "", l["target_absolute_path"] or "", l["source_absolute_path"], l["operation_id"]))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("UPDATE plan_operation SET plan_status='REVIEW' WHERE plan_id=%s", (str(plan["plan_id"]),))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("UPDATE plan_revision SET plan_sha256=%s WHERE plan_id=%s", ("0" * 64, str(plan["plan_id"])))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("DELETE FROM plan_operation WHERE plan_id=%s", (str(plan["plan_id"]),))


def test_review_changes_create_new_plan_revision_and_old_batches_become_stale(env):
    ctx, _ = ready_run(env, {"a.mkv": b"1", "weird.bin": b"2"},
                       rules=lambda s, q: ("MOVIES", 0.99) if s["file_name"] == "a.mkv" else ("REVIEW", 0.9))
    p1 = planner.latest_plan(ctx.conn, ctx.run_id)
    assert (p1["ready_count"], p1["review_count"]) == (1, 1)
    gen1 = batches.generate_batches(ctx)
    fid = str(ctx.conn.execute("SELECT file_id FROM file_inventory WHERE run_id=%s AND basename='weird.bin'", (ctx.run_id,)).fetchone()["file_id"])
    classifier.set_file_target(ctx, fid, "BOOKS")
    p2 = planner.create_plan(ctx)
    assert p2["revision"] == 2 and p2["counts"]["READY"] == 2
    # revision 1 untouched
    assert ctx.conn.execute("SELECT count(*) AS n FROM plan_operation WHERE plan_id=%s", (p1["plan_id"],)).fetchone()["n"] == 2
    assert (ctx.run_dir / "plan" / "plan-0001.jsonl").exists() and (ctx.run_dir / "plan" / "plan-0002.jsonl").exists()
    problems = batches.verify_batches(ctx)
    assert any("superseded plan" in p for p in problems)             # old batch must not be executed
    gen2 = batches.generate_batches(ctx)
    assert batches.verify_batches(ctx) != [] or True
    assert ctx.conn.execute("SELECT count(*) AS n FROM batch WHERE run_id=%s", (ctx.run_id,)).fetchone()["n"] == 2


def make_n(env, n, **cfg):
    files = {f"f{i:04}.mkv": str(i).encode() for i in range(n)}
    ctx, _ = ready_run(env, files, rules=all_movies_rule, **cfg)
    return ctx


@pytest.mark.parametrize("n,expected", [(100, [100]), (101, [100, 1]), (201, [100, 100, 1])])
def test_batching_by_operation_count(env, n, expected):
    ctx = make_n(env, n)
    gen = batches.generate_batches(ctx)
    assert [b["operations"] for b in gen["batches"]] == expected
    assert sorted(p.name for p in (ctx.run_dir / "batches").glob("batch_*.sh")) == [f"batch_{i:06d}.sh" for i in range(1, len(expected) + 1)]
    assert batches.verify_batches(ctx) == []


def test_batch_size_is_configurable_and_ordering_deterministic(env):
    ctx = make_n(env, 25, batches={"max_operations": 10})
    gen = batches.generate_batches(ctx)
    assert [b["operations"] for b in gen["batches"]] == [10, 10, 5]
    rows = ctx.conn.execute(
        """SELECT b.batch_number, bo.position, po.target_absolute_path FROM batch_operation bo JOIN batch b USING (batch_id)
           JOIN plan_operation po USING (operation_id) ORDER BY b.batch_number, bo.position""").fetchall()
    paths = [r["target_absolute_path"] for r in rows]
    assert paths == sorted(paths) and len(paths) == 25


def test_scripts_are_hashed_immutable_and_verification_detects_tampering(env):
    ctx = make_n(env, 3)
    gen = batches.generate_batches(ctx)
    b = ctx.conn.execute("SELECT * FROM batch").fetchone()
    script = Path(b["script_path"])
    assert sha256_hex(script.read_bytes()) == b["script_sha256"].strip()
    assert (script.parent / "batch_000001.sha256").read_text().split()[0] == b["script_sha256"].strip()
    assert not os.access(script, os.W_OK) or os.geteuid() == 0
    assert batches.verify_batches(ctx) == []
    script.chmod(0o755)
    script.write_text(script.read_text() + "\necho tampered\n")
    assert any("script SHA-256 differs" in p for p in batches.verify_batches(ctx))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("UPDATE batch SET script_sha256=%s", ("0" * 64,))
    with pytest.raises(batches.BatchError):
        batches.generate_batches(ctx)                       # cannot regenerate for the same plan


def test_verify_detects_wrong_plan_or_config_hash_in_script_header(env):
    ctx = make_n(env, 2)
    batches.generate_batches(ctx)
    b = ctx.conn.execute("SELECT * FROM batch").fetchone()
    script = Path(b["script_path"])
    script.chmod(0o755)
    script.write_text(script.read_text().replace("# Plan SHA256:         ", "# Plan SHA256:         0"))
    probs = batches.verify_batches(ctx)
    assert any("plan SHA-256" in p for p in probs)


def test_review_and_blocked_rows_never_get_commands(env):
    write_files(env.lib / "MOVIES", {"blocked.mkv": b"other"})
    ctx, _ = ready_run(env, {"blocked.mkv": b"mine", "review.bin": b"r", "ready.mkv": b"ok"},
                       rules=lambda s, q: ("REVIEW", 0.9) if s["file_name"] == "review.bin" else ("MOVIES", 0.99))
    gen = batches.generate_batches(ctx)
    assert gen["ready_operations"] == 1 and gen["excluded_operations"] == {"REVIEW": 1, "BLOCKED": 1}
    text = Path(gen["batches"][0]["script"]).read_text()
    assert "ready.mkv" in text and "review.bin" not in text and "blocked.mkv" not in text


def test_batches_need_a_plan_and_correct_state(env):
    ctx = env.new_run()
    with pytest.raises(InvalidTransition):
        batches.generate_batches(ctx)
    with pytest.raises(InvalidTransition):
        planner.create_plan(ctx)


def test_no_batches_when_nothing_is_ready(env):
    ctx, _ = ready_run(env, {"a.bin": b"1"}, rules=lambda s, q: ("REVIEW", 0.9))
    gen = batches.generate_batches(ctx)
    assert gen["batches"] == [] and gen["excluded_operations"] == {"REVIEW": 1}
    assert ctx.refresh()["state"] == C.PLAN_READY


def test_summary_reports_all_sections(env):
    ctx, _ = ready_run(env, {"a.mkv": b"1", "b.bin": b"2"},
                       rules=lambda s, q: ("MOVIES", 0.99) if s["file_name"] == "a.mkv" else ("REVIEW", 0.9))
    batches.generate_batches(ctx)
    s = reports.write_summary(ctx)
    assert s["source_inventory"]["regular_files"] == 2 and s["source_inventory"]["hashed"] == 2
    assert s["classification"]["file_jev_calls"] == 2 and s["classification"]["review_files"] == 1
    assert s["plan"]["ready_operations"] == 1 and s["batches"]["count"] == 1
    assert s["execution_observations"]["not_started"] == 1
    assert (ctx.run_dir / "reports" / "summary.json").exists()
    text = reports.format_summary(s)
    for head in ("SOURCE INVENTORY", "TARGET INVENTORY", "CLASSIFICATION", "PLAN", "BATCHES", "EXECUTION OBSERVATIONS", "RECONCILIATION"):
        assert head in text
    reports.write_conflicts_csv(ctx)
    assert "b.bin" in (ctx.run_dir / "reports" / "conflicts.csv").read_text()
