import json
import re

import pytest

from migrator import classifier, constants as C, inventory
from migrator.jev import JevError
from tests.fake_jev import FakeJev
from tests.helpers import write_config, write_files

pytestmark = pytest.mark.postgres

ALLOWED_DIR = {"current_directory", "ancestor_names", "child_directory_names", "file_names"}
ALLOWED_FILE = {"file_name", "ancestor_names"}


def classify(env, files, rules, cfg_path=None, fake=None):
    write_files(env.src, files)
    ctx = env.new_run(cfg_path)
    inventory.run_inventory(ctx)
    fake = fake or FakeJev(rules)
    res = classifier.run_classification(ctx, fake)
    return ctx, fake, res


def routes(ctx):
    return {r["absolute_path"].split("/MEDIA/", 1)[1]: r for r in ctx.conn.execute(
        "SELECT f.absolute_path, fr.* FROM file_route fr JOIN file_inventory f USING (file_id) "
        "WHERE fr.run_id = %s", (ctx.run_id,))}


def test_high_confidence_directory_routes_whole_subtree_and_stops_recursion(bare_env):
    ctx, fake, _ = classify(bare_env, {"FILMY/Dune/Dune.mkv": b"1", "FILMY/Alien/a/b/Alien.mkv": b"2"},
                            lambda s, q: ("MOVIES", 0.97))
    r = routes(ctx)
    assert {v["target_id"] for v in r.values()} == {"MOVIES"}
    assert {v["route_origin_type"] for v in r.values()} == {C.ROUTE_INHERITED}
    assert [x["state"]["current_directory"] for x in fake.directory_requests] == ["FILMY"]
    assert fake.file_requests == []
    fd = ctx.conn.execute("SELECT directory_id FROM directory_inventory WHERE run_id=%s AND basename='FILMY'",
                          (ctx.run_id,)).fetchone()["directory_id"]
    assert {str(v["route_directory_id"]) for v in r.values()} == {str(fd)}


def test_descend_choice_classifies_children_and_files_separately(bare_env):
    def rules(s, q):
        if "current_directory" in s:
            return ("DESCEND", 0.99) if s["current_directory"] == "MIX" else ("MUSIC", 0.95)
        return ("BOOKS", 0.96)
    ctx, fake, _ = classify(bare_env, {"MIX/song/a.mp3": b"1", "MIX/loose.epub": b"2"}, rules)
    r = routes(ctx)
    assert r["MIX/song/a.mp3"]["target_id"] == "MUSIC" and r["MIX/song/a.mp3"]["route_origin_type"] == C.ROUTE_INHERITED
    assert r["MIX/loose.epub"]["target_id"] == "BOOKS" and r["MIX/loose.epub"]["route_origin_type"] == C.ROUTE_DIRECT


def test_descend_wins_regardless_of_confidence(bare_env):
    ctx, fake, _ = classify(bare_env, {"D/a.mkv": b"1"},
                            lambda s, q: ("DESCEND", 0.01) if "current_directory" in s else ("MOVIES", 0.99))
    assert routes(ctx)["D/a.mkv"]["route_origin_type"] == C.ROUTE_DIRECT


def test_low_confidence_directory_is_descended_not_assigned(bare_env):
    def rules(s, q):
        return ("MUSIC", 0.60) if "current_directory" in s else ("MUSIC", 0.95)
    ctx, fake, _ = classify(bare_env, {"D/a.mp3": b"1", "D/sub/b.mp3": b"2"}, rules)
    r = routes(ctx)
    assert r["D/a.mp3"]["route_origin_type"] == C.ROUTE_DIRECT       # decided at file level
    assert {x["state"]["current_directory"] for x in fake.directory_requests} == {"D", "sub"}


def test_threshold_applies_to_confidence_not_to_winning_probability(bare_env):
    class Odd(FakeJev):
        def decide(self, request):
            resp = super().decide(request)
            resp.probabilities = {k: (0.99 if k == resp.choice else 0.0) for k in resp.probabilities}
            return resp
    fake = Odd(lambda s, q: ("MOVIES", 0.50))
    ctx, _, _ = classify(bare_env, {"a.mkv": b"1"}, None, fake=fake)
    assert routes(ctx)["a.mkv"]["route_status"] == C.ROUTE_REVIEW
    d = ctx.conn.execute("SELECT confidence, probabilities FROM route_decision WHERE run_id=%s", (ctx.run_id,)).fetchone()
    assert d["confidence"] == 0.5 and max(d["probabilities"].values()) == 0.99   # both saved


def test_configured_threshold_boundary_is_inclusive(bare_env):
    ctx, _, _ = classify(bare_env, {"a.mkv": b"1", "b.mkv": b"2"},
                         lambda s, q: ("MOVIES", 0.90 if s["file_name"] == "a.mkv" else 0.8999))
    r = routes(ctx)
    assert r["a.mkv"]["route_status"] == "READY" and r["b.mkv"]["route_status"] == "REVIEW"


def test_file_review_choice_and_low_confidence_file(bare_env):
    ctx, _, res = classify(bare_env, {"a.bin": b"1", "b.mkv": b"2", "c.mkv": b"3"},
                           lambda s, q: {"a.bin": ("REVIEW", 0.99), "b.mkv": ("MOVIES", 0.7),
                                         "c.mkv": ("MOVIES", 0.95)}[s["file_name"]])
    r = routes(ctx)
    assert (r["a.bin"]["route_status"], r["a.bin"]["reason_code"]) == ("REVIEW", "JEV_REVIEW")
    assert (r["b.mkv"]["route_status"], r["b.mkv"]["reason_code"]) == ("REVIEW", "LOW_CONFIDENCE")
    assert r["c.mkv"]["route_status"] == "READY"
    assert res["state"] == C.REVIEW_REQUIRED and (res["ready"], res["review"]) == (1, 2)


def test_all_confident_run_is_classified(bare_env):
    _, _, res = classify(bare_env, {"a.mkv": b"1"}, lambda s, q: ("MOVIES", 0.99))
    assert res["state"] == C.CLASSIFIED


def test_api_failure_goes_to_review_without_guessing(bare_env):
    def rules(s, q):
        if s.get("file_name") == "bad.mkv":
            return JevError("giving up after 4 attempts: HTTP 503", retryable=True)
        return ("MOVIES", 0.99)
    ctx, fake, res = classify(bare_env, {"good.mkv": b"1", "bad.mkv": b"2"}, rules)
    r = routes(ctx)
    assert (r["bad.mkv"]["route_status"], r["bad.mkv"]["reason_code"]) == ("REVIEW", "CLASSIFICATION_API_FAILED")
    assert r["good.mkv"]["route_status"] == "READY"
    d = ctx.conn.execute("SELECT * FROM route_decision WHERE decision_status='API_FAILED'").fetchone()
    assert "503" in d["error_text"] and d["selected_choice"] is None
    ev = [x["event_type"] for x in ctx.conn.execute(
        "SELECT event_type FROM audit_event e JOIN file_inventory f USING (trace_id) WHERE f.basename='bad.mkv' "
        "ORDER BY sequence_no")]
    assert "CLASSIFICATION_API_FAILED" in ev and "ROUTE_ASSIGNED" not in ev
    # no fallback model: every request used the configured model
    assert {q["model"] for q in fake.requests} == {"typesafe/jev-1.13"}
    # re-running classification retries only the failed item
    fake2 = FakeJev(lambda s, q: ("MOVIES", 0.99))
    classifier.run_classification(ctx, fake2)
    assert [q["state"]["file_name"] for q in fake2.file_requests] == ["bad.mkv"]
    assert routes(ctx)["bad.mkv"]["route_status"] == "READY"


def test_directory_api_failure_holds_the_whole_subtree(bare_env):
    ctx, _, _ = classify(bare_env, {"D/a.mkv": b"1", "D/x/b.mkv": b"2"},
                         lambda s, q: JevError("timeout", retryable=True))
    assert {(v["route_status"], v["reason_code"]) for v in routes(ctx).values()} == \
        {("REVIEW", "CLASSIFICATION_API_FAILED")}


def test_max_depth_leaves_deeper_files_in_review(bare_env):
    cfg = write_config(bare_env.tmp, name="d.yaml", routing={"max_depth": 2})
    files = {"a/b/c/d/deep.mkv": b"1", "a/b/shallow.mkv": b"2"}
    ctx, fake, _ = classify(bare_env, files,
                            lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("MOVIES", 0.99), cfg)
    r = routes(ctx)
    assert (r["a/b/c/d/deep.mkv"]["route_status"], r["a/b/c/d/deep.mkv"]["reason_code"]) == ("REVIEW", "MAX_DEPTH")
    assert r["a/b/shallow.mkv"]["route_status"] == "READY"
    assert {x["state"]["current_directory"] for x in fake.directory_requests} == {"a", "b"}


def test_empty_directories_cause_no_requests(bare_env):
    (bare_env.src / "empty" / "nested").mkdir(parents=True)
    ctx, fake, _ = classify(bare_env, {"a.mkv": b"1"}, lambda s, q: ("MOVIES", 0.99))
    assert fake.directory_requests == []


def test_jev_receives_names_only(bare_env):
    files = {"FILMY/Dune (2021).mkv": b"x" * 1234567, "FILMY/sub/Alien.mkv": b"y" * 7654321, "root.epub": b"z" * 999983}
    ctx, fake, _ = classify(bare_env, files, lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("MOVIES", 0.99))
    assert fake.requests
    forbidden = [r["sha256"].strip() for r in ctx.conn.execute("SELECT sha256 FROM file_inventory WHERE run_id=%s", (ctx.run_id,))]
    forbidden += [str(r["size_bytes"]) for r in ctx.conn.execute("SELECT size_bytes FROM file_inventory WHERE run_id=%s", (ctx.run_id,))]
    forbidden += [str(r["mtime_ns"]) for r in ctx.conn.execute("SELECT mtime_ns FROM file_inventory WHERE run_id=%s", (ctx.run_id,))]
    forbidden += [str(r["st_ino"]) for r in ctx.conn.execute("SELECT st_ino FROM file_inventory WHERE run_id=%s", (ctx.run_id,))]
    for req in fake.requests:
        assert set(req) == {"model", "state", "questions"}
        allowed = ALLOWED_DIR if "current_directory" in req["state"] else ALLOWED_FILE
        assert set(req["state"]) == allowed
        for v in req["state"].values():
            assert isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))
        blob = json.dumps(req)
        for bad in forbidden:
            assert bad not in blob, bad
        assert not re.search(r"\b[0-9a-f]{64}\b", blob)
        assert not re.search(r"(?i)\b(uid|gid|acl|mtime|ctime|owner|sha256|size)\b", json.dumps(req["state"]))
        assert set(req["questions"]) == {"route"} and req["questions"]["route"]["type"] == "choice"
        crit = set(req["questions"]["route"]["criteria"])
        targets = {"MOVIES", "SERIES", "MUSIC", "BOOKS"}
        assert crit in (targets | {"DESCEND"}, targets | {"REVIEW"})       # Jev cannot invent destinations


def test_states_are_deterministic_across_runs(bare_env):
    files = {f"D/{i:03}.mkv": b"1" for i in range(300)} | {f"D/sub{i}/x.mkv": b"1" for i in range(150)}
    nocache = write_config(bare_env.tmp, name="nc.yaml", routing={"cache_decisions": False})
    _, f1, _ = classify(bare_env, files, lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("REVIEW", 0.9),
                        cfg_path=nocache)
    ctx2 = bare_env.new_run(nocache)
    inventory.run_inventory(ctx2)
    f2 = FakeJev(lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("REVIEW", 0.9))
    classifier.run_classification(ctx2, f2)
    strip = lambda f: sorted(json.dumps(r["state"], sort_keys=True) for r in f.directory_requests)
    assert strip(f1) == strip(f2)
    d = [r for r in f1.directory_requests if r["state"]["current_directory"] == "D"][0]["state"]
    assert len(d["file_names"]) == 120 and len(d["child_directory_names"]) == 80    # configured caps


def test_decision_records_everything_needed_to_reproduce(bare_env):
    ctx, fake, _ = classify(bare_env, {"a.mkv": b"1"}, lambda s, q: ("MOVIES", 0.97))
    d = ctx.conn.execute("SELECT * FROM route_decision WHERE run_id=%s", (ctx.run_id,)).fetchone()
    from migrator.paths import canonical_json, sha256_hex
    assert d["state_json"] == {"file_name": "a.mkv", "ancestor_names": ["MEDIA"]}
    assert d["state_sha256"].strip() == sha256_hex(canonical_json(d["state_json"]))
    assert d["criteria_sha256"].strip() == sha256_hex(canonical_json(d["question_json"]))
    assert set(d["question_json"]["criteria"]) == {"MOVIES", "SERIES", "MUSIC", "BOOKS", "REVIEW"}
    assert (d["decision_source"], d["selected_choice"], d["confidence"]) == ("JEV", "MOVIES", 0.97)
    assert d["requested_model"] == "typesafe/jev-1.13" and d["returned_model"] == "typesafe/jev-1.13-2026-01-01"
    assert d["api_request_id"] == "req-1" and d["api_usage"] == {"total_tokens": 42}
    assert set(d["probabilities"]) == {"MOVIES", "SERIES", "MUSIC", "BOOKS", "REVIEW"}
    assert d["response_json"]["answers"]["route"]["choice"] == "MOVIES"
    assert (ctx.run_dir / "decisions" / "decisions.jsonl").read_text().count("\n") == 1


def test_decision_cache_hit_creates_record_referencing_source(bare_env):
    files = {"a.mkv": b"1"}
    ctx1, f1, _ = classify(bare_env, files, lambda s, q: ("MOVIES", 0.97))
    ctx2 = bare_env.new_run()
    inventory.run_inventory(ctx2)
    f2 = FakeJev(lambda s, q: ("MUSIC", 0.99))                # would differ if it were asked
    res = classifier.run_classification(ctx2, f2)
    assert f2.requests == [] and res["cache_hits"] == 1
    d2 = ctx2.conn.execute("SELECT * FROM route_decision WHERE run_id=%s", (ctx2.run_id,)).fetchone()
    d1 = ctx1.conn.execute("SELECT * FROM route_decision WHERE run_id=%s", (ctx1.run_id,)).fetchone()
    assert str(d2["cached_from_decision_id"]) == str(d1["decision_id"]) and d2["run_id"] != d1["run_id"]
    assert d2["selected_choice"] == "MOVIES" and d2["decision_id"] != d1["decision_id"]
    assert routes(ctx2)["a.mkv"]["target_id"] == "MOVIES"


def test_cache_is_invalidated_by_changed_criteria_or_model(bare_env):
    ctx1, _, _ = classify(bare_env, {"a.mkv": b"1"}, lambda s, q: ("MOVIES", 0.97))
    changed_desc = write_config(bare_env.tmp, name="crit.yaml", scope={"targets": [
        {"id": "MOVIES", "path": str(bare_env.lib / "MOVIES"), "description": "Different description now."},
        {"id": "SERIES", "path": str(bare_env.lib / "SERIES"), "description": "Series."},
        {"id": "MUSIC", "path": str(bare_env.lib / "MUSIC"), "description": "Music."},
        {"id": "BOOKS", "path": str(bare_env.lib / "BOOKS"), "description": "Books."}]})
    other_model = write_config(bare_env.tmp, name="model.yaml", openrouter={"model": "typesafe/jev-9.9"})
    for cfg in (changed_desc, other_model):
        ctx = bare_env.new_run(cfg)
        inventory.run_inventory(ctx)
        fake = FakeJev(lambda s, q: ("MOVIES", 0.97))
        res = classifier.run_classification(ctx, fake)
        assert res["cache_hits"] == 0 and len(fake.file_requests) == 1, cfg
    same = bare_env.new_run()
    inventory.run_inventory(same)
    fake = FakeJev(lambda s, q: ("MOVIES", 0.97))
    assert classifier.run_classification(same, fake)["cache_hits"] == 1


def test_cache_can_be_disabled(bare_env):
    classify(bare_env, {"a.mkv": b"1"}, lambda s, q: ("MOVIES", 0.97))
    cfg = write_config(bare_env.tmp, name="nocache.yaml", routing={"cache_decisions": False})
    ctx = bare_env.new_run(cfg)
    inventory.run_inventory(ctx)
    fake = FakeJev(lambda s, q: ("MOVIES", 0.97))
    assert classifier.run_classification(ctx, fake)["cache_hits"] == 0 and len(fake.requests) == 1


def test_identical_states_in_one_batch_share_one_api_call(bare_env):
    ctx, fake, res = classify(bare_env, {"x/a.mkv": b"1", "y/a.mkv": b"2"},
                              lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("MOVIES", 0.99))
    # states differ by ancestor name so both are asked; same-name siblings at the same depth would share
    assert len(fake.file_requests) == 2
    ctx2, fake2, res2 = classify(bare_env, {"p/dup.mkv": b"1", "q/dup.mkv": b"2"},
                                 lambda s, q: ("MOVIES", 0.99))
    assert len(fake2.requests) >= 1


# --- human review ----------------------------------------------------------------------------------

def test_human_file_decision_supersedes_without_modifying_jev(bare_env):
    ctx, _, _ = classify(bare_env, {"weird.bin": b"1"}, lambda s, q: ("REVIEW", 0.9))
    fid = str(ctx.conn.execute("SELECT file_id FROM file_inventory WHERE run_id=%s", (ctx.run_id,)).fetchone()["file_id"])
    jev = ctx.conn.execute("SELECT * FROM route_decision WHERE run_id=%s", (ctx.run_id,)).fetchone()
    did = classifier.set_file_target(ctx, fid, "BOOKS")
    rows = ctx.conn.execute("SELECT * FROM route_decision WHERE run_id=%s ORDER BY created_at", (ctx.run_id,)).fetchall()
    assert len(rows) == 2
    human = rows[1]
    assert str(human["decision_id"]) == did and human["decision_source"] == "HUMAN"
    assert str(human["supersedes_decision_id"]) == str(jev["decision_id"])
    assert rows[0]["selected_choice"] == "REVIEW" and rows[0]["decision_id"] == jev["decision_id"]
    r = routes(ctx)["weird.bin"]
    assert (r["target_id"], r["route_status"], r["route_origin_type"]) == ("BOOKS", "READY", "DIRECT")
    ev = [x["event_type"] for x in ctx.conn.execute(
        "SELECT event_type FROM audit_event WHERE trace_id=(SELECT trace_id FROM file_inventory WHERE file_id=%s) "
        "ORDER BY sequence_no", (fid,))]
    assert "HUMAN_DECISION_RECORDED" in ev and ev[-1] == "ROUTE_ASSIGNED"
    with pytest.raises(classifier.ClassifyError):
        classifier.set_file_target(ctx, fid, "NOPE")


def test_human_directory_subtree_decision(bare_env):
    ctx, fake, _ = classify(bare_env, {"D/a.bin": b"1", "D/s/b.bin": b"2", "E/c.bin": b"3"},
                            lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("REVIEW", 0.9))
    d = str(ctx.conn.execute("SELECT directory_id FROM directory_inventory WHERE run_id=%s AND basename='D'",
                             (ctx.run_id,)).fetchone()["directory_id"])
    classifier.set_directory_target(ctx, d, "MUSIC", subtree=True)
    r = routes(ctx)
    assert r["D/a.bin"]["target_id"] == r["D/s/b.bin"]["target_id"] == "MUSIC"
    assert r["E/c.bin"]["route_status"] == "REVIEW"
    # human decision on a directory beats the Jev decision below/above it and needs no new Jev call
    n = len(fake.requests)
    classifier.run_classification(ctx, fake)
    assert len(fake.requests) == n


def test_human_directory_direct_only_leaves_subdirectories_alone(bare_env):
    ctx, _, _ = classify(bare_env, {"D/a.bin": b"1", "D/s/b.bin": b"2"},
                         lambda s, q: ("DESCEND", 0.9) if "current_directory" in s else ("REVIEW", 0.9))
    d = str(ctx.conn.execute("SELECT directory_id FROM directory_inventory WHERE run_id=%s AND basename='D'",
                             (ctx.run_id,)).fetchone()["directory_id"])
    classifier.set_directory_target(ctx, d, "MUSIC", subtree=False)
    r = routes(ctx)
    assert r["D/a.bin"]["target_id"] == "MUSIC" and r["D/s/b.bin"]["route_status"] == "REVIEW"


def test_review_csv_export_and_import_round_trip(bare_env, tmp_path):
    ctx, _, _ = classify(bare_env, {"a.bin": b"1", "b.bin": b"2", "ok.mkv": b"3"},
                         lambda s, q: ("MOVIES", 0.99) if s["file_name"] == "ok.mkv" else ("REVIEW", 0.9))
    out = tmp_path / "out" / "review.csv"
    classifier.export_review_csv(ctx, out)
    import csv
    rows = list(csv.DictReader(out.open()))
    assert {r["absolute_path"].rsplit("/", 1)[1] for r in rows} == {"a.bin", "b.bin"}
    for r in rows:
        if r["absolute_path"].endswith("a.bin"):
            r["human_target"] = "BOOKS"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=classifier.REVIEW_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    res = classifier.import_review_csv(ctx, out)
    assert res["applied"] == 1 and res["review"] == 1
    assert routes(ctx)["a.bin"]["target_id"] == "BOOKS"
    for r in rows:
        r["human_target"] = "NOWHERE"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=classifier.REVIEW_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with pytest.raises(classifier.ClassifyError):
        classifier.import_review_csv(ctx, out)


def test_review_export_refuses_to_write_beneath_migration_roots(bare_env):
    ctx, _, _ = classify(bare_env, {"a.bin": b"1"}, lambda s, q: ("REVIEW", 0.9))
    with pytest.raises(classifier.ClassifyError):
        classifier.export_review_csv(ctx, bare_env.src / "review.csv")
    assert not (bare_env.src / "review.csv").exists()


def test_decision_rows_are_append_only(bare_env):
    ctx, _, _ = classify(bare_env, {"a.mkv": b"1"}, lambda s, q: ("MOVIES", 0.99))
    import psycopg
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("UPDATE route_decision SET selected_choice='X' WHERE run_id=%s", (ctx.run_id,))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        ctx.conn.execute("DELETE FROM route_decision WHERE run_id=%s", (ctx.run_id,))
