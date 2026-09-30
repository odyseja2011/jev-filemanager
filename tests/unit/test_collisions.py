from migrator import constants as C
from migrator.collisions import TargetIndex, detect_collisions
from migrator.models import PlanOp

POLICY = {"exact_path_collision": "review", "casefold_path_collision": "review",
          "existing_target_same_hash": "review", "existing_target_different_hash": "block"}
H1, H2 = "1" * 64, "2" * 64


def op(i, src, tgt, sha=H1, status=C.PLAN_READY_STATUS):
    return PlanOp(f"op{i}", f"f{i}", f"t{i}", None, src, tgt, sha, 1, "MOVIES", status)


def test_no_collision_stays_ready():
    ops = [op(1, "/s/a", "/t/a"), op(2, "/s/b", "/t/b")]
    assert detect_collisions(ops, TargetIndex(), POLICY) == {}
    assert {o.plan_status for o in ops} == {"READY"}


def test_exact_collision_between_sources():
    ops = [op(1, "/s/x/a.mkv", "/t/a.mkv"), op(2, "/s/y/a.mkv", "/t/a.mkv"), op(3, "/s/c", "/t/c")]
    detect_collisions(ops, TargetIndex(), POLICY)
    assert [(o.plan_status, o.blocker_code) for o in ops[:2]] == [("REVIEW", "TARGET_PATH_COLLISION")] * 2
    assert ops[2].plan_status == "READY"


def test_same_target_same_hash_is_review_never_automatic_delete():
    idx = TargetIndex()
    idx.add_file("/t/a.mkv", H1, C.HASH_HASHED)
    o = op(1, "/s/a.mkv", "/t/a.mkv", sha=H1)
    detect_collisions([o], idx, POLICY)
    assert (o.plan_status, o.blocker_code) == ("REVIEW", "TARGET_ALREADY_IDENTICAL")


def test_same_target_different_hash_is_blocked():
    idx = TargetIndex()
    idx.add_file("/t/a.mkv", H2, C.HASH_HASHED)
    o = op(1, "/s/a.mkv", "/t/a.mkv", sha=H1)
    detect_collisions([o], idx, POLICY)
    assert (o.plan_status, o.blocker_code) == ("BLOCKED", "TARGET_EXISTS_DIFFERENT_CONTENT")


def test_existing_target_without_hash_is_treated_as_different():
    idx = TargetIndex()
    idx.add_file("/t/a.mkv", None, C.HASH_FAILED)
    o = op(1, "/s/a.mkv", "/t/a.mkv")
    detect_collisions([o], idx, POLICY)
    assert o.blocker_code == "TARGET_EXISTS_DIFFERENT_CONTENT"


def test_policy_knob_can_turn_different_hash_into_review():
    idx = TargetIndex()
    idx.add_file("/t/a.mkv", H2, C.HASH_HASHED)
    o = op(1, "/s/a.mkv", "/t/a.mkv")
    detect_collisions([o], idx, {**POLICY, "existing_target_different_hash": "review"})
    assert (o.plan_status, o.blocker_code) == ("REVIEW", "TARGET_EXISTS_DIFFERENT_CONTENT")


def test_casefold_collision_between_planned_targets():
    ops = [op(1, "/s/1", "/t/Movie.mkv"), op(2, "/s/2", "/t/movie.mkv")]
    detect_collisions(ops, TargetIndex(), POLICY)
    assert [(o.plan_status, o.blocker_code) for o in ops] == [("REVIEW", "CASEFOLD_TARGET_COLLISION")] * 2


def test_casefold_collision_with_existing_target():
    idx = TargetIndex()
    idx.add_file("/t/MOVIE.mkv", H1, C.HASH_HASHED)
    o = op(1, "/s/1", "/t/movie.mkv")
    detect_collisions([o], idx, POLICY)
    assert o.blocker_code == "CASEFOLD_TARGET_COLLISION"


def test_target_path_is_existing_directory_or_parent_is_file():
    idx = TargetIndex()
    idx.add_dir("/t/Dune")
    idx.add_file("/t/File", H1, C.HASH_HASHED)
    a, b = op(1, "/s/1", "/t/Dune"), op(2, "/s/2", "/t/File/inner.mkv")
    detect_collisions([a, b], idx, POLICY)
    assert (a.plan_status, a.blocker_code) == ("BLOCKED", "TARGET_PATH_IS_DIRECTORY")
    assert (b.plan_status, b.blocker_code) == ("BLOCKED", "TARGET_PARENT_IS_FILE")


def test_file_target_that_is_also_a_planned_directory():
    ops = [op(1, "/s/1", "/t/Dune"), op(2, "/s/2", "/t/Dune/Dune.mkv")]
    detect_collisions(ops, TargetIndex(), POLICY)
    assert all(o.plan_status == "REVIEW" for o in ops)


def test_non_ready_operations_are_ignored():
    o1, o2 = op(1, "/s/1", "/t/a"), op(2, "/s/2", "/t/a", status=C.PLAN_REVIEW)
    detect_collisions([o1, o2], TargetIndex(), POLICY)
    assert o1.plan_status == "READY"
