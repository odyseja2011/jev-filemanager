import json
import random

from migrator.classifier import (build_directory_state, build_file_state, decision_cache_key, sample_names)
from migrator.config import normalize_and_validate
from migrator.planner import build_target_path, temp_name
from tests.helpers import base_config

SAMPLES = {"max_child_directory_names": 3, "max_file_names": 4, "max_ancestor_names": 2,
           "max_state_characters": 24000}


def test_sampling_is_independent_of_enumeration_order():
    names = [f"file-{i}.mkv" for i in range(50)]
    a = sample_names(names, 5)
    shuffled = names[:]
    random.Random(1).shuffle(shuffled)
    assert sample_names(shuffled, 5) == a
    assert len(a) == 5 and a == sorted(a)


def test_sampling_is_not_first_n():
    names = [f"{i:03}" for i in range(100)]
    assert sample_names(names, 5) != sorted(names)[:5]


def test_sampling_dedups_and_handles_small_sets():
    assert sample_names(["a", "a", "b"], 10) == ["a", "b"]
    assert sample_names([], 3) == []
    assert sample_names(["a"], 0) == []


def test_directory_state_shape_and_limits():
    st = build_directory_state("FILMY", ["MEDIA", "MULTIMEDIA", "X"], [f"d{i}" for i in range(10)],
                               [f"f{i}.mkv" for i in range(10)], SAMPLES)
    assert set(st) == {"current_directory", "ancestor_names", "child_directory_names", "file_names"}
    assert st["ancestor_names"] == ["MULTIMEDIA", "X"]          # nearest ancestors
    assert len(st["child_directory_names"]) == 3 and len(st["file_names"]) == 4


def test_state_shrinks_to_character_budget():
    big = build_directory_state("D", [], [f"dir-{i:04}" * 5 for i in range(200)],
                                [f"file-{i:04}" * 5 for i in range(200)],
                                {**SAMPLES, "max_child_directory_names": 200, "max_file_names": 200,
                                 "max_state_characters": 600})
    assert len(json.dumps(big, sort_keys=True, separators=(",", ":"))) <= 600


def test_file_state_has_only_names():
    st = build_file_state("Blade Runner 2049 (2017).mkv", ["MEDIA", "Old Downloads", "Unsored"], 8)
    assert st == {"file_name": "Blade Runner 2049 (2017).mkv",
                  "ancestor_names": ["MEDIA", "Old Downloads", "Unsored"]}


def test_cache_key_depends_on_all_four_components():
    base = decision_cache_key("m", "s", "c", "1")
    assert base == decision_cache_key("m", "s", "c", "1")
    assert len({base, decision_cache_key("m2", "s", "c", "1"), decision_cache_key("m", "s2", "c", "1"),
                decision_cache_key("m", "s", "c2", "1"), decision_cache_key("m", "s", "c", "2")}) == 5


def cfg(tmp_path, include_dir=False):
    raw = base_config(tmp_path, routing={"directory_mapping": {"include_classified_directory_name": include_dir}})
    return normalize_and_validate(raw)


def test_directory_relative_mapping(tmp_path):
    c = cfg(tmp_path)
    t = build_target_path(c, "MOVIES", origin="INHERITED_DIRECTORY",
                          source_path="/mnt/MEDIA/MULTIMEDIA/FILMY/Dune/Dune.mkv",
                          source_basename="Dune.mkv", route_dir_path="/mnt/MEDIA/MULTIMEDIA/FILMY",
                          route_dir_basename="FILMY")
    assert t == f"{tmp_path}/LIBRARY/MOVIES/Dune/Dune.mkv"          # NOT .../MOVIES/FILMY/Dune/Dune.mkv


def test_directory_mapping_can_include_classified_directory_name(tmp_path):
    t = build_target_path(cfg(tmp_path, True), "MOVIES", origin="INHERITED_DIRECTORY",
                          source_path="/m/FILMY/Dune/Dune.mkv", source_basename="Dune.mkv",
                          route_dir_path="/m/FILMY", route_dir_basename="FILMY")
    assert t == f"{tmp_path}/LIBRARY/MOVIES/FILMY/Dune/Dune.mkv"


def test_direct_file_mapping_uses_basename_only(tmp_path):
    t = build_target_path(cfg(tmp_path), "MOVIES", origin="DIRECT", source_path="/mnt/MEDIA/random/Alien.mkv",
                          source_basename="Alien.mkv", route_dir_path=None, route_dir_basename=None)
    assert t == f"{tmp_path}/LIBRARY/MOVIES/Alien.mkv"


def test_names_are_never_normalized(tmp_path):
    weird = "  Żółć—gęślą  (2020) [x].MKV "
    t = build_target_path(cfg(tmp_path), "MOVIES", origin="DIRECT", source_path=f"/s/{weird}",
                          source_basename=weird, route_dir_path=None, route_dir_basename=None)
    assert t.endswith("/" + weird)


def test_temp_name_is_a_sibling_with_operation_uuid():
    t = temp_name("/lib/MOVIES/Dune/Dune.mkv", "0123")
    assert t == "/lib/MOVIES/Dune/.Dune.mkv.migrator-0123.partial"


def test_temp_name_falls_back_for_long_names():
    long = "x" * 250 + ".mkv"
    t = temp_name(f"/lib/{long}", "0123")
    assert t == "/lib/.migrator-0123.partial"
