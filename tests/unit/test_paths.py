import pytest

from migrator.paths import (GlobSet, PathSafetyError, WorkspaceGuard, canonical_json, glob_to_regex,
                            is_within, relative_to, safe_join, write_new_file)


def test_safe_join_keeps_names_exactly():
    assert safe_join("/lib/MOVIES", "Dune", "Dune (2021) [1080p].mkv") == "/lib/MOVIES/Dune/Dune (2021) [1080p].mkv"
    assert safe_join("/lib/MOVIES", "Zażółć  gęślą.mkv") == "/lib/MOVIES/Zażółć  gęślą.mkv"


@pytest.mark.parametrize("bad", ["../x", "a/../../x", "..", "a/../..", "/../etc"])
def test_safe_join_rejects_escapes(bad):
    with pytest.raises(PathSafetyError):
        safe_join("/lib/MOVIES", bad)


def test_safe_join_rejects_root_itself_nul_and_relative_root():
    with pytest.raises(PathSafetyError):
        safe_join("/lib/MOVIES", ".")
    with pytest.raises(PathSafetyError):
        safe_join("/lib/MOVIES", "a\x00b")
    with pytest.raises(PathSafetyError):
        safe_join("relative", "x")


def test_is_within_is_not_fooled_by_prefixes():
    assert is_within("/a/b/c", "/a/b")
    assert is_within("/a/b", "/a/b")
    assert not is_within("/a/bc", "/a/b")
    assert not is_within("/a/b/../c", "/a/b")


def test_relative_to():
    assert relative_to("/m/FILMY/Dune/Dune.mkv", "/m/FILMY") == "Dune/Dune.mkv"
    assert relative_to("/m/FILMY", "/m/FILMY") == ""
    with pytest.raises(PathSafetyError):
        relative_to("/m/OTHER/x", "/m/FILMY")


@pytest.mark.parametrize("pattern,path,expected", [
    ("**/*", "a.mkv", True), ("**/*", "a/b/c.mkv", True), ("*.mkv", "a.mkv", True),
    ("*.mkv", "a/b.mkv", False), ("**/*.tmp", "x/y/z.tmp", True), ("**/*.tmp", "z.tmp", True),
    ("cache/**", "cache/a/b", True), ("cache/**", "other/a", False), ("a?c", "abc", True),
    ("[ab]x", "bx", True), ("[!ab]x", "bx", False), ("a.b", "aXb", False),
])
def test_glob(pattern, path, expected):
    assert bool(glob_to_regex(pattern).match(path)) is expected


def test_globset_empty_is_falsy():
    assert not GlobSet([])
    assert GlobSet(["*"]).matches("x")


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 1, "a": [2, {"d": 1, "c": 2}]}) == '{"a":[2,{"c":2,"d":1}],"b":1}'
    assert canonical_json({"k": "ż"}) == '{"k":"\\u017c"}'


def test_workspace_guard_blocks_migration_roots_and_outside(tmp_path):
    g = WorkspaceGuard(str(tmp_path / "ws"), [str(tmp_path / "src")])
    g.check(tmp_path / "ws" / "runs" / "x")
    with pytest.raises(PathSafetyError):
        g.check(tmp_path / "src" / "file")
    with pytest.raises(PathSafetyError):
        g.check(tmp_path / "elsewhere")
    with pytest.raises(PathSafetyError):
        write_new_file(tmp_path / "src" / "f", b"x", guard=g)


def test_write_new_file_never_overwrites(tmp_path):
    p = tmp_path / "a" / "f"
    write_new_file(p, b"one")
    with pytest.raises(FileExistsError):
        write_new_file(p, b"two")
    assert p.read_bytes() == b"one"
    assert not [x for x in p.parent.iterdir() if x.name.endswith(".tmp")]
