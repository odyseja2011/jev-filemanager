import os
from pathlib import Path

import pytest

from migrator import constants as C
from migrator import inventory
from migrator.hashing import HashResult, hash_file
from migrator.runs import RunError, open_run
from tests.helpers import write_config, write_files

pytestmark = pytest.mark.postgres


def rows(ctx, root_type="SOURCE"):
    return {r["relative_path"]: r for r in ctx.conn.execute(
        "SELECT * FROM file_inventory WHERE run_id = %s AND root_type = %s", (ctx.run_id, root_type))}


def test_awkward_filenames_and_special_files(bare_env):
    env = bare_env
    names = {
        "a file with spaces.mkv": b"1", "quo'te \"dq\".mkv": b"2", "Zażółć gęślą jaźń.mkv": b"3",
        "tab\tname.mkv": b"4", "new\nline.mkv": b"5", "empty.bin": b"", "-leading-dash.mkv": b"6",
        "deep/er/est/file.txt": b"7", "back\\slash.mkv": b"8", "$(dollar).mkv": b"9",
    }
    write_files(env.src, names)
    with open(env.src / "sparse.bin", "wb") as f:
        f.truncate(32 * 1024 * 1024)
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    got = rows(ctx)
    assert set(got) == set(names) | {"sparse.bin"}
    import hashlib
    for rel, data in names.items():
        assert got[rel]["sha256"].strip() == hashlib.sha256(data).hexdigest(), rel
        assert got[rel]["absolute_path"] == str(env.src / rel)         # absolute, exact
        assert got[rel]["hash_status"] == "HASHED"
    assert got["sparse.bin"]["sha256"].strip() == hashlib.sha256(bytes(32 * 1024 * 1024)).hexdigest()
    assert got["empty.bin"]["size_bytes"] == 0
    # directories are inventoried for classification only, root has depth 0
    d = {r["relative_path"]: r for r in ctx.conn.execute(
        "SELECT * FROM directory_inventory WHERE run_id = %s", (ctx.run_id,))}
    assert {"", "deep", "deep/er", "deep/er/est"} <= set(d)
    assert d["deep/er/est"]["depth"] == 3


def test_every_file_gets_a_permanent_trace_id_and_first_event(bare_env):
    write_files(bare_env.src, {"a": b"1", "b/c": b"2"})
    ctx = bare_env.new_run()
    inventory.run_inventory(ctx)
    traces = [r["trace_id"] for r in ctx.conn.execute("SELECT trace_id FROM file_inventory WHERE run_id=%s", (ctx.run_id,))]
    assert len(traces) == 2 == len(set(traces))
    for t in traces:
        evs = [r["event_type"] for r in ctx.conn.execute(
            "SELECT event_type FROM audit_event WHERE trace_id=%s ORDER BY sequence_no", (t,))]
        assert evs == ["FILE_DISCOVERED", "FILE_HASH_STARTED", "FILE_HASHED"]


def test_symlinks_are_ignored_and_counted(bare_env):
    env = bare_env
    write_files(env.src, {"real.txt": b"x", "dir/inner.txt": b"y"})
    (env.src / "link-file").symlink_to(env.src / "real.txt")
    (env.src / "link-dir").symlink_to(env.src / "dir")
    (env.src / "dangling").symlink_to("/nonexistent")
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    assert set(rows(ctx)) == {"real.txt", "dir/inner.txt"}
    sr = ctx.conn.execute("SELECT * FROM scan_root WHERE run_id=%s AND root_type='SOURCE'", (ctx.run_id,)).fetchone()
    assert sr["symlink_skipped_count"] == 3 and sr["regular_file_count"] == 2
    assert not ctx.conn.execute("SELECT 1 FROM directory_inventory WHERE run_id=%s AND relative_path='link-dir'",
                                (ctx.run_id,)).fetchone()


def test_hardlinked_source_files_are_blocked_not_hashed(bare_env):
    env = bare_env
    write_files(env.src, {"a": b"same", "solo": b"solo"})
    os.link(env.src / "a", env.src / "b")
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    r = rows(ctx)
    assert r["a"]["hash_status"] == r["b"]["hash_status"] == C.HASH_BLOCKED_HARDLINK
    assert r["a"]["st_nlink"] == 2 and r["a"]["sha256"] is None
    assert r["solo"]["hash_status"] == "HASHED" and r["solo"]["st_nlink"] == 1


def test_nested_structures_and_exclude_globs(bare_env):
    env = bare_env
    write_files(env.src, {"keep/a.mkv": b"1", "cache/tmp/x.mkv": b"2", "keep/skip.tmp": b"3", "top.mkv": b"4"})
    cfg = write_config(env.tmp, name="c2.yaml", scope={"sources": [
        {"id": "media", "path": str(env.src), "include": ["**/*"], "exclude": ["cache/**", "**/*.tmp"]}]})
    ctx = env.new_run(cfg)
    inventory.run_inventory(ctx)
    assert set(rows(ctx)) == {"keep/a.mkv", "top.mkv"}


def test_target_inventory_is_scanned_and_hashed_too(bare_env):
    env = bare_env
    write_files(env.src, {"a": b"1"})
    write_files(env.lib / "MOVIES", {"Existing/e.mkv": b"existing"})
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    t = rows(ctx, "TARGET")
    assert set(t) == {"Existing/e.mkv"} and t["Existing/e.mkv"]["hash_status"] == "HASHED"
    assert {p.name for p in ctx.run_dir.iterdir()} >= {"source-manifest.tsv0.gz", "target-manifest.tsv0.gz",
                                                       "source-manifest.sha256", "target-manifest.sha256"}


def test_missing_target_root_is_treated_as_empty_but_missing_source_fails(bare_env):
    env = bare_env
    write_files(env.src, {"a": b"1"})
    import shutil
    shutil.rmtree(env.lib / "BOOKS")
    ctx = env.new_run()
    inventory.run_inventory(ctx)                       # BOOKS target absent: fine
    cfg = write_config(env.tmp, name="c3.yaml", scope={"sources": [{"id": "media", "path": str(env.tmp / "nope")}]})
    ctx2 = env.new_run(cfg)
    with pytest.raises(inventory.InventoryError):
        inventory.run_inventory(ctx2)
    assert ctx2.refresh()["state"] == C.CREATED         # nothing half-started


def test_manifest_is_nul_terminated_deterministic_and_immutable(bare_env):
    env = bare_env
    write_files(env.src, {"a b\tc\nd.mkv": b"1", "z": b"2"})
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    gz = ctx.run_dir / "source-manifest.tsv0.gz"
    import gzip, hashlib
    raw = gzip.open(gz).read()
    assert raw.endswith(b"\0") and raw.count(b"\0") == 3        # header + 2 records
    recs = list(inventory.read_manifest(gz))
    assert {r["relative_path"] for r in recs} == {"a b\tc\nd.mkv", "z"}
    side = (ctx.run_dir / "source-manifest.sha256").read_text().split()[0]
    assert side == hashlib.sha256(gz.read_bytes()).hexdigest()
    assert not os.access(gz, os.W_OK) or os.geteuid() == 0
    inventory.run_inventory(ctx)                                # re-run is a no-op, manifest unchanged
    assert hashlib.sha256(gz.read_bytes()).hexdigest() == side


def test_unreadable_and_unstable_files_reach_terminal_states(bare_env):
    env = bare_env
    write_files(env.src, {"ok": b"1", "denied": b"2", "flapping": b"3"})

    def hasher(path, **kw):
        if path.endswith("denied"):
            return HashResult(C.HASH_FAILED, None, "PermissionError: denied", 1, None)
        if path.endswith("flapping"):
            return HashResult(C.HASH_UNSTABLE, None, "file kept changing while being hashed", 3, None)
        return hash_file(path, **kw)

    ctx = env.new_run()
    inventory.run_inventory(ctx, hasher=hasher)
    r = rows(ctx)
    assert (r["ok"]["hash_status"], r["denied"]["hash_status"], r["flapping"]["hash_status"]) == \
        ("HASHED", "FAILED", "UNSTABLE")
    assert r["denied"]["hash_error"] and r["denied"]["sha256"] is None
    assert ctx.refresh()["state"] == C.INVENTORY_COMPLETE      # all terminal
    ev = {x["event_type"] for x in ctx.conn.execute(
        "SELECT event_type FROM audit_event WHERE run_id=%s", (ctx.run_id,))}
    assert {"HASH_FAILED", "HASH_UNSTABLE", "FILE_HASHED", "DISCOVERY_COMPLETE", "INVENTORY_COMPLETE"} <= ev


def test_file_changed_between_discovery_and_hash_records_hashed_state(bare_env):
    env = bare_env
    write_files(env.src, {"grows": b"1"})
    ctx = env.new_run()
    inventory.discover(ctx)
    (env.src / "grows").write_bytes(b"123456")            # changes after discovery
    inventory.hash_inventory(ctx)
    r = rows(ctx)["grows"]
    assert r["size_bytes"] == 6 and r["hash_status"] == "HASHED"   # the hash matches the recorded stat
    e = ctx.conn.execute("SELECT payload FROM audit_event WHERE trace_id=%s AND event_type='FILE_HASHED'",
                         (r["trace_id"],)).fetchone()
    assert e["payload"]["stat_changed_since_discovery"] is True


class _FakeStat:
    def __init__(self, st, dev):
        self._st = st
        self.st_dev = dev if dev is not None else st.st_dev

    def __getattr__(self, k):
        return getattr(self._st, k)


class _Ent:
    def __init__(self, e, dev):
        self._e, self._dev = e, dev
        self.name = e.name

    def is_symlink(self):
        return self._e.is_symlink()

    def is_dir(self, **kw):
        return self._e.is_dir(**kw)

    def is_file(self, **kw):
        return self._e.is_file(**kw)

    def stat(self, **kw):
        return _FakeStat(self._e.stat(**kw), self._dev)


class _Scan:
    def __init__(self, real, path, mount_name):
        self._it = real(path)
        self._m = mount_name

    def __enter__(self):
        self._entries = list(self._it.__enter__())
        return self

    def __exit__(self, *a):
        return self._it.__exit__(*a)

    def __iter__(self):
        return iter(_Ent(e, 999_999 if e.name == self._m else None) for e in self._entries)


@pytest.mark.parametrize("cross,expected", [(True, {"top.mkv", "mnt/inside.mkv"}), (False, {"top.mkv"})])
def test_cross_mounts_flag(bare_env, monkeypatch, cross, expected):
    """A nested dataset looks like a directory whose st_dev differs from its parent."""
    env = bare_env
    write_files(env.src, {"top.mkv": b"1", "mnt/inside.mkv": b"2"})
    cfg = write_config(env.tmp, name="cm.yaml", scope={"sources": [
        {"id": "media", "path": str(env.src), "cross_mounts": cross}]})
    real = os.scandir
    monkeypatch.setattr(inventory.os, "scandir", lambda p: _Scan(real, p, "mnt") if str(p) == str(env.src) else real(p))
    ctx = env.new_run(cfg)
    inventory.run_inventory(ctx)
    assert set(rows(ctx)) == expected


def test_non_utf8_names_are_skipped_and_counted(bare_env):
    env = bare_env
    write_files(env.src, {"good.mkv": b"1"})
    bad = os.fsencode(str(env.src)) + b"/bad-\xff\xfe.mkv"
    with open(bad, "wb") as f:
        f.write(b"x")
    ctx = env.new_run()
    inventory.run_inventory(ctx)
    assert set(rows(ctx)) == {"good.mkv"}
    sr = ctx.conn.execute("SELECT undecodable_skipped_count FROM scan_root WHERE run_id=%s AND root_type='SOURCE'",
                          (ctx.run_id,)).fetchone()
    assert sr["undecodable_skipped_count"] == 1


def test_scope_is_configuration_driven_not_hardcoded(bare_env, tmp_path):
    other = tmp_path / "SOMEWHERE" / "ELSE"
    write_files(other, {"x.bin": b"1"})
    cfg = write_config(bare_env.tmp, name="c4.yaml", scope={"sources": [{"id": "else", "path": str(other)}]})
    ctx = bare_env.new_run(cfg)
    inventory.run_inventory(ctx)
    assert set(rows(ctx)) == {"x.bin"}


def test_inventory_only_from_created_and_hashing_is_resumable(bare_env):
    write_files(bare_env.src, {"a": b"1", "b": b"2"})
    ctx = bare_env.new_run()
    inventory.discover(ctx)
    assert ctx.refresh()["state"] == C.DISCOVERY_COMPLETE
    calls = []

    def dying(path, **kw):
        calls.append(path)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        inventory.hash_inventory(ctx, hasher=dying)
    assert ctx.refresh()["state"] == C.HASHING
    inventory.run_inventory(ctx)                       # resumes
    assert ctx.refresh()["state"] == C.INVENTORY_COMPLETE
    assert all(r["hash_status"] == "HASHED" for r in rows(ctx).values())
    from migrator.db import InvalidTransition
    with pytest.raises(InvalidTransition):
        inventory.discover(ctx)


def test_config_snapshot_is_saved_and_changes_require_a_new_run(bare_env):
    env = bare_env
    ctx = env.new_run()
    snap = ctx.run_dir / "config.snapshot.yaml"
    assert snap.read_bytes() == env.config.read_bytes()          # exact YAML
    assert (ctx.run_dir / "config.sha256").read_text().strip() == ctx.run["config_sha256"].strip()
    assert ctx.run["config_json"]["migration"]["name"] == "test-migration"
    assert ctx.run["requested_jev_model"] == "typesafe/jev-1.13"
    changed = write_config(env.tmp, name="changed.yaml", routing={"confidence_threshold": 0.5})
    with pytest.raises(RunError):
        open_run(env.conn, ctx.run_id, changed)
    open_run(env.conn, ctx.run_id, env.config)                   # same config: fine
    # DB-level immutability of the snapshot
    import psycopg
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        env.conn.execute("UPDATE migration_run SET config_sha256 = %s WHERE run_id = %s", ("f" * 64, ctx.run_id))
    (ctx.run_dir / "config.sha256").chmod(0o644)
    (ctx.run_dir / "config.sha256").write_text("0" * 64 + "\n")
    with pytest.raises(RunError):
        open_run(env.conn, ctx.run_id)
