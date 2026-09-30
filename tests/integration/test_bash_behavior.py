"""Executes the generated Bash for real and checks every safety property of the move."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from migrator import audit as A, batches, classifier, inventory, planner
from tests.fake_jev import FakeJev
from tests.helpers import write_files
from tests.integration.conftest import all_movies, ready_run

pytestmark = pytest.mark.postgres

REAL_CP = shutil.which("cp")


@pytest.fixture()
def env(bare_env):
    return bare_env


def setup_ops(env, files, gen=True):
    ctx, _ = ready_run(env, files, rules=all_movies)
    g = batches.generate_batches(ctx) if gen else None
    return ctx, (Path(g["batches"][0]["script"]) if g else None)


def types(ctx, name):
    A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    return [e["event_type"] for e in ctx.conn.execute(
        """SELECT e.event_type FROM audit_event e JOIN file_inventory f USING (trace_id)
           WHERE f.run_id=%s AND f.basename=%s AND e.source='BASH' ORDER BY e.sequence_no""", (ctx.run_id, name))]


def dst(env, name="a.mkv"):
    return env.lib / "MOVIES" / name


def shim(tmp, body):
    d = tmp / "shim"
    d.mkdir(exist_ok=True)
    cp = d / "cp"
    cp.write_text(f"#!/bin/bash\n{body}\n")
    cp.chmod(0o755)
    return {"PATH": f"{d}:{os.environ['PATH']}"}


def test_state1_normal_move(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    r = env.run_batch(script)
    assert r.returncode == 0 and "Success: 1" in r.stdout
    assert dst(env).read_bytes() == b"payload" and not (env.src / "a.mkv").exists()
    assert not list(env.lib.rglob("*.partial"))


def test_state2_rerun_after_completion_is_already_complete(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    env.run_batch(script)
    r = env.run_batch(script)
    assert r.returncode == 0 and "Already complete: 1" in r.stdout
    assert types(ctx, "a.mkv")[-2:] == ["BATCH_OPERATION_STARTED", "OPERATION_ALREADY_COMPLETE"]
    assert dst(env).read_bytes() == b"payload"


def test_state3_resume_after_target_commit_deletes_source(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    dst(env).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(env.src / "a.mkv", dst(env))                 # interrupted run: committed, not yet deleted
    r = env.run_batch(script)
    assert r.returncode == 0 and "Success: 1" in r.stdout
    assert not (env.src / "a.mkv").exists() and dst(env).read_bytes() == b"payload"
    t = types(ctx, "a.mkv")
    assert "OPERATION_RESUMED_AFTER_TARGET_COMMIT" in t and "COPY_STARTED" not in t
    assert t.index("OPERATION_RESUMED_AFTER_TARGET_COMMIT") < t.index("SOURCE_DELETE_STARTED") < t.index("SOURCE_DELETED")


def test_state4_target_with_different_content_blocks_and_keeps_everything(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    dst(env).parent.mkdir(parents=True, exist_ok=True)
    dst(env).write_bytes(b"someone else's data")
    r = env.run_batch(script)
    assert r.returncode == 1 and "Blocked: 1" in r.stdout
    assert (env.src / "a.mkv").read_bytes() == b"payload"
    assert dst(env).read_bytes() == b"someone else's data"          # NO OVERWRITE, EVER
    assert not list(env.lib.rglob("*.partial"))
    assert "TARGET_COLLISION" in types(ctx, "a.mkv")


def test_state5_both_missing_is_reported_as_data_missing(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    (env.src / "a.mkv").unlink()
    r = env.run_batch(script)
    assert r.returncode == 1 and "Blocked: 1" in r.stdout
    assert types(ctx, "a.mkv")[-1] == "DATA_MISSING"


def test_source_changed_after_inventory_is_never_migrated(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    (env.src / "a.mkv").write_bytes(b"PAYLOAD")                     # same size, different content
    r = env.run_batch(script)
    assert r.returncode == 1
    assert (env.src / "a.mkv").read_bytes() == b"PAYLOAD" and not dst(env).exists()
    assert not (env.lib / "MOVIES").exists() or not any((env.lib / "MOVIES").iterdir())
    assert types(ctx, "a.mkv")[-1] == "SOURCE_CHANGED_AFTER_INVENTORY"


def test_symlink_replacing_the_source_is_refused(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload", "other": b"o"})
    (env.src / "a.mkv").unlink()
    (env.src / "a.mkv").symlink_to(env.src / "other")
    r = env.run_batch(script)
    assert (env.src / "a.mkv").is_symlink() and not dst(env).exists()
    assert "SOURCE_PRECHECK_FAILED" in types(ctx, "a.mkv")


def test_temp_hash_mismatch_keeps_source_and_removes_only_the_temp(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    extra = shim(env.tmp, f'{REAL_CP} "$@" || exit $?\nprintf X >> "${{@: -1}}"')
    r = env.run_batch(script, **extra)
    assert r.returncode == 1 and "Failed: 1" in r.stdout
    assert (env.src / "a.mkv").read_bytes() == b"payload" and not dst(env).exists()
    assert not list(env.lib.rglob("*.partial"))
    t = types(ctx, "a.mkv")
    assert "TARGET_HASH_MISMATCH" in t and "SOURCE_DELETE_STARTED" not in t


def test_cp_failure_keeps_source(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    r = env.run_batch(script, **shim(env.tmp, "exit 1"))
    assert r.returncode == 1 and (env.src / "a.mkv").exists() and not dst(env).exists()
    assert "COPY_FAILED" in types(ctx, "a.mkv")


def test_target_appearing_after_plan_is_not_overwritten(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    final = str(dst(env))
    extra = shim(env.tmp, f'{REAL_CP} "$@" || exit $?\nprintf squatter > {final!r}')
    r = env.run_batch(script, **extra)
    assert r.returncode == 1 and "Blocked: 1" in r.stdout
    assert dst(env).read_bytes() == b"squatter" and (env.src / "a.mkv").read_bytes() == b"payload"
    assert not list(env.lib.rglob("*.partial"))
    assert "TARGET_APPEARED_AFTER_PLAN" in types(ctx, "a.mkv")


def test_source_modified_during_copy_is_not_deleted(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    src = str(env.src / "a.mkv")
    extra = shim(env.tmp, f'{REAL_CP} "$@" || exit $?\nsleep 0.05; printf more >> {src!r}')
    r = env.run_batch(script, **extra)
    assert (env.src / "a.mkv").exists()                              # kept
    assert "SOURCE_DELETE_STARTED" not in types(ctx, "a.mkv")
    assert "SOURCE_CHANGED_DURING_COPY" in types(ctx, "a.mkv") and r.returncode == 1


def test_audit_failure_before_mutation_changes_nothing(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    broken = env.tmp / "brokenbin"
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(0o755)
    r = env.run_batch(script, MIGRATOR_BIN=str(broken))
    assert r.returncode == 2 and "nothing further will be changed" in r.stderr
    assert (env.src / "a.mkv").read_bytes() == b"payload"
    assert not (env.lib / "MOVIES").exists() or not list((env.lib / "MOVIES").rglob("*"))


def test_preflight_failures_exit_2_without_changes(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    r = env.run_batch(script, MIGRATOR_BIN="definitely-not-installed")
    assert r.returncode == 2 and (env.src / "a.mkv").exists()
    script.chmod(0o755)
    script.write_text(script.read_text() + "\n# edited\n")
    r = env.run_batch(script)
    assert r.returncode == 2 and "does not match its recorded SHA-256" in r.stderr
    assert (env.src / "a.mkv").exists() and not dst(env).exists()
    assert env.run_batch(script, VERIFY_SELF="0").returncode == 0       # explicit opt-out only


def test_stop_on_error_variable(env):
    ctx, script = setup_ops(env, {"a.mkv": b"1", "b.mkv": b"2"})
    (env.src / "a.mkv").write_bytes(b"X")                        # first op will be blocked
    r = env.run_batch(script, STOP_ON_ERROR="1")
    assert r.returncode == 1 and "Not run" in r.stdout
    assert (env.src / "b.mkv").exists() and not dst(env, "b.mkv").exists()
    r = env.run_batch(script)                                     # default: continue with the next operation
    assert dst(env, "b.mkv").exists() and "Blocked: 1" in r.stdout and "Success: 1" in r.stdout


def test_failure_of_one_operation_does_not_erase_others(env):
    files = {f"f{i}.mkv": str(i).encode() for i in range(5)}
    ctx, script = setup_ops(env, files)
    (env.src / "f2.mkv").write_bytes(b"changed")
    r = env.run_batch(script)
    assert r.returncode == 1 and "Success: 4" in r.stdout and "Blocked: 1" in r.stdout
    assert {p.name for p in (env.lib / "MOVIES").iterdir()} == {"f0.mkv", "f1.mkv", "f3.mkv", "f4.mkv"}


HOSTILE = ["it's \"quoted\".mkv", "$(touch PWNED1).mkv", "`touch PWNED2`.mkv", "line\nbreak.mkv", "tab\there.mkv",
           "-rf.mkv", "Zażółć gęślą jaźń.mkv", "semi;colon && touch PWNED3 || x | y.mkv", "back\\slash.mkv",
           "glob*?[x].mkv", "  spaces  .mkv", "--help.mkv"]


def test_hostile_filenames_are_moved_verbatim_and_nothing_is_executed(env):
    files = {f"Dir with 'quotes' & $pecial/{n}": n.encode() for n in HOSTILE}
    ctx, _ = ready_run(env, files, rules=lambda s, q: ("MOVIES", 0.99))
    g = batches.generate_batches(ctx)
    assert batches.verify_batches(ctx) == []
    cwd = env.tmp / "cwd"
    cwd.mkdir()
    r = subprocess.run(["bash", g["batches"][0]["script"]], capture_output=True, text=True, cwd=cwd,
                       env={**os.environ, "MIGRATOR_DATABASE_URL": env.dsn, "MIGRATOR_BIN": str(env.wrapper)})
    assert r.returncode == 0, r.stderr
    assert f"Success: {len(HOSTILE)}" in r.stdout
    for n in HOSTILE:
        p = env.lib / "MOVIES" / n          # the classified directory's own name is not part of the target
        assert p.read_bytes() == n.encode(), n
    assert not list(cwd.iterdir()) and not list(env.tmp.rglob("PWNED*"))


def test_source_directories_are_never_removed(env):
    ctx, script = setup_ops(env, {"Deep/er/a.mkv": b"1"})
    env.run_batch(script)
    assert (env.src / "Deep" / "er").is_dir() and not any((env.src / "Deep" / "er").iterdir())


def test_destination_directories_are_created_only_where_needed(env):
    ctx, script = setup_ops(env, {"a.mkv": b"1"})
    shutil.rmtree(env.lib / "MOVIES")
    r = env.run_batch(script)
    assert r.returncode == 0 and dst(env).exists()


def test_permissions_are_not_preserved_from_source(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    src = env.src / "a.mkv"
    os.chmod(src, 0o600)
    os.utime(src, (1_000_000_000, 1_000_000_000))
    try:
        os.chown(src, 4242, 4243)
        chowned = True
    except PermissionError:
        chowned = False
    # the mode/ownership change must not have invalidated the plan (ctime is not compared)
    r = env.run_batch(script, umask=0o027)
    assert r.returncode == 0, r.stderr
    st = dst(env).stat()
    assert stat.S_IMODE(st.st_mode) == 0o640              # 0666 & ~umask: destination policy, not the source's 0600
    assert st.st_mtime != 1_000_000_000                    # timestamps are not preserved either
    if chowned:
        assert (st.st_uid, st.st_gid) == (os.geteuid(), os.getegid())


@pytest.mark.skipif(not shutil.which("setfacl") or not shutil.which("getfacl"), reason="needs POSIX ACL tools")
def test_destination_default_acl_is_inherited_and_source_acl_is_not_preserved(env, tmp_path):
    """Portable POSIX-ACL check.  The production requirement (TrueNAS/ZFS NFSv4 ACLs) must be verified on
    the real target dataset — see README 'Verifying ACL inheritance in production'."""
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    lib_movies = env.lib / "MOVIES"
    subprocess.run(["setfacl", "-d", "-m", "u:65534:rw-", str(lib_movies)], check=True)
    subprocess.run(["setfacl", "-m", "u:65533:rwx", str(env.src / "a.mkv")], check=True)
    r = env.run_batch(script)
    assert r.returncode == 0, r.stderr
    acl = subprocess.run(["getfacl", "-p", str(dst(env))], capture_output=True, text=True, check=True).stdout
    assert "user:65534:rw-" in acl                      # inherited from the destination directory
    assert "65533" not in acl                           # the source ACL was not carried over


ACL_DIR = os.environ.get("MIGRATOR_ACL_TEST_DIR")


@pytest.mark.skipif(not ACL_DIR, reason="set MIGRATOR_ACL_TEST_DIR to a directory on the production dataset")
def test_acl_inheritance_on_the_production_filesystem(tmp_path):
    pytest.skip("run scripts/verify_acl_inheritance.sh on the real target host (see README)")


def test_process_mode_fallback_produces_the_same_events(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    r = env.run_batch(script, AUDIT_MODE="process")
    assert r.returncode == 0 and dst(env).read_bytes() == b"payload"
    t = types(ctx, "a.mkv")
    assert t[0] == "BATCH_OPERATION_STARTED" and t[-1] == "OPERATION_COMPLETED" and len(t) == 11
    assert A.verify_run_chain(ctx.conn, ctx.run_id).ok


def test_audit_helper_dying_mid_batch_stops_before_the_next_state_change(env):
    ctx, script = setup_ops(env, {"a.mkv": b"1", "b.mkv": b"2"})
    dying = env.tmp / "dying-migrator"
    dying.write_text(f"""#!{__import__('sys').executable}
import os, sys
if sys.argv[1:3] == ["audit", "serve"]:
    os.read(0, 100)              # answer the PING, then die
    os.write(1, b"OK\\n")
    sys.exit(0)
os.execv(sys.executable, [sys.executable, "-m", "migrator", *sys.argv[1:]])
""")
    dying.chmod(0o755)
    r = env.run_batch(script, MIGRATOR_BIN=str(dying))
    assert r.returncode == 2 and "cannot durably record" in r.stderr
    assert (env.src / "a.mkv").exists() and (env.src / "b.mkv").exists()
    assert not (env.lib / "MOVIES").exists() or not list((env.lib / "MOVIES").rglob("*"))


def test_helper_that_cannot_start_falls_back_to_per_event_emit(env):
    ctx, script = setup_ops(env, {"a.mkv": b"payload"})
    nohelper = env.tmp / "nohelper"
    nohelper.write_text(f"""#!{__import__('sys').executable}
import os, sys
if sys.argv[1:3] == ["audit", "serve"]:
    sys.exit(1)
os.execv(sys.executable, [sys.executable, "-m", "migrator", *sys.argv[1:]])
""")
    nohelper.chmod(0o755)
    r = env.run_batch(script, MIGRATOR_BIN=str(nohelper))
    assert r.returncode == 0 and "falling back" in r.stderr and dst(env).exists()
