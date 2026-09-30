import re
import subprocess

import pytest

from migrator.batches import BatchMeta, BatchOp, render_batch_script

META = BatchMeta("run-1", "plan-1", 1, "p" * 64, "batch-1", 1, "c" * 64, "typesafe/jev-1.13",
                 "/ws/runs/run-1", "2026-01-01T00:00:00.000000Z", "batch_000001.sh")
NASTY = ["it's \"quoted\".mkv", "$(touch /tmp/pwned).mkv", "`id`.mkv", "line\nbreak.mkv", "tab\there.mkv",
         "-rf.mkv", "Zażółć gęślą.mkv", "semi;colon && or || pipe|.mkv", "back\\slash.mkv", "glob*?[x].mkv"]


def ops(names=NASTY):
    return [BatchOp(f"op{i}", f"tr{i}", f"f{i}", 3, "a" * 64, 10, "b" * 64, f"/src/{n}", f"/dst/M/{n}",
                    f"/dst/M/.{n}.migrator-op{i}.partial") for i, n in enumerate(names)]


def render(names=NASTY):
    return render_batch_script(META, ops(names))


def test_header_metadata():
    text = render()
    head = text.split("set -uo pipefail")[0]
    for needle in ("GENERATED FILE - DO NOT EDIT", "run-1", "plan-1", "p" * 64, "batch-1", "Batch number:        1",
                   "Operations:          10", "2026-01-01T00:00:00.000000Z", "c" * 64, "typesafe/jev-1.13"):
        assert needle in head, needle
    assert text.startswith("#!/usr/bin/env bash")


def test_no_global_set_e_and_stop_on_error_variable():
    text = render()
    assert "set -uo pipefail" in text
    assert not re.search(r"^set -[a-z]*e", text, re.M)
    assert 'STOP_ON_ERROR="${STOP_ON_ERROR:-0}"' in text


def test_syntax_is_valid_bash_even_with_hostile_names(tmp_path):
    p = tmp_path / "b.sh"
    p.write_text(render())
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_all_dynamic_values_round_trip_through_shell_parsing():
    """Parse the generated calls exactly like bash would (POSIX word splitting): every hostile
    name must come back byte-identical, proving nothing is expanded or split."""
    import shlex
    text = render()
    tail = text.split('preflight || { log "batch preflight failed; nothing was changed"; exit 2; }\n')[1]
    tokens = shlex.split(tail)
    assert tokens[-1] == "finish"
    calls, cur = [], []
    for t in tokens[:-1]:
        if t == "run_operation" and cur:
            calls.append(cur)
            cur = []
        cur.append(t)
    calls.append(cur)
    assert len(calls) == len(NASTY)
    for i, (call, name) in enumerate(zip(calls, NASTY), start=1):
        assert call[0] == "run_operation" and len(call) == 12
        assert call[1] == str(i)
        assert call[9] == f"/src/{name}" and call[10] == f"/dst/M/{name}"
        assert call[11] == f"/dst/M/.{name}.migrator-op{i - 1}.partial"


def test_absolute_paths_only():
    for o in ops():
        assert o.source.startswith("/") and o.target.startswith("/") and o.temp.startswith("/")


@pytest.mark.parametrize("forbidden", [r"\bcp\b[^\n]*\s-[a-zA-Z]*[fpa]\b", r"\bmv\b", r"\brsync\b", r"\bchown\b",
                                       r"\bchmod\b", r"\bsetfacl\b", r"--preserve", r"--inplace", r"\brm\b[^\n]*\s-[a-zA-Z]*[rf]",
                                       r"\bcp -a\b", r"--reference"])
def test_no_forbidden_primitives(forbidden):
    code = "\n".join(l for l in render().splitlines() if not l.lstrip().startswith("#") and not l.startswith("run_operation "))
    assert not re.search(forbidden, code), forbidden


def test_copy_primitive_and_promotion_never_overwrite():
    text = render()
    assert "cp --reflink=auto --no-preserve=all -- " in text
    assert "ln -T -- " in text                      # link without -f: fails if the target exists
    code = "\n".join(l for l in text.split("copy_stage()")[1].split("run_operation()")[0].splitlines()
                     if not l.lstrip().startswith("#"))
    assert not re.search(r"\s-f\b", code)


def test_temp_file_is_created_beside_final_target_and_cleaned_only_by_name():
    for o in ops(["a.mkv"]):
        assert o.temp.rsplit("/", 1)[0] == o.target.rsplit("/", 1)[0]
        assert ".migrator-op0.partial" in o.temp


def test_sha_precondition_and_postconditions_present_in_order():
    text = render()
    move = text.split("move_one() {")[1].split("run_operation() {")[0]
    copy = text.split("copy_stage() {")[1].split("delete_stage() {")[0]
    assert move.index('cur_sha="$(sha_of "$SRC")"') < move.index("SOURCE_PRECHECK_OK") < move.index("copy_stage")
    assert copy.index("TEMP_TARGET_HASH_VERIFIED") < copy.index("TARGET_COMMIT_STARTED") < copy.index('ln -T')
    assert copy.index("TARGET_COMMITTED") < copy.index("FINAL_TARGET_HASH_VERIFIED")
    delete = text.split("delete_stage() {")[1].split("# returns:")[0]
    assert delete.index("SOURCE_DELETE_STARTED") < delete.index('rm -- "$SRC"') < delete.index("SOURCE_DELETED")


def test_source_is_deleted_only_in_delete_stage_after_final_verification():
    text = render()
    assert text.count('rm -- "$SRC"') == 1
    move = text.split("move_one() {")[1].split("run_operation() {")[0]
    # delete_stage is only reachable after copy_stage returned 0 or the target was verified identical
    assert "copy_stage; rc=$?" in move and "(( rc == 0 )) || return $rc" in move
    assert move.rstrip().endswith("delete_stage\n}")


def test_summary_and_exit_codes():
    text = render()
    for needle in ("Batch complete", "Success:", "Already complete:", "Failed:", "Blocked:", "exit 2", "exit 1", "exit 0"):
        assert needle in text


def test_pre_events_gate_state_changing_steps():
    text = render()
    copy = text.split("copy_stage() {")[1].split("delete_stage() {")[0]
    assert copy.index("audit_pre COPY_STARTED") < copy.index("mkdir -p") < copy.index("cp --reflink=auto")
    assert copy.index("audit_pre TARGET_COMMIT_STARTED") < copy.index("ln -T")


def test_no_secrets_in_script(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-very-secret")
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", "postgresql://u:pw@h/db")
    text = render()
    assert "sk-very-secret" not in text and "pw@h" not in text
