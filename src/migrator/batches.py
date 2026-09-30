"""Generation and verification of the reviewed Bash batch scripts.

The Python application only *writes script files inside the workspace*.  It never
runs them: a human executes them explicitly.
"""

from __future__ import annotations

import os
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from migrator import audit as A
from migrator import constants as C
from migrator import db
from migrator.logs import get_logger
from migrator.paths import sha256_hex, utc_now, write_new_file, format_time
from migrator.planner import latest_plan, temp_name
from migrator.runs import RunContext

log = get_logger("batches")


class BatchError(RuntimeError):
    pass


@dataclass
class BatchOp:
    operation_id: str
    trace_id: str
    file_id: str
    head_sequence: int
    head_hash: str
    expected_size: int
    expected_sha256: str
    source: str
    target: str
    temp: str


@dataclass
class BatchMeta:
    run_id: str
    plan_id: str
    plan_revision: int
    plan_sha256: str
    batch_id: str
    batch_number: int
    config_sha256: str
    model: str
    run_dir: str
    generated_at: str
    script_name: str


def _q(v: object) -> str:
    return shlex.quote(str(v))


def _header_safe(s: str) -> str:
    return "".join(c if c.isprintable() and c not in "\r\n" else "?" for c in s)


# --------------------------------------------------------------------------------------
# The generated script.  Every dynamic value is inserted through shlex.quote.
# --------------------------------------------------------------------------------------
_SCRIPT_BODY = r'''
log() { printf '%s\n' "$*" >&2; }

SUCCESS=0
ALREADY_COMPLETE=0
FAILED=0
BLOCKED=0
NOT_RUN=0
ABORT=0
AUDIT_BROKEN=0

AUDIT_SERVER_UP=0

audit_start() {
    # One persistent helper per batch (imports psycopg once, keeps one connection). Falls back to
    # one `audit emit` process per event, which is slower but equally safe.
    [[ "$AUDIT_MODE" == serve ]] || return 0
    coproc AUDITOR { "$MIGRATOR_BIN" audit serve --run "$RUN_ID" --run-dir "$RUN_DIR"; }
    local reply=""
    if printf '%s\0' PING "" >&"${AUDITOR[1]}" 2>/dev/null \
            && read -r -t 30 -u "${AUDITOR[0]}" reply 2>/dev/null && [[ "$reply" == OK ]]; then
        AUDIT_SERVER_UP=1
    else
        log "warning: audit helper did not start; falling back to one process per audit event"
    fi
}

audit_stop() {
    if (( AUDIT_SERVER_UP )); then
        AUDIT_SERVER_UP=0
        if [[ -n ${AUDITOR[1]:-} ]]; then
            eval "exec ${AUDITOR[1]}>&-"          # EOF on the helper's stdin ends it
            wait "${AUDITOR_PID:-}" 2>/dev/null
        fi
    fi
}

audit_emit() {
    # audit_emit EVENT [key=value ...]  -> records audit information only
    local event="$1"; shift
    if (( AUDIT_SERVER_UP )); then
        local reply=""
        # if the helper died, bash unsets the coproc variables
        [[ -n ${AUDITOR[1]:-} && -n ${AUDITOR[0]:-} ]] || { log "audit: helper is gone"; return 1; }
        printf '%s\0' "$RUN_ID" "$TRACE_ID" "$FILE_ID" "$OP_ID" "$BATCH_ID" "$PREV_SEQ" "$PREV_HASH" \
            "$ACTOR" "$event" "$@" "" >&"${AUDITOR[1]}" 2>/dev/null || { log "audit: helper is gone"; return 1; }
        read -r -t 300 -u "${AUDITOR[0]}" reply || { log "audit: no reply from helper"; return 1; }
        [[ "$reply" == OK ]] || { log "audit: $reply"; return 1; }
        return 0
    fi
    local kv=() a
    for a in "$@"; do kv+=(--kv "$a"); done
    "$MIGRATOR_BIN" audit emit --run "$RUN_ID" --run-dir "$RUN_DIR" --trace "$TRACE_ID" \
        --file "$FILE_ID" --operation "$OP_ID" --batch "$BATCH_ID" --event "$event" \
        --actor "$ACTOR" --expect-sequence "$PREV_SEQ" --expect-hash "$PREV_HASH" \
        ${kv[@]+"${kv[@]}"}
}

# A pre-event MUST be durable before the state-changing step it announces.
audit_pre() {
    if ! audit_emit "$@"; then
        log "FATAL: cannot durably record $1 for operation $OP_ID; nothing further will be changed"
        return 1
    fi
}

# A post-event records something that already happened; failing to record it stops the batch.
audit_post() {
    if ! audit_emit "$@"; then
        log "CRITICAL: $1 happened for operation $OP_ID but could not be recorded"
        AUDIT_BROKEN=1
        return 1
    fi
}

sha_of()   { local out; out="$(sha256sum < "$1")" || return 1; printf '%s' "${out%% *}"; }
size_of()  { stat -c %s -- "$1"; }
sig_of()   { stat -c '%d:%i:%s:%.9Y' -- "$1"; }
is_regular() { [[ -f $1 && ! -L $1 ]]; }
present()  { [[ -e $1 || -L $1 ]]; }

preflight() {
    local tool
    for tool in cp ln rm mkdir stat sha256sum "$MIGRATOR_BIN"; do
        command -v "$tool" >/dev/null 2>&1 || { log "preflight: required tool not found: $tool"; return 1; }
    done
    mkdir -p -- "$SPOOL_DIR" && [[ -w $SPOOL_DIR ]] || { log "preflight: audit spool is not writable: $SPOOL_DIR"; return 1; }
    if [[ "$VERIFY_SELF" == 1 ]]; then
        local self="${BASH_SOURCE[0]}" sidecar plan_sidecar expected actual
        sidecar="${self%.sh}.sha256"
        plan_sidecar="$RUN_DIR/plan/plan-$(printf '%04d' "$PLAN_REVISION").sha256"
        [[ -r $sidecar ]] || { log "preflight: missing $sidecar"; return 1; }
        expected="$(cut -d' ' -f1 < "$sidecar")"
        actual="$(sha_of "$self")" || return 1
        [[ "$expected" == "$actual" ]] || { log "preflight: this script does not match its recorded SHA-256"; return 1; }
        [[ -r $plan_sidecar ]] || { log "preflight: missing $plan_sidecar"; return 1; }
        expected="$(cut -d' ' -f1 < "$plan_sidecar")"
        [[ "$expected" == "$PLAN_SHA256" ]] || { log "preflight: plan SHA-256 differs from the one this batch was generated for"; return 1; }
        if [[ -e "$RUN_DIR/plan/plan-$(printf '%04d' $((PLAN_REVISION + 1))).sha256" ]]; then
            log "preflight: plan revision $PLAN_REVISION has been superseded; this batch must not run"; return 1
        fi
    fi
}

# --- stage 2: copy to a temporary file in the destination directory, verify, commit -------
copy_stage() {
    local tmp_sha final_sha ddir="${DST%/*}"
    audit_pre COPY_STARTED "temp=$TMP" || return 4
    if ! mkdir -p -- "$ddir"; then
        audit_post COPY_FAILED "reason=mkdir failed" "directory=$ddir" || return 4
        return 2
    fi
    if present "$TMP"; then                       # only this operation's own leftover
        rm -- "$TMP" 2>/dev/null
        if present "$TMP"; then
            audit_post COPY_FAILED "reason=cannot remove leftover temp file" || return 4
            return 2
        fi
    fi
    if ! cp --reflink=auto --no-preserve=all -- "$SRC" "$TMP"; then
        present "$TMP" && rm -- "$TMP" 2>/dev/null
        audit_post COPY_FAILED "reason=cp failed" || return 4
        return 2
    fi
    audit_post COPY_FINISHED "temp=$TMP" || return 4

    if ! tmp_sha="$(sha_of "$TMP")" || [[ "$tmp_sha" != "$EXPECTED_SHA" ]]; then
        present "$TMP" && rm -- "$TMP" 2>/dev/null
        audit_post TARGET_HASH_MISMATCH "stage=temp" "actual_sha256=${tmp_sha:-}" || return 4
        return 2                                   # source is KEPT
    fi
    audit_pre TEMP_TARGET_HASH_VERIFIED "sha256=$tmp_sha" || return 4

    # runtime race protection: the planner saw the target free, but is it still?
    if present "$DST"; then
        rm -- "$TMP" 2>/dev/null
        audit_post TARGET_APPEARED_AFTER_PLAN "target=$DST" || return 4
        return 3
    fi
    audit_pre TARGET_COMMIT_STARTED "target=$DST" || return 4
    # `ln` without -f fails if DST exists (atomic, never overwrites); -T: DST is never treated as a directory
    if ! ln -T -- "$TMP" "$DST" 2>/dev/null; then
        rm -- "$TMP" 2>/dev/null
        if present "$DST"; then
            audit_post TARGET_APPEARED_AFTER_PLAN "target=$DST" || return 4
            return 3
        fi
        audit_post TARGET_COMMIT_FAILED "reason=ln failed" || return 4
        return 2
    fi
    rm -- "$TMP" 2>/dev/null || log "warning: could not remove temp file $TMP"
    audit_post TARGET_COMMITTED "target=$DST" || return 4

    final_sha="$(sha_of "$DST")" || final_sha=""
    if [[ "$final_sha" != "$EXPECTED_SHA" ]]; then
        audit_post FINAL_TARGET_HASH_MISMATCH "actual_sha256=$final_sha" || return 4
        return 2                                   # DO NOT DELETE SOURCE
    fi
    audit_pre FINAL_TARGET_HASH_VERIFIED "sha256=$final_sha" || return 4
    return 0
}

# --- stage 3: delete exactly this regular source file, only after the target is verified ------
delete_stage() {
    local now_sig
    now_sig="$(sig_of "$SRC")" || now_sig=""
    if [[ "$now_sig" != "$S_SIG" ]]; then
        audit_pre SOURCE_CHANGED_DURING_COPY "before=$S_SIG" "after=$now_sig" || return 4
        return 3
    fi
    audit_pre SOURCE_DELETE_STARTED "source=$SRC" || return 4
    if ! rm -- "$SRC"; then
        audit_post SOURCE_DELETE_FAILED "source=$SRC" || return 4
        return 2
    fi
    audit_post SOURCE_DELETED "source=$SRC" || return 4
    audit_post OPERATION_COMPLETED || return 4
    return 0
}

# returns: 0 SUCCESS, 1 ALREADY_COMPLETE, 2 FAILED, 3 BLOCKED, 4 AUDIT FAILURE (abort batch)
move_one() {
    local cur_size cur_sha dst_sha rc
    audit_pre BATCH_OPERATION_STARTED "source=$SRC" "target=$DST" "expected_sha256=$EXPECTED_SHA" \
        "expected_size=$EXPECTED_SIZE" || return 4

    if ! present "$SRC"; then
        if present "$DST"; then
            if is_regular "$DST" && [[ "$(size_of "$DST")" == "$EXPECTED_SIZE" ]] \
                    && dst_sha="$(sha_of "$DST")" && [[ "$dst_sha" == "$EXPECTED_SHA" ]]; then
                audit_post OPERATION_ALREADY_COMPLETE "target=$DST" || return 4
                return 1
            fi
            audit_pre TARGET_HASH_MISMATCH "stage=rerun" "target=$DST" "detail=source missing; target differs" || return 4
            return 3
        fi
        audit_pre DATA_MISSING "source=$SRC" "target=$DST" || return 4
        return 3
    fi

    if ! is_regular "$SRC"; then
        audit_pre SOURCE_PRECHECK_FAILED "reason=not a regular file or is a symlink" || return 4
        return 3
    fi
    cur_size="$(size_of "$SRC")" || cur_size=""
    if ! cur_sha="$(sha_of "$SRC")"; then
        audit_pre SOURCE_PRECHECK_FAILED "reason=source unreadable" || return 4
        return 3
    fi
    if [[ "$cur_size" != "$EXPECTED_SIZE" || "$cur_sha" != "$EXPECTED_SHA" ]]; then
        audit_pre SOURCE_CHANGED_AFTER_INVENTORY "current_size=$cur_size" "current_sha256=$cur_sha" || return 4
        return 3
    fi
    S_SIG="$(sig_of "$SRC")" || S_SIG=""
    audit_pre SOURCE_PRECHECK_OK "sha256=$cur_sha" || return 4

    if present "$DST"; then
        if is_regular "$DST" && [[ "$(size_of "$DST")" == "$EXPECTED_SIZE" ]] \
                && dst_sha="$(sha_of "$DST")" && [[ "$dst_sha" == "$EXPECTED_SHA" ]]; then
            # execution stopped after the target commit but before the source delete
            audit_pre OPERATION_RESUMED_AFTER_TARGET_COMMIT "target=$DST" || return 4
            audit_pre FINAL_TARGET_HASH_VERIFIED "sha256=$dst_sha" || return 4
        else
            audit_pre TARGET_COLLISION "code=TARGET_EXISTS_DIFFERENT_CONTENT" "target=$DST" || return 4
            return 3
        fi
    else
        copy_stage; rc=$?
        (( rc == 0 )) || return $rc
    fi
    delete_stage
}

run_operation() {
    IDX="$1"; OP_ID="$2"; TRACE_ID="$3"; FILE_ID="$4"; PREV_SEQ="$5"; PREV_HASH="$6"
    EXPECTED_SIZE="$7"; EXPECTED_SHA="$8"; SRC="$9"; DST="${10}"; TMP="${11}"
    if (( ABORT )); then NOT_RUN=$((NOT_RUN + 1)); return 0; fi
    local rc
    move_one; rc=$?
    case $rc in
        0) SUCCESS=$((SUCCESS + 1));                   log "[$IDX/$OPERATION_COUNT] moved: $SRC" ;;
        1) ALREADY_COMPLETE=$((ALREADY_COMPLETE + 1)); log "[$IDX/$OPERATION_COUNT] already complete: $SRC" ;;
        2) FAILED=$((FAILED + 1));                     log "[$IDX/$OPERATION_COUNT] FAILED (source kept): $SRC" ;;
        3) BLOCKED=$((BLOCKED + 1));                   log "[$IDX/$OPERATION_COUNT] BLOCKED (nothing changed): $SRC" ;;
        *) AUDIT_BROKEN=1; ABORT=1 ;;
    esac
    if (( AUDIT_BROKEN )); then ABORT=1; fi
    if (( rc >= 2 && rc <= 3 )) && [[ "$STOP_ON_ERROR" == 1 ]]; then ABORT=1; fi
}

finish() {
    audit_stop
    printf 'Batch complete\nSuccess: %s\nAlready complete: %s\nFailed: %s\nBlocked: %s\n' \
        "$SUCCESS" "$ALREADY_COMPLETE" "$FAILED" "$BLOCKED"
    (( NOT_RUN )) && printf 'Not run (batch stopped): %s\n' "$NOT_RUN"
    if (( AUDIT_BROKEN )); then log "Batch aborted: audit events could not be recorded"; exit 2; fi
    if (( FAILED + BLOCKED + NOT_RUN > 0 )); then exit 1; fi
    exit 0
}

preflight || { log "batch preflight failed; nothing was changed"; exit 2; }
audit_start
'''


def render_batch_script(meta: BatchMeta, ops: list[BatchOp]) -> str:
    header = "\n".join([
        "#!/usr/bin/env bash", "",
        "# GENERATED FILE - DO NOT EDIT",
        f"# Migration run:       {meta.run_id}",
        f"# Plan:                {meta.plan_id} (revision {meta.plan_revision})",
        f"# Plan SHA256:         {meta.plan_sha256}",
        f"# Batch:               {meta.batch_id}",
        f"# Batch number:        {meta.batch_number}",
        f"# Operations:          {len(ops)}",
        f"# Generated at:        {meta.generated_at}",
        f"# Config SHA256:       {meta.config_sha256}",
        f"# Requested Jev model: {_header_safe(meta.model)}",
        "#",
        "# Every operation: COPY -> VERIFY -> COMMIT TARGET -> VERIFY -> DELETE SOURCE.",
        "# NO OVERWRITE, EVER: an existing target is never replaced.",
        "# The source is deleted only after the final target has the SHA-256 recorded at inventory.",
        "",
        "set -uo pipefail",
        "",
        f"RUN_ID={_q(meta.run_id)}",
        f"PLAN_ID={_q(meta.plan_id)}",
        f"PLAN_REVISION={_q(meta.plan_revision)}",
        f"PLAN_SHA256={_q(meta.plan_sha256)}",
        f"BATCH_ID={_q(meta.batch_id)}",
        f"BATCH_NUMBER={_q(meta.batch_number)}",
        f"OPERATION_COUNT={_q(len(ops))}",
        f"CONFIG_SHA256={_q(meta.config_sha256)}",
        f"RUN_DIR={_q(meta.run_dir)}",
        'SPOOL_DIR="$RUN_DIR/audit-spool"',
        'STOP_ON_ERROR="${STOP_ON_ERROR:-0}"      # 1 = stop the batch at the first failed/blocked operation',
        'MIGRATOR_BIN="${MIGRATOR_BIN:-migrator}"  # only used for `audit emit`; never touches migration files',
        'VERIFY_SELF="${VERIFY_SELF:-1}"',
        'AUDIT_MODE="${AUDIT_MODE:-serve}"          # serve = one helper process; process = one `audit emit` per event',
        "trap '' PIPE                               # a dead audit helper must fail the audit, not kill the shell",
        f'ACTOR={_q(meta.script_name)}":${{USER:-unknown}}@$(hostname 2>/dev/null || echo unknown)"',
    ])
    calls = []
    for i, o in enumerate(ops, start=1):
        calls.append("run_operation " + " ".join(_q(x) for x in (
            i, o.operation_id, o.trace_id, o.file_id, o.head_sequence, o.head_hash,
            o.expected_size, o.expected_sha256, o.source, o.target, o.temp)))
    return header + "\n" + _SCRIPT_BODY + "\n" + "\n".join(calls) + "\n\nfinish\n"


def _cleanup(paths: list[Path]) -> None:
    for p in paths:
        try:
            p.unlink()
        except OSError:
            pass


def generate_batches(ctx: RunContext) -> dict[str, Any]:
    conn, cfg = ctx.conn, ctx.cfg
    db.require_state(ctx.refresh(), C.PLAN_READY, C.BATCHES_GENERATED)
    A.require_spool_synced(conn, ctx.run_id, ctx.spool)
    plan = latest_plan(conn, ctx.run_id)
    if plan is None:
        raise BatchError("no plan exists; run `plan create` first")
    plan_id = str(plan["plan_id"])
    if conn.execute("SELECT 1 FROM batch WHERE plan_id = %s LIMIT 1", (plan_id,)).fetchone():
        raise BatchError("batches already exist for this plan; create a new plan revision to regenerate")
    name = f"plan-{plan['revision']:04d}"
    plan_file = ctx.path("plan", f"{name}.jsonl")
    if sha256_hex(plan_file.read_bytes()) != plan["plan_sha256"].strip():
        raise BatchError(f"{plan_file} does not match the plan SHA-256 recorded in PostgreSQL")

    rows = conn.execute(
        """SELECT operation_id, trace_id, file_id, expected_size_bytes, expected_sha256,
                  source_absolute_path, target_absolute_path, target_id
           FROM plan_operation WHERE plan_id = %s AND plan_status = 'READY'
           ORDER BY target_id COLLATE "C", target_absolute_path COLLATE "C",
                    source_absolute_path COLLATE "C", operation_id""", (plan_id,)).fetchall()
    size = cfg["batches"]["max_operations"]
    excluded = {r["plan_status"]: r["n"] for r in conn.execute(
        "SELECT plan_status, count(*) AS n FROM plan_operation WHERE plan_id = %s AND plan_status <> 'READY' "
        "GROUP BY 1", (plan_id,))}
    written: list[Path] = []
    batches_info: list[dict[str, Any]] = []
    now = format_time(utc_now())
    try:
        with conn.transaction():
            for bn, start in enumerate(range(0, len(rows), size), start=1):
                chunk = rows[start:start + size]
                batch_id = str(uuid.uuid4())
                A.append_events(conn, ctx.run_id, [A.EventSpec(
                    r["trace_id"], "BATCH_ASSIGNED", "migrator", C.SRC_PYTHON,
                    {"batch_id": batch_id, "batch_number": bn, "position": i, "plan_id": plan_id},
                    file_id=r["file_id"], operation_id=r["operation_id"], batch_id=uuid.UUID(batch_id))
                    for i, r in enumerate(chunk, start=1)])
                heads = A.get_heads(conn, [str(r["trace_id"]) for r in chunk])
                ops = []
                for r in chunk:
                    seq, h = heads[str(r["trace_id"])]
                    oid = str(r["operation_id"])
                    ops.append(BatchOp(oid, str(r["trace_id"]), str(r["file_id"]), seq, h,
                                       r["expected_size_bytes"], r["expected_sha256"].strip(),
                                       r["source_absolute_path"], r["target_absolute_path"],
                                       temp_name(r["target_absolute_path"], oid)))
                script_name = f"batch_{bn:06d}.sh"
                meta = BatchMeta(ctx.run_id, plan_id, plan["revision"], plan["plan_sha256"].strip(),
                                 batch_id, bn, ctx.run["config_sha256"].strip(), cfg.model,
                                 str(ctx.run_dir), now, script_name)
                text = render_batch_script(meta, ops).encode("utf-8")
                digest = sha256_hex(text)
                # revision 1 keeps the documented layout; later revisions get their own directory so
                # older (superseded) batches stay intact as historical evidence
                sub = [] if plan["revision"] == 1 else [f"plan-{plan['revision']:04d}"]
                script_path = ctx.path("batches", *sub, script_name)
                sha_path = ctx.path("batches", *sub, f"batch_{bn:06d}.sha256")
                write_new_file(script_path, text, mode=0o555, guard=ctx.guard)
                written.append(script_path)
                write_new_file(sha_path, f"{digest}  {script_name}\n".encode(), guard=ctx.guard)
                written.append(sha_path)
                conn.execute(
                    """INSERT INTO batch (batch_id, plan_id, run_id, batch_number, operation_count,
                           script_path, script_sha256) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (batch_id, plan_id, ctx.run_id, bn, len(ops), str(script_path), digest))
                with conn.cursor() as cur:
                    cur.executemany(
                        """INSERT INTO batch_operation (batch_id, operation_id, position, trace_head_sequence,
                               trace_head_hash, temp_absolute_path) VALUES (%s,%s,%s,%s,%s,%s)""",
                        [(batch_id, o.operation_id, i, o.head_sequence, o.head_hash, o.temp)
                         for i, o in enumerate(ops, start=1)])
                batches_info.append({"batch_id": batch_id, "batch_number": bn, "operations": len(ops),
                                     "script": str(script_path), "sha256": digest})
            A.append_event(conn, ctx.run_id, A.EventSpec(
                uuid.UUID(str(ctx.run["run_trace_id"])), "BATCHES_GENERATED", "migrator", C.SRC_PYTHON,
                {"plan_id": plan_id, "batches": len(batches_info), "operations": len(rows),
                 "excluded": excluded}))
            if batches_info:
                db.transition(conn, ctx.run_id, C.BATCHES_GENERATED)
    except Exception:
        _cleanup(written)
        raise
    return {"plan_id": plan_id, "batches": batches_info, "ready_operations": len(rows),
            "excluded_operations": excluded,
            "batch_dir": str(ctx.run_dir / "batches" / ("" if plan["revision"] == 1 else f"plan-{plan['revision']:04d}"))
            .rstrip("/")}


def list_batches(ctx: RunContext) -> list[dict[str, Any]]:
    return ctx.conn.execute(
        """SELECT b.batch_number, b.batch_id, b.operation_count, b.script_path, b.script_sha256, p.revision
           FROM batch b JOIN plan_revision p USING (plan_id) WHERE b.run_id = %s
           ORDER BY p.revision, b.batch_number""", (ctx.run_id,)).fetchall()


def verify_batches(ctx: RunContext) -> list[str]:
    """Recompute artifact hashes and cross-check them against PostgreSQL."""
    conn = ctx.conn
    problems: list[str] = []
    run = ctx.refresh()
    cfg_hash = run["config_sha256"].strip()
    if ctx.cfg.sha256() != cfg_hash:
        problems.append("configuration hash does not match the run")
    plan = latest_plan(conn, ctx.run_id)
    if plan is None:
        return ["no plan exists"]
    plan_hash = plan["plan_sha256"].strip()
    name = f"plan-{plan['revision']:04d}"
    pf = ctx.run_dir / "plan" / f"{name}.jsonl"
    if not pf.exists():
        problems.append(f"plan file missing: {pf}")
    elif sha256_hex(pf.read_bytes()) != plan_hash:
        problems.append(f"plan file {pf} does not match plan_sha256 in PostgreSQL")
    psf = ctx.run_dir / "plan" / f"{name}.sha256"
    if not psf.exists() or psf.read_text().split()[0] != plan_hash:
        problems.append(f"plan sidecar {psf} missing or different")
    rows = conn.execute("SELECT * FROM batch WHERE run_id = %s ORDER BY batch_number", (ctx.run_id,)).fetchall()
    current = [b for b in rows if str(b["plan_id"]) == str(plan["plan_id"])]
    if len(current) != len(rows):
        problems.append(f"{len(rows) - len(current)} batch(es) belong to superseded plan revisions "
                        "and must not be executed")
    if not current:
        problems.append("no batches were generated for the current plan")
    seen_ops: set[str] = set()
    for b in current:
        path = Path(b["script_path"])
        tag = f"batch {b['batch_number']}"
        if not path.exists():
            problems.append(f"{tag}: script missing: {path}")
            continue
        data = path.read_bytes()
        if sha256_hex(data) != b["script_sha256"].strip():
            problems.append(f"{tag}: script SHA-256 differs from PostgreSQL")
        side = path.with_suffix(".sha256")
        if not side.exists() or side.read_text().split()[0] != b["script_sha256"].strip():
            problems.append(f"{tag}: sidecar hash missing or different")
        text = data.decode("utf-8", "replace")
        for needle, what in ((f"# Plan SHA256:         {plan_hash}", "plan SHA-256"),
                             (f"# Config SHA256:       {cfg_hash}", "config SHA-256"),
                             (f"# Batch:               {b['batch_id']}", "batch id")):
            if needle not in text:
                problems.append(f"{tag}: header does not carry the expected {what}")
        ops = conn.execute("""SELECT bo.operation_id, po.plan_status, po.plan_id FROM batch_operation bo
                              JOIN plan_operation po USING (operation_id) WHERE bo.batch_id = %s""",
                           (str(b["batch_id"]),)).fetchall()
        if len(ops) != b["operation_count"]:
            problems.append(f"{tag}: operation count mismatch")
        for o in ops:
            if o["plan_status"] != "READY":
                problems.append(f"{tag}: contains non-READY operation {o['operation_id']}")
            if str(o["plan_id"]) != str(plan["plan_id"]):
                problems.append(f"{tag}: operation {o['operation_id']} belongs to another plan")
            if str(o["operation_id"]) in seen_ops:
                problems.append(f"operation {o['operation_id']} occurs in two batches")
            seen_ops.add(str(o["operation_id"]))
    ready = {str(r["operation_id"]) for r in conn.execute(
        "SELECT operation_id FROM plan_operation WHERE plan_id = %s AND plan_status = 'READY'",
        (str(plan["plan_id"]),))}
    if current and ready - seen_ops:
        problems.append(f"{len(ready - seen_ops)} READY operations are in no batch")
    return problems
