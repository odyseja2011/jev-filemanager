#!/usr/bin/env bash
# Edge-case trial on throw-away dummy data.
#
# Runs the real tool (your PostgreSQL, your Jev key) end to end in isolated sandboxes under
# $BASE (default ~/migtest-edge) and checks every outcome.  Nothing outside $BASE is touched.
#
#   . ~/.migrator.env            # MIGRATOR_DATABASE_URL, OPENROUTER_API_KEY
#   . .venv/bin/activate
#   scripts/edge_case_trial.sh            # all scenarios
#   scripts/edge_case_trial.sh s03 s07    # selected scenarios
#
# Routing is forced with a human `review set-directory --subtree` on the source root, so the
# checks do not depend on what Jev answers (Jev is still called by `classify`).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE:-$HOME/migtest-edge}"
MIGRATOR="${MIGRATOR:-migrator}"             # override only to inject a test double
export MIGRATOR_BIN="${MIGRATOR_BIN:-$MIGRATOR}"
PY="${PY:-python}"
LOG="$BASE/trial.log"

PASS=0; FAIL=0; FAILED_CHECKS=()

case "$BASE" in "$HOME"|/|"") echo "refusing BASE=$BASE"; exit 2;; esac
[[ -n "${MIGRATOR_DATABASE_URL:-}" ]] || { echo "MIGRATOR_DATABASE_URL is not set"; exit 2; }
command -v "$MIGRATOR" >/dev/null || { echo "$MIGRATOR not found (activate the venv)"; exit 2; }
rm -rf -- "$BASE" && mkdir -p -- "$BASE" && : > "$LOG"

ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); FAILED_CHECKS+=("$CASE: $1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
check() { local d="$1"; shift; if "$@" >>"$LOG" 2>&1; then ok "$d"; else bad "$d"; fi; }
mig()  { "$MIGRATOR" --log-level WARNING "$@" 2>>"$LOG"; }
has()  { grep -qF -- "$2" <<<"$1"; }
rc_out() {     # rc_out WANTED_RC [text-that-must-appear ...]  (uses $RC and $OUT)
    [[ "$RC" -eq "$1" ]] || return 1; shift
    local t; for t in "$@"; do grep -qF -- "$t" <<<"$OUT" || return 1; done
}
count_is() { [[ "$(grep -cF -- "$2" <<<"$3")" -eq "$1" ]]; }   # count_is N needle text
content_is() { [[ -f "$1" && "$(cat -- "$1")" == "$2" ]]; }

# fingerprint of a tree: names, types, sizes, mtimes, inodes and content hashes
fingerprint() {
    (cd "$1" 2>/dev/null && find . -printf '%p|%y|%s|%T@|%i\n' | LC_ALL=C sort &&
     find . -type f -print0 | LC_ALL=C sort -z | xargs -0r sha256sum) | sha256sum
}

sql1() {   # first column of the first row
    "$PY" - "$@" <<'EOF'
import sys
from migrator import db
c = db.connect()
r = c.execute(sys.argv[1], tuple(sys.argv[2:])).fetchone()
print("" if r is None else list(r.values())[0])
EOF
}

new_case() {
    CASE="$1"; shift
    echo; echo "== $CASE: $*"; echo "== $CASE" >>"$LOG"
    D="$BASE/$CASE"; SRC="$D/MEDIA"; LIB="$D/LIB"; WS="$D/WS"; CFG="$D/config.yaml"
    mkdir -p "$SRC" "$LIB" "$WS"
    sed -e "s#/mnt/data/MIGRATION_WORKSPACE#$WS#" -e "s#/mnt/data/MEDIA_LIBRARY#$LIB#" \
        -e "s#/mnt/data/MEDIA\$#$SRC#" "$REPO/examples/media-migration.yaml" > "$CFG"
}

# create run, inventory, classify, then force every file under the root to MOVIES
stage1() {
    RUN="$(mig run create --config "$CFG" | sed -n 's/^RUN_ID=//p')"
    [[ -n "$RUN" ]] || { bad "run create"; return 1; }
    RD="$WS/runs/$RUN"
    mig inventory --run "$RUN" >>"$LOG" || { bad "inventory"; return 1; }
    mig classify --run "$RUN" >>"$LOG" || { bad "classify"; return 1; }
    local root
    root="$(sql1 "SELECT d.directory_id FROM directory_inventory d JOIN scan_root r USING (scan_root_id)
                  WHERE d.run_id = %s AND d.depth = 0 AND r.root_type = 'SOURCE'" "$RUN")"
    mig review set-directory --run "$RUN" --directory "$root" --target MOVIES --subtree >>"$LOG" ||
        { bad "review set-directory"; return 1; }
}

stage2() {
    mig plan create --run "$RUN" >>"$LOG" || { bad "plan create"; return 1; }
    mig batches generate --run "$RUN" >>"$LOG" || { bad "batches generate"; return 1; }
    BATCH="$RD/batches/batch_000001.sh"
}

run_batch() {   # sets OUT and RC
    OUT="$(env "$@" bash "$BATCH" 2>&1)"; RC=$?
    printf '%s\n' "--- batch (rc=$RC)" "$OUT" >>"$LOG"
}

file_id() { sql1 "SELECT file_id FROM file_inventory WHERE run_id = %s AND basename = %s" "$RUN" "$1"; }
op_id()   { sql1 "SELECT po.operation_id FROM plan_operation po JOIN file_inventory f USING (file_id)
                  WHERE po.run_id = %s AND f.basename = %s ORDER BY po.created_at DESC" "$RUN" "$1"; }

want() { [[ $# -eq 0 ]] || printf '%s\n' "$@"; }
selected() { [[ ${#SELECT[@]} -eq 0 ]] && return 0; local s; for s in "${SELECT[@]}"; do [[ $s == "$1" ]] && return 0; done; return 1; }
SELECT=("$@")

# ------------------------------------------------------------------------------------------------
if selected s01; then
new_case s01 "happy path, Python never mutates, rerun is idempotent, reconcile + audit chain"
mkdir -p "$SRC/sub"; echo alpha > "$SRC/a.mkv"; echo beta > "$SRC/sub/b.mkv"
before="$(fingerprint "$D/MEDIA")$(fingerprint "$LIB")"
stage1 && stage2 && {
    mig plan show --run "$RUN" >/dev/null; mig plan conflicts --run "$RUN" >/dev/null
    mig batches verify --run "$RUN" >>"$LOG"; mig run summary --run "$RUN" >/dev/null
    mig review list --run "$RUN" >/dev/null; mig audit status --run "$RUN" >/dev/null
    after="$(fingerprint "$D/MEDIA")$(fingerprint "$LIB")"
    check "Python commands left MEDIA and LIB byte-for-byte unchanged" test "$before" == "$after"
    check "batches verify passes" mig batches verify --run "$RUN"
    run_batch
    check "batch exit 0" test "$RC" -eq 0
    check "Success: 2" has "$OUT" "Success: 2"
    check "targets have the original content" bash -c "[[ \$(cat '$LIB/MOVIES/a.mkv') == alpha && \$(cat '$LIB/MOVIES/sub/b.mkv') == beta ]]"
    check "sources removed, source directories kept" bash -c "[[ ! -e '$SRC/a.mkv' && ! -e '$SRC/sub/b.mkv' && -d '$SRC/sub' ]]"
    check "no .partial files left" bash -c "[[ -z \$(find '$LIB' -name '*.partial') ]]"
    run_batch
    check "rerun: exit 0 and Already complete: 2" rc_out 0 "Already complete: 2"
    rec="$(mig reconcile --run "$RUN")"
    check "reconcile: VERIFIED_MOVED 2" has "$rec" '"VERIFIED_MOVED": 2'
    check "audit verify-chain clean" mig audit verify-chain --run "$RUN"
}
fi

if selected s02; then
new_case s02 "source modified after planning -> blocked, nothing copied"
echo alpha > "$SRC/a.mkv"; echo beta > "$SRC/b.mkv"
stage1 && stage2 && {
    echo changed > "$SRC/a.mkv"
    run_batch
    check "batch exit 1" test "$RC" -eq 1
    check "Blocked: 1 / Success: 1" rc_out 1 "Blocked: 1" "Success: 1"
    check "changed source kept as is" content_is "$SRC/a.mkv" changed
    check "no target written for it" test ! -e "$LIB/MOVIES/a.mkv"
    check "the other file moved" content_is "$LIB/MOVIES/b.mkv" beta
}
fi

if selected s03; then
new_case s03 "target appears with other content after planning -> never overwritten"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    mkdir -p "$LIB/MOVIES"; echo squatter > "$LIB/MOVIES/a.mkv"
    run_batch
    check "batch exit 1, Blocked: 1" rc_out 1 "Blocked: 1"
    check "existing target untouched" content_is "$LIB/MOVIES/a.mkv" squatter
    check "source kept" content_is "$SRC/a.mkv" alpha
}
fi

if selected s04; then
new_case s04 "interrupted after target commit (identical target exists) -> resumes, deletes source"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    mkdir -p "$LIB/MOVIES"; cp "$SRC/a.mkv" "$LIB/MOVIES/a.mkv"
    run_batch
    check "batch exit 0, Success: 1" rc_out 0 "Success: 1"
    check "source deleted" test ! -e "$SRC/a.mkv"
    check "target intact" content_is "$LIB/MOVIES/a.mkv" alpha
}
fi

if selected s05; then
new_case s05 "source and target both missing -> DATA_MISSING, blocked"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    rm "$SRC/a.mkv"
    run_batch
    check "batch exit 1, Blocked: 1" rc_out 1 "Blocked: 1"
    mig audit sync --run "$RUN" >>"$LOG"
    ev="$(sql1 "SELECT e.event_type FROM audit_event e JOIN file_inventory f USING (trace_id)
                WHERE f.run_id = %s ORDER BY e.sequence_no DESC" "$RUN")"
    check "last audit event is DATA_MISSING" test "$ev" == DATA_MISSING
}
fi

if selected s06; then
new_case s06 "leftover .partial from a crashed copy -> cleaned up, move completes"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    op="$(op_id a.mkv)"; mkdir -p "$LIB/MOVIES"; echo half > "$LIB/MOVIES/.a.mkv.migrator-$op.partial"
    run_batch
    check "batch exit 0" test "$RC" -eq 0
    check "target complete" content_is "$LIB/MOVIES/a.mkv" alpha
    check "partial removed" test ! -e "$LIB/MOVIES/.a.mkv.migrator-$op.partial"
}
fi

if selected s07; then
new_case s07 "symlinks ignored, hardlinks held for review"
echo solo > "$SRC/solo.mkv"; echo hard > "$SRC/h1.mkv"; ln "$SRC/h1.mkv" "$SRC/h2.mkv"
ln -s solo.mkv "$SRC/link.mkv"; ln -s /nonexistent "$SRC/dangling.mkv"
stage1 && stage2 && {
    conf="$(mig plan conflicts --run "$RUN")"
    check "hardlinks reported as BLOCKED_HARDLINK" count_is 2 BLOCKED_HARDLINK "$conf"
    check "symlinks not in the plan" bash -c "! grep -q 'link.mkv\|dangling' '$RD/plan/plan-0001.jsonl'"
    run_batch
    check "only the regular file moved (Success: 1)" rc_out 0 "Success: 1"
    check "hardlinks and symlinks still in MEDIA" bash -c "[[ -f '$SRC/h1.mkv' && -f '$SRC/h2.mkv' && -L '$SRC/link.mkv' && -L '$SRC/dangling.mkv' ]]"
}
fi

if selected s08; then
new_case s08 "hostile file names are moved verbatim and never executed"
names=("it's \"quoted\".mkv" '$(touch PWNED1).mkv' '`touch PWNED2`.mkv' $'line\nbreak.mkv' $'tab\there.mkv'
       '-rf.mkv' 'Zażółć gęślą jaźń.mkv' 'a; touch PWNED3 && b | c.mkv' 'back\slash.mkv' 'glob*?[x].mkv'
       '  spaces  .mkv' '--help.mkv')
for n in "${names[@]}"; do printf '%s' "$n" > "$SRC/$n"; done
stage1 && stage2 && {
    mig batches verify --run "$RUN" >>"$LOG"
    OUT="$(cd "$D" && bash "$BATCH" 2>&1)"; RC=$?; printf '%s\n' "$OUT" >>"$LOG"
    check "batch exit 0, Success: ${#names[@]}" rc_out 0 "Success: ${#names[@]}"
    allok=1
    for n in "${names[@]}"; do [[ "$(cat -- "$LIB/MOVIES/$n" 2>/dev/null)" == "$n" ]] || { allok=0; echo "missing: $n" >>"$LOG"; }; done
    check "every name arrived byte-for-byte with its content" test "$allok" -eq 1
    check "no injected command ran" bash -c "[[ -z \$(find '$BASE' '$REPO' -name 'PWNED*' 2>/dev/null) ]]"
}
fi

if selected s09; then
new_case s09 "collisions with existing library content"
mkdir -p "$LIB/MOVIES"
echo different > "$LIB/MOVIES/same.mkv"; echo x > "$LIB/MOVIES/Movie.mkv"; echo ident > "$LIB/MOVIES/ident.mkv"
echo mine > "$SRC/same.mkv"; echo y > "$SRC/movie.mkv"; echo ident > "$SRC/ident.mkv"; echo ok > "$SRC/ok.mkv"
stage1 && stage2 && {
    conf="$(mig plan conflicts --run "$RUN")"; printf '%s\n' "$conf" >>"$LOG"
    check "different content at target detected" has "$conf" TARGET_EXISTS_DIFFERENT_CONTENT
    check "case-only collision detected" has "$conf" CASEFOLD_TARGET_COLLISION
    check "identical existing target held for review" has "$conf" TARGET_ALREADY_IDENTICAL
    run_batch
    check "only the clean file moved (Success: 1)" rc_out 0 "Success: 1"
    check "library files untouched" bash -c "[[ \$(cat '$LIB/MOVIES/same.mkv') == different && \$(cat '$LIB/MOVIES/Movie.mkv') == x ]]"
    check "held sources still in MEDIA" bash -c "[[ -f '$SRC/same.mkv' && -f '$SRC/movie.mkv' && -f '$SRC/ident.mkv' ]]"
}
fi

if selected s10; then
new_case s10 "batch from a superseded plan refuses to run"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    mig plan create --run "$RUN" >>"$LOG"
    run_batch
    check "batch exit 2 (preflight)" test "$RC" -eq 2
    run_batch VERIFY_SELF=0
    check "also refused by the audit chain check (exit 2, stale)" rc_out 2 stale
    check "nothing moved" bash -c "[[ -f '$SRC/a.mkv' && ! -e '$LIB/MOVIES/a.mkv' ]]"
}
fi

if selected s11; then
new_case s11 "edited batch script refuses to run"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    chmod u+w "$BATCH"; echo "# edited" >> "$BATCH"
    run_batch
    check "batch exit 2, hash mismatch reported" rc_out 2 "does not match its recorded SHA-256"
    check "nothing moved" test -f "$SRC/a.mkv"
    check "batches verify reports the tampering" bash -c "! '$MIGRATOR' --log-level WARNING batches verify --run '$RUN'"
}
fi

if selected s12; then
new_case s12 "PostgreSQL unreachable during the batch -> spool, then audit sync"
echo alpha > "$SRC/a.mkv"
stage1 && stage2 && {
    run_batch MIGRATOR_DATABASE_URL='postgresql://nobody@127.0.0.1:1/none?connect_timeout=2'
    check "batch still succeeds (exit 0)" test "$RC" -eq 0
    st="$(mig audit status --run "$RUN")"; printf '%s\n' "$st" >>"$LOG"
    check "events are waiting in the local spool" bash -c 'grep -q "\"pending\": [1-9]" <<<"$1"' _ "$st"
    check "audit sync imports them" mig audit sync --run "$RUN"
    check "audit chain verifies" mig audit verify-chain --run "$RUN"
}
fi

if selected s13; then
new_case s13 "STOP_ON_ERROR=1 stops at the first problem"
echo alpha > "$SRC/a.mkv"; echo beta > "$SRC/b.mkv"
stage1 && stage2 && {
    echo changed > "$SRC/a.mkv"
    run_batch STOP_ON_ERROR=1
    check "batch exit 1, remaining operation not run" rc_out 1 "Not run"
    check "b.mkv untouched" bash -c "[[ -f '$SRC/b.mkv' && ! -e '$LIB/MOVIES/b.mkv' ]]"
}
fi

if selected s14; then
new_case s14 "human per-file override creates a new plan route"
echo alpha > "$SRC/a.mkv"; echo novel > "$SRC/novel.epub"
stage1 && {
    mig review set --run "$RUN" --file "$(file_id novel.epub)" --target BOOKS >>"$LOG"
    stage2 && {
        run_batch
        check "batch exit 0" test "$RC" -eq 0
        check "override honoured (BOOKS/novel.epub)" content_is "$LIB/BOOKS/novel.epub" novel
        check "the rest follows the directory decision" content_is "$LIB/MOVIES/a.mkv" alpha
        n="$(sql1 "SELECT count(*) FROM route_decision WHERE run_id = %s AND decision_source = 'HUMAN'" "$RUN")"
        check "both human decisions recorded" test "$n" -eq 2
    }
}
fi

echo
echo "========================================"
echo "PASS: $PASS   FAIL: $FAIL   (details: $LOG)"
for f in "${FAILED_CHECKS[@]+"${FAILED_CHECKS[@]}"}"; do echo "  failed: $f"; done
[[ $FAIL -eq 0 ]]
