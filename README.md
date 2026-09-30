# File Migration Planner

Plans and audits filesystem migrations. **The Python application never copies, moves, renames,
deletes or changes permissions of any migration file.** It inventories, hashes, classifies (with
Jev 1.13), plans, records lineage in PostgreSQL, and *generates reviewed Bash batch scripts*.
Only a human explicitly running those scripts changes the filesystem. There is deliberately no
`migrator execute` (nor `move`/`copy`) command, and a test asserts it.

```
Python application                          Generated Bash (run by a human)
  scan → hash → classify → plan →             precheck → copy → verify SHA-256 →
  audit → generate bash → reconcile           commit target → verify → delete source
  X never mutates source/target files         reports audit events back
```

| Layer | Owner |
|---|---|
| Filesystem facts | Python scanner + SHA-256 (`hashlib`) |
| Semantic decision (which configured target?) | Jev, from **names only** |
| Safety decisions, paths, collisions, thresholds | deterministic Python |
| Plan | PostgreSQL + immutable artifacts |
| Mutation | generated Bash, executed by a human |
| Audit | append-only per-file hash chain |
| Ground truth after execution | reconciliation (stat + SHA-256) |

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
export MIGRATOR_DATABASE_URL='postgresql://user:pass@host/dbname'
export OPENROUTER_API_KEY='...'
migrator db migrate
```

The SQL migrations are read from the repository's `sql/` directory (an editable install finds it
automatically; otherwise set `MIGRATOR_SQL_DIR`). Applied migrations are checksummed: editing one after
it was applied is refused.

Requires Python ≥ 3.11, PostgreSQL, and on the machine that *runs the generated batches*: bash ≥ 4,
GNU coreutils (`cp`, `ln`, `rm`, `stat`, `sha256sum`) and the `migrator` executable (used only for
`audit emit`). Secrets are read from environment variables named in the config; they are never
written to the config snapshot, database, scripts or logs.

## Operator workflow

```bash
migrator run create --config media-migration.yaml      # prints RUN_ID=...
migrator inventory  --run $RUN                        # discovery -> hashing -> manifests
migrator run summary --run $RUN
migrator classify   --run $RUN                         # recursive Jev routing
migrator review list --run $RUN                        # what needs a human
migrator review export --run $RUN --output review.csv  # fill human_target (+human_subtree for DIRECTORY rows)
migrator review import --run $RUN --input review.csv
migrator review set --run $RUN --file FILE_ID --target MOVIES
migrator review set-directory --run $RUN --directory DIR_ID --target MOVIES --subtree
migrator plan create --run $RUN                        # immutable plan revision
migrator plan conflicts --run $RUN
migrator batches generate --run $RUN
migrator batches verify   --run $RUN
# ---- the application stops here. A human reads and runs the scripts: ----
./workspace/runs/$RUN/batches/batch_000001.sh
migrator audit sync --run $RUN
migrator reconcile  --run $RUN
migrator audit verify-chain --run $RUN
migrator run summary --run $RUN
```

`migrator prepare --config X` chains create → inventory → classify → plan → batches, prints a
summary, and never executes anything.

Confident files/subtrees proceed while uncertain ones wait: `REVIEW`/`BLOCKED` rows never get a
command, and `batches generate` reports how many were excluded. If review decisions change, run
`plan create` again: it makes revision N+1. Batches of older revisions stay on disk as evidence but
`batches verify` flags them as superseded and their first audit event is refused (stale chain head).
Revision 1 batches live in `batches/`, later revisions in `batches/plan-000N/`.

### Batch script controls

| Variable | Default | Meaning |
|---|---|---|
| `STOP_ON_ERROR` | `0` | `1` stops the batch at the first failed/blocked operation |
| `MIGRATOR_BIN` | `migrator` | executable used only for `audit emit` |
| `VERIFY_SELF` | `1` | preflight checks the script against its `.sha256` sidecar and the plan hash |
| `AUDIT_MODE` | `serve` | `serve`: one persistent `migrator audit serve` helper per batch (fast); `process`: one `audit emit` process per event (also the automatic fallback if the helper cannot start) |

Exit status: `0` all success/already-complete, `1` any failed/blocked, `2` preflight or audit failure.

## Safety properties (and where they are enforced)

* **Only regular files migrate.** Symlinks are counted and ignored, never followed. Hardlinked
  *source* files (`st_nlink > 1`) become `BLOCKED_HARDLINK` → `REVIEW` (`inventory.hardlinks.action`).
* **Every file has a permanent `trace_id`** from discovery; all events chain to it.
* **No file without a SHA-256 is planned** (`FAILED`, `UNSTABLE`, `BLOCKED_HARDLINK` are excluded).
  Hashing retries when `st_dev/st_ino/size/mtime_ns` change mid-read.
* **Jev sees names only** (`file_name`, `current_directory`, `ancestor_names`, sampled child
  directory/file names) and can only choose configured target ids plus `DESCEND` (directories) or
  `REVIEW` (files). Sampling is deterministic (SHA-256 order, not filesystem order). Tests assert the
  payload contains no hash/size/time/owner/ACL/metadata.
* **`confidence < threshold` never routes automatically.** The threshold applies to the returned
  `confidence`, not to the winning option's probability; both are stored.
* **Target paths are computed, not chosen by Jev**, preserve names byte-for-byte, and must stay
  beneath the target root (`safe_join`).
* **No overwrite, ever.** Promotion is `ln -T tmp final` (fails if `final` exists) then `rm tmp`.
  Existing targets → `TARGET_ALREADY_IDENTICAL` (review) / `TARGET_EXISTS_DIFFERENT_CONTENT`;
  exact and case-folded collisions → review.
* **Source deleted only after** the final target has the inventory SHA-256, and only if the source's
  `dev:ino:size:mtime` did not change during the copy.
* **Pre-events are durable before state changes.** `audit emit` fsyncs a spool file first; if that
  fails the operation does nothing and the batch exits 2.
* **Plans, batches, decisions and audit events are immutable/append-only** (database triggers).
* **Python only writes** under the workspace (guarded) and to PostgreSQL. `review export --output`
  refuses paths under any migration root.

## Audit

Per-trace hash chain: `event_hash = SHA256(previous_event_hash + canonical_json(event_id, run_id,
trace_id, file_id, operation_id, batch_id, sequence_no, event_type, actor, event_time, payload,
source))`. Appends lock `trace_head` `FOR UPDATE`. Each batch operation stores the trace head at
generation time; the first `audit emit` continues from it (and is refused if PostgreSQL shows the
trace moved on for any reason other than read-only reconciliation).

`audit emit` → spool file (`audit-spool/<trace>/<seq>-<event>.json`, fsynced) → best-effort insert.
`audit sync` validates spooled chains, inserts idempotently by `event_id`, marks `*.synced`, and
reports `GAP`/`DIVERGED`/`MUTATED_EVENT`. `audit verify-chain` recomputes everything from PostgreSQL.
`reconcile` syncs the spool first so chains stay linear.

## Failure and recovery

| Situation | Behaviour / action |
|---|---|
| PostgreSQL down during a batch | Events go to the spool; batch continues. Run `audit sync` later. |
| Spool can't be written | Operation refuses to start; batch exit 2; nothing changed. |
| Batch interrupted after target commit | Re-run the script: `OPERATION_RESUMED_AFTER_TARGET_COMMIT`, then source delete. |
| Interrupted mid-copy | Leftover `.<name>.migrator-<op>.partial` is removed by the same operation on re-run. |
| Source missing and target correct | `OPERATION_ALREADY_COMPLETE`. |
| Source & target both missing | `DATA_MISSING` (critical): investigate; reconcile reports `SOURCE_MISSING_TARGET_MISSING`. |
| Source changed after inventory | `SOURCE_CHANGED_AFTER_INVENTORY`, nothing copied. Create a **new run**. |
| Target appeared after plan | `TARGET_APPEARED_AFTER_PLAN`; temp removed, source kept. |
| Discovery interrupted | Not resumable: create a new run. (Hashing and classification are resumable.) |
| Classification API failure | `CLASSIFICATION_API_FAILED` → review; re-run `classify` retries only failed items. |
| Config changed | Create a new run; commands given `--config` refuse a different config. |

## Configuration notes

* `scope.allow_overlapping_sources` / `scope.allow_targets_in_sources` are the explicit opt-ins.
* The workspace must not overlap any source/target root.
* `planning.*` knobs accept `review|block`. The spec's collision section says "same target, different
  SHA-256 ⇒ BLOCKED"; the built-in default is `block`, while the sample config from the task sets
  `review`. Either way the file is excluded from batches.
* v1 rejects (rather than silently ignores) settings that would weaken safety: `overwrite_existing_targets: true`,
  `preserve_source_*: true`, non-SHA-256 algorithms, `reconciliation.verify_sha256: false`, etc.

## Architecture

```
src/migrator/
  config.py      load/validate/normalize/hash config          paths.py     safe_join, globs, guarded writes
  db.py          psycopg 3, SQL migrations, state machine     constants.py states/statuses/event names
  runs.py        run creation + snapshot                      models.py    small records
  inventory.py   discovery + hashing + manifests              hashing.py   streaming SHA-256, stability
  audit.py       hash chain, spool, sync, verify              jev.py       Decisions API client (names only)
  classifier.py  recursion, cache, route resolution, review   planner.py   paths, revalidation, plan revisions
  collisions.py  exact/casefold/existing-target detection     batches.py   Bash generation + verification
  reconcile.py   post-execution SHA-256 reconciliation        reports.py   summary / conflicts
  cli.py         Typer commands                               logs.py      structured JSON logs, redaction
sql/001_initial.sql   schema, append-only triggers
```

Run states: `CREATED → DISCOVERING → DISCOVERY_COMPLETE → HASHING → INVENTORY_COMPLETE → CLASSIFYING →
{CLASSIFIED | REVIEW_REQUIRED} → PLANNING → PLAN_READY → BATCHES_GENERATED → EXTERNAL_EXECUTION_OBSERVED →
RECONCILING → RECONCILED`. There is no application-side `EXECUTING` state.

## Tests

```bash
pytest                       # unit + PostgreSQL integration (starts a throw-away local cluster; or set
                             # MIGRATOR_TEST_DATABASE_URL to an admin DSN that may create databases)
pytest tests/unit            # no database needed
OPENROUTER_API_KEY=... pytest -m live_jev    # optional live check of the Jev request/response assumptions
```

Release-blocking: `tests/integration/test_no_mutation.py` runs every Python command and asserts the
source and target trees are byte-for-byte unchanged; only the generated Bash changes them.

## Known gaps — read before production use

1. **Jev API shape is unverified.** The build environment could not reach openrouter.ai, so
   `jev.py` follows the task specification (`state` + `questions.route`; `answers.route.choice/
   probabilities/confidence`, request id from `id` or `x-request-id`, `usage`, `model`). Run the
   `live_jev` tests first; adjust `parse_response` if the real schema differs.
2. **ACL inheritance is not verified on TrueNAS/ZFS.** Tests prove mode/owner/timestamps are not
   preserved and (where POSIX ACL tools exist) that default ACLs are inherited. Run
   `scripts/verify_acl_inheritance.sh <dest dir>` on the real dataset (NFSv4 ACLs) and adjust the copy
   primitive if needed. Do not treat permission handling as done until then.
3. **Promotion uses a hard link** (`ln`, then `rm` of the temp name) because it is the portable atomic
   no-overwrite primitive. The destination filesystem must support hard links.
4. **Names that are not valid UTF-8** cannot be stored in PostgreSQL text; such files/directories are
   skipped and counted (`undecodable_skipped_count`), never migrated. Rename them first.
5. **Hardlinked source files are not hashed** (`BLOCKED_HARDLINK`); hardlinked *target* files are.
6. **Audit callback cost.** A per-event `migrator audit emit` process costs ~200 ms (Python + psycopg
   import), i.e. ~2 s per file at ~10 events per file. Batches therefore start one `audit serve` helper
   (Bash coprocess; it replies `OK` only after the event file is fsynced) — measured ~5x faster end to
   end in the test suite. Throughput at real scale (100k+ files, fsync latency on the actual pool) has
   not been measured; use `MIGRATOR_AUDIT_NO_DB=1` (spool only) and `audit sync` afterwards if PostgreSQL
   round-trips become the bottleneck.
7. Scale has been exercised with hundreds of files, not millions; `plan create` keeps the operations
   of one plan in memory.
8. After re-planning, `reconcile` works against the latest plan and needs its batches generated. If the
   new revision has no READY operations, the run never reaches `BATCHES_GENERATED` and `reconcile` refuses.
9. Discovery is not resumable; a real mount boundary (`cross_mounts: false`) is tested with a simulated
   `st_dev`, not a real second filesystem.
