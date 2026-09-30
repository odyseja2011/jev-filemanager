"""Typer CLI.

There is intentionally NO `execute`, `move` or `copy` command: the application
plans and audits; a human runs the generated Bash.
"""

from __future__ import annotations

import functools
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

import typer

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="Plan and audit filesystem migrations. Never moves files itself.")
db_app = typer.Typer(no_args_is_help=True, help="Database schema management.")
run_app = typer.Typer(no_args_is_help=True, help="Migration runs.")
review_app = typer.Typer(no_args_is_help=True, help="Human review of uncertain routes.")
plan_app = typer.Typer(no_args_is_help=True, help="Migration plans.")
batches_app = typer.Typer(no_args_is_help=True, help="Generated Bash batches (never executed here).")
audit_app = typer.Typer(no_args_is_help=True, help="Append-only audit chain.")
app.add_typer(db_app, name="db")
app.add_typer(run_app, name="run")
app.add_typer(review_app, name="review")
app.add_typer(plan_app, name="plan")
app.add_typer(batches_app, name="batches")
app.add_typer(audit_app, name="audit")

_STATE: dict[str, Any] = {"dsn_env": "MIGRATOR_DATABASE_URL"}

RunOpt = typer.Option(..., "--run", help="Run id (UUID).")
ConfigCheckOpt = typer.Option(None, "--config", help="Refuse to continue if this config differs from the run's snapshot.")


@app.callback()
def _root(dsn_env: str = typer.Option("MIGRATOR_DATABASE_URL", "--dsn-env",
                                      help="Name of the environment variable holding the PostgreSQL DSN."),
          log_level: str = typer.Option("INFO", "--log-level")) -> None:
    from migrator.logs import configure_logging
    _STATE["dsn_env"] = dsn_env
    configure_logging(log_level)


def guarded(fn: Callable) -> Callable:
    """Turn expected domain errors into a clean message and exit status 1."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        from migrator.audit import AuditError
        from migrator.batches import BatchError
        from migrator.classifier import ClassifyError
        from migrator.config import ConfigError
        from migrator.db import DatabaseError
        from migrator.inventory import InventoryError
        from migrator.jev import JevError
        from migrator.planner import PlanError
        from migrator.reconcile import ReconcileError
        from migrator.runs import RunError
        import psycopg
        try:
            return fn(*a, **kw)
        except (ConfigError, DatabaseError, RunError, ClassifyError, InventoryError, PlanError,
                BatchError, ReconcileError, AuditError, JevError, psycopg.Error, OSError) as exc:
            from migrator.logs import redact
            typer.echo(f"error: {redact(str(exc))}", err=True)
            raise typer.Exit(1)
    return wrapper


def _connect():
    from migrator import db
    return db.connect(dsn_env=_STATE["dsn_env"])


def _open(run_id: str, config: Optional[Path] = None):
    from migrator.runs import open_run
    conn = _connect()
    return open_run(conn, run_id, config)


def make_jev_client(cfg):
    """Factory kept module-level so tests can substitute a fake client."""
    from migrator.jev import OpenRouterJevClient
    return OpenRouterJevClient.from_config(cfg)


def _echo_json(obj: Any) -> None:
    typer.echo(json.dumps(obj, indent=2, sort_keys=True, default=str))


# --- db ---------------------------------------------------------------------------------------

@db_app.command("migrate")
@guarded
def db_migrate() -> None:
    """Apply pending SQL migrations."""
    from migrator import db
    with _connect() as conn:
        applied = db.migrate(conn)
    typer.echo("applied: " + (", ".join(applied) if applied else "nothing (up to date)"))


@db_app.command("status")
@guarded
def db_status() -> None:
    """Show applied and pending migrations."""
    from migrator import db
    with _connect() as conn:
        st = db.migration_status(conn)
    _echo_json(st)


# --- run --------------------------------------------------------------------------------------

@run_app.command("create")
@guarded
def run_create(config: Path = typer.Option(..., "--config", exists=True, dir_okay=False)) -> None:
    """Validate and snapshot the configuration, then create a run."""
    from migrator.config import load_config
    from migrator.runs import create_run
    cfg, _ = load_config(config)
    from migrator import db
    conn = db.connect(dsn_env=cfg["database"]["dsn_env"])
    ctx = create_run(conn, config)
    typer.echo(f"RUN_ID={ctx.run_id}")
    typer.echo(f"run directory: {ctx.run_dir}")
    typer.echo(f"config sha256: {ctx.run['config_sha256'].strip()}")


@run_app.command("status")
@guarded
def run_status(run: str = RunOpt) -> None:
    """Show the run's state and state history."""
    ctx = _open(run)
    hist = ctx.conn.execute("SELECT from_state, to_state, at FROM run_state_history WHERE run_id = %s ORDER BY id",
                            (ctx.run_id,)).fetchall()
    _echo_json({"run_id": ctx.run_id, "name": ctx.run["name"], "state": ctx.run["state"],
                "workspace": ctx.run["workspace_path"], "run_dir": str(ctx.run_dir),
                "history": [f"{h['at']:%Y-%m-%d %H:%M:%S} {h['from_state']} -> {h['to_state']}" for h in hist]})


@run_app.command("summary")
@guarded
def run_summary(run: str = RunOpt, as_json: bool = typer.Option(False, "--json")) -> None:
    """Summarize inventory, classification, plan, batches, execution and reconciliation."""
    from migrator import reports
    ctx = _open(run)
    s = reports.write_summary(ctx)
    typer.echo(json.dumps(s, indent=2, sort_keys=True, default=str) if as_json else reports.format_summary(s))


# --- inventory / classify -----------------------------------------------------------------------

@app.command("inventory")
@guarded
def inventory_cmd(run: str = RunOpt, config: Optional[Path] = ConfigCheckOpt) -> None:
    """Discover, hash and export manifests (read-only on source and target roots)."""
    from migrator import inventory
    ctx = _open(run, config)
    res = inventory.run_inventory(ctx)
    for rid, d in res.get("discovery", {}).items():
        typer.echo(f"{rid}: files={d['files']} dirs={d['dirs']} symlinks_skipped={d['symlinks_skipped']}")
    typer.echo(f"state: {ctx.refresh()['state']}")
    typer.echo(f"manifests: {json.dumps(res.get('manifests', {}))}")


@app.command("classify")
@guarded
def classify_cmd(run: str = RunOpt, config: Optional[Path] = ConfigCheckOpt) -> None:
    """Recursively classify directories and files with Jev."""
    from migrator import classifier
    ctx = _open(run, config)
    client = make_jev_client(ctx.cfg)
    try:
        res = classifier.run_classification(ctx, client)
    finally:
        close = getattr(client, "close", None)
        if close:
            close()
    _echo_json(res)


# --- review -------------------------------------------------------------------------------------

@review_app.command("list")
@guarded
def review_list(run: str = RunOpt, limit: int = typer.Option(50, "--limit")) -> None:
    """List files that need a human decision."""
    from migrator import classifier
    ctx = _open(run)
    rows = classifier.review_rows(ctx)
    typer.echo(f"{len(rows)} file(s) need review")
    for r in rows[:limit]:
        typer.echo(f"{r['subject_id']}  {r['route_status']:8} {r['reason_code']:26} "
                   f"{r['jev_choice'] or '-':10} {r['absolute_path']}")
    if len(rows) > limit:
        typer.echo(f"... {len(rows) - limit} more (use `review export`)")


@review_app.command("export")
@guarded
def review_export(run: str = RunOpt, output: Path = typer.Option(..., "--output")) -> None:
    """Write review.csv; fill in human_target (and human_subtree for DIRECTORY rows)."""
    from migrator import classifier
    ctx = _open(run)
    typer.echo(str(classifier.export_review_csv(ctx, output)))


@review_app.command("import")
@guarded
def review_import(run: str = RunOpt, input: Path = typer.Option(..., "--input", exists=True)) -> None:
    """Apply the filled-in rows as new HUMAN decisions (all-or-nothing)."""
    from migrator import classifier
    ctx = _open(run)
    _echo_json(classifier.import_review_csv(ctx, input))


@review_app.command("set")
@guarded
def review_set(run: str = RunOpt, file: str = typer.Option(..., "--file"),
               target: str = typer.Option(..., "--target")) -> None:
    """Route one file by human decision (creates a new decision; Jev's is kept)."""
    from migrator import classifier
    ctx = _open(run)
    did = classifier.set_file_target(ctx, file, target)
    typer.echo(f"decision {did}")


@review_app.command("set-directory")
@guarded
def review_set_directory(run: str = RunOpt, directory: str = typer.Option(..., "--directory"),
                         target: str = typer.Option(..., "--target"),
                         subtree: bool = typer.Option(False, "--subtree",
                                                      help="Apply to the whole subtree (default: direct files only).")
                         ) -> None:
    """Route a directory by human decision."""
    from migrator import classifier
    ctx = _open(run)
    did = classifier.set_directory_target(ctx, directory, target, subtree=subtree)
    typer.echo(f"decision {did}")


# --- plan ---------------------------------------------------------------------------------------

@plan_app.command("create")
@guarded
def plan_create(run: str = RunOpt, config: Optional[Path] = ConfigCheckOpt) -> None:
    """Create a new immutable plan revision."""
    from migrator import planner, reports
    ctx = _open(run, config)
    res = planner.create_plan(ctx)
    reports.write_conflicts_csv(ctx)
    _echo_json(res)


@plan_app.command("show")
@guarded
def plan_show(run: str = RunOpt) -> None:
    """Show the latest plan revision."""
    from migrator import planner
    ctx = _open(run)
    plan = planner.latest_plan(ctx.conn, ctx.run_id)
    if plan is None:
        raise typer.Exit(1)
    per_target = ctx.conn.execute(
        "SELECT COALESCE(target_id, '-') AS target_id, plan_status, count(*) AS n FROM plan_operation "
        "WHERE plan_id = %s GROUP BY 1, 2 ORDER BY 1, 2", (str(plan["plan_id"]),)).fetchall()
    _echo_json({"plan_id": str(plan["plan_id"]), "revision": plan["revision"],
                "plan_sha256": plan["plan_sha256"].strip(), "operations": plan["operation_count"],
                "ready": plan["ready_count"], "review": plan["review_count"],
                "blocked": plan["blocked_count"], "noop": plan["noop_count"],
                "per_target": [f"{r['target_id']} {r['plan_status']}: {r['n']}" for r in per_target]})


@plan_app.command("conflicts")
@guarded
def plan_conflicts(run: str = RunOpt, limit: int = typer.Option(50, "--limit")) -> None:
    """List operations held back from batches (REVIEW / BLOCKED) and why."""
    from migrator import reports
    ctx = _open(run)
    rows = reports.plan_blockers(ctx)
    path = reports.write_conflicts_csv(ctx)
    typer.echo(f"{len(rows)} operation(s) excluded from batches; full list: {path}")
    for r in rows[:limit]:
        typer.echo(f"{r['plan_status']:8} {r['blocker_code'] or '-':34} {r['source_absolute_path']}")


# --- batches --------------------------------------------------------------------------------------

@batches_app.command("generate")
@guarded
def batches_generate(run: str = RunOpt, config: Optional[Path] = ConfigCheckOpt) -> None:
    """Write the Bash batch scripts.  They are NOT executed."""
    from migrator import batches
    ctx = _open(run, config)
    res = batches.generate_batches(ctx)
    typer.echo(f"{len(res['batches'])} batch(es) for {res['ready_operations']} READY operation(s) in {res['batch_dir']}")
    if res["excluded_operations"]:
        typer.echo("EXCLUDED from batches (no command generated): "
                   + ", ".join(f"{k}={v}" for k, v in sorted(res["excluded_operations"].items())))
    typer.echo("Review the scripts, then execute them yourself. This tool never does.")


@batches_app.command("list")
@guarded
def batches_list(run: str = RunOpt) -> None:
    """List generated batches."""
    from migrator import batches
    ctx = _open(run)
    for b in batches.list_batches(ctx):
        typer.echo(f"plan-{b['revision']:04d} batch {b['batch_number']:>6}  ops={b['operation_count']:<4} "
                   f"{b['script_sha256'].strip()}  {b['script_path']}")


@batches_app.command("verify")
@guarded
def batches_verify(run: str = RunOpt) -> None:
    """Recompute script/plan/config hashes and compare with PostgreSQL."""
    from migrator import batches
    ctx = _open(run)
    problems = batches.verify_batches(ctx)
    if problems:
        for p in problems:
            typer.echo(f"PROBLEM: {p}", err=True)
        raise typer.Exit(1)
    typer.echo("all batch artifacts verified")


# --- audit ------------------------------------------------------------------------------------------

def _dsn_for_run_dir(run_dir: Path, no_db: bool) -> str | None:
    if no_db or os.environ.get("MIGRATOR_AUDIT_NO_DB") == "1":
        return None
    env_name = "MIGRATOR_DATABASE_URL"
    snap = run_dir / "config.snapshot.yaml"
    try:
        import yaml
        env_name = yaml.safe_load(snap.read_text())["database"]["dsn_env"]
    except Exception:
        pass
    return os.environ.get(env_name) or None


@audit_app.command("emit")
def audit_emit(run: str = RunOpt,
               trace: str = typer.Option(..., "--trace"),
               event: str = typer.Option(..., "--event"),
               operation: Optional[str] = typer.Option(None, "--operation"),
               file: Optional[str] = typer.Option(None, "--file"),
               batch: Optional[str] = typer.Option(None, "--batch"),
               actor: str = typer.Option("bash", "--actor"),
               run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
               expect_sequence: Optional[int] = typer.Option(None, "--expect-sequence"),
               expect_hash: Optional[str] = typer.Option(None, "--expect-hash"),
               kv: list[str] = typer.Option([], "--kv", help="key=value payload entries (repeatable)"),
               payload_json: Optional[str] = typer.Option(None, "--payload-json"),
               no_db: bool = typer.Option(False, "--no-db", help="Spool only; synchronize later.")) -> None:
    """Record one audit event (spool first, then PostgreSQL).  Never touches migration files."""
    from migrator import audit as A
    try:
        payload: dict[str, Any] = json.loads(payload_json) if payload_json else {}
        for item in kv:
            k, sep, v = item.partition("=")
            if not sep:
                raise A.AuditError(f"--kv expects key=value, got {item!r}")
            payload[k] = v
        if run_dir is None:
            from migrator import db
            with db.connect(dsn_env=_STATE["dsn_env"]) as c:
                run_dir = Path(db.get_run(c, run)["workspace_path"]) / "runs" / run
        spool = A.Spool(run_dir / "audit-spool")
        res = A.emit_event(spool, run_id=run, trace_id=trace, event_type=event, actor=actor, payload=payload,
                           file_id=file, operation_id=operation, batch_id=batch,
                           expect_sequence=expect_sequence, expect_hash=expect_hash,
                           dsn=_dsn_for_run_dir(run_dir, no_db))
    except A.StaleChainError as exc:
        typer.echo(f"audit emit: {exc}", err=True)
        raise typer.Exit(3)
    except (A.AuditError, ValueError, OSError) as exc:
        typer.echo(f"audit emit failed: {exc}", err=True)
        raise typer.Exit(4)
    if os.environ.get("MIGRATOR_AUDIT_VERBOSE") == "1":
        typer.echo(f"{res.event.sequence_no} {res.event.event_hash} db_synced={res.db_synced}")


@audit_app.command("sync")
@guarded
def audit_sync(run: str = RunOpt) -> None:
    """Import spooled events into PostgreSQL (idempotent; verifies chains)."""
    from migrator import audit as A
    from migrator import constants as C
    from migrator import db
    ctx = _open(run)
    rep = A.sync_spool(ctx.conn, ctx.run_id, ctx.spool)
    if rep.bash_events_imported and ctx.refresh()["state"] == C.BATCHES_GENERATED:
        with ctx.conn.transaction():
            db.transition(ctx.conn, ctx.run_id, C.EXTERNAL_EXECUTION_OBSERVED, "audit sync imported Bash events")
    typer.echo(f"traces={rep.traces} imported={rep.imported} already_present={rep.already_present} "
               f"problems={len(rep.problems)}")
    for p in rep.problems:
        typer.echo(f"PROBLEM: {p}", err=True)
    if rep.problems:
        raise typer.Exit(1)


@audit_app.command("status")
@guarded
def audit_status(run: str = RunOpt) -> None:
    """Spool and database audit status."""
    ctx = _open(run)
    n = ctx.conn.execute("SELECT count(*) AS n, count(DISTINCT trace_id) AS t FROM audit_event WHERE run_id = %s",
                         (ctx.run_id,)).fetchone()
    by_src = {r["source"]: r["n"] for r in ctx.conn.execute(
        "SELECT source, count(*) AS n FROM audit_event WHERE run_id = %s GROUP BY 1", (ctx.run_id,))}
    _echo_json({"database": {"events": n["n"], "traces": n["t"], "by_source": by_src},
                "spool": ctx.spool.counts()})


@audit_app.command("verify-chain")
@guarded
def audit_verify_chain(run: str = RunOpt) -> None:
    """Recompute every trace's hash chain; report gaps and mutations."""
    from migrator import audit as A
    ctx = _open(run)
    rep = A.verify_run_chain(ctx.conn, ctx.run_id)
    typer.echo(f"traces checked: {rep.traces_checked}  events checked: {rep.events_checked}  "
               f"problems: {len(rep.problems)}")
    for p in rep.problems[:200]:
        typer.echo(f"PROBLEM: {p}", err=True)
    if rep.problems:
        raise typer.Exit(1)
    typer.echo("audit chains verified")


# --- reconcile / prepare ------------------------------------------------------------------------------

@app.command("reconcile")
@guarded
def reconcile_cmd(run: str = RunOpt, config: Optional[Path] = ConfigCheckOpt) -> None:
    """Compare the filesystem with the plan using SHA-256 (read-only)."""
    from migrator import reconcile
    ctx = _open(run, config)
    _echo_json(reconcile.reconcile(ctx))


@app.command("prepare")
@guarded
def prepare_cmd(config: Path = typer.Option(..., "--config", exists=True, dir_okay=False)) -> None:
    """create run + inventory + classify + plan + generate batches.  Never executes them."""
    from migrator import batches, classifier, db, inventory, planner, reports
    from migrator.config import load_config
    from migrator.runs import create_run
    cfg, _ = load_config(config)
    conn = db.connect(dsn_env=cfg["database"]["dsn_env"])
    ctx = create_run(conn, config)
    inventory.run_inventory(ctx)
    client = make_jev_client(ctx.cfg)
    try:
        classifier.run_classification(ctx, client)
    finally:
        close = getattr(client, "close", None)
        if close:
            close()
    planner.create_plan(ctx)
    gen = batches.generate_batches(ctx)
    reports.write_conflicts_csv(ctx)
    s = reports.write_summary(ctx)
    src, cl = s["source_inventory"], s["classification"]
    typer.echo(f"Run ID:                     {ctx.run_id}")
    typer.echo(f"Files discovered:           {src['regular_files']}")
    typer.echo(f"Files hashed:               {src['hashed']}")
    typer.echo(f"Files routed automatically: {cl['auto_routed_files']}")
    typer.echo(f"Files awaiting review:      {cl['review_files']}")
    typer.echo(f"Files blocked:              {cl['blocked_files']}")
    typer.echo(f"Operations ready:           {s['plan']['ready_operations']}")
    typer.echo(f"Generated batches:          {len(gen['batches'])}")
    typer.echo(f"Batch directory:            {gen['batch_dir']}")
    typer.echo("Nothing was executed. Review the scripts and run them yourself.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
