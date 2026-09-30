"""Run creation, config snapshotting and run-directory layout."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

import psycopg

from migrator import audit as A
from migrator import constants as C
from migrator import db
from migrator.config import Config, ConfigError, load_config, parse_config_text
from migrator.paths import WorkspaceGuard, sha256_hex, write_new_file


class RunError(RuntimeError):
    pass


@dataclass
class RunContext:
    conn: psycopg.Connection
    run: dict
    cfg: Config
    run_dir: Path
    guard: WorkspaceGuard

    @property
    def run_id(self) -> str:
        return str(self.run["run_id"])

    @property
    def spool(self) -> A.Spool:
        return A.Spool(self.run_dir / "audit-spool")

    def path(self, *parts: str) -> Path:
        p = self.run_dir.joinpath(*parts)
        self.guard.check(p)
        return p

    def refresh(self) -> dict:
        self.run = db.get_run(self.conn, self.run_id)
        return self.run


def run_dir_for(workspace: str, run_id: str | uuid.UUID) -> Path:
    return Path(workspace) / "runs" / str(run_id)


def make_guard(cfg: Config) -> WorkspaceGuard:
    return WorkspaceGuard(cfg.workspace, cfg.migration_roots)


def create_run(conn: psycopg.Connection, config_path: str | os.PathLike) -> RunContext:
    cfg, raw = load_config(config_path)
    run_id = uuid.uuid4()
    trace_id = uuid.uuid4()
    run_dir = run_dir_for(cfg.workspace, run_id)
    guard = make_guard(cfg)
    cfg_hash = cfg.sha256()
    with conn.transaction():
        conn.execute(
            """INSERT INTO migration_run (run_id, name, state, config_json, config_sha256,
                   requested_jev_model, workspace_path, run_trace_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (str(run_id), cfg.name, C.CREATED, db.jsonb(cfg.data), cfg_hash, cfg.model,
             cfg.workspace, str(trace_id)))
        conn.execute("INSERT INTO run_state_history(run_id, from_state, to_state) VALUES (%s,NULL,%s)",
                     (str(run_id), C.CREATED))
        for s in cfg.sources:
            conn.execute("""INSERT INTO scan_root (scan_root_id, run_id, root_type, config_id,
                            absolute_path, cross_mounts) VALUES (%s,%s,'SOURCE',%s,%s,%s)""",
                         (str(uuid.uuid4()), str(run_id), s.id, s.path, s.cross_mounts))
        for t in cfg.targets:
            conn.execute("""INSERT INTO scan_root (scan_root_id, run_id, root_type, config_id,
                            absolute_path, cross_mounts) VALUES (%s,%s,'TARGET',%s,%s,%s)""",
                         (str(uuid.uuid4()), str(run_id), t.id, t.path, t.cross_mounts))
        write_new_file(run_dir / "config.snapshot.yaml", raw, guard=guard)
        write_new_file(run_dir / "config.sha256", (cfg_hash + "\n").encode(), guard=guard)
        A.append_event(conn, run_id, A.EventSpec(
            trace_id, "RUN_CREATED", "migrator", C.SRC_PYTHON,
            {"config_sha256": cfg_hash, "requested_model": cfg.model, "name": cfg.name}))
    return open_run(conn, run_id)


def open_run(conn: psycopg.Connection, run_id: str | uuid.UUID,
             config_path: str | os.PathLike | None = None) -> RunContext:
    """Load a run and verify its configuration snapshot is intact.

    If `config_path` is given and its normalized hash differs from the run's,
    the command is refused: changed configuration requires a new run.
    """
    run = db.get_run(conn, run_id)
    cfg = Config(run["config_json"])
    if cfg.sha256() != run["config_sha256"].strip():
        raise RunError("stored configuration does not match its recorded SHA-256")
    run_dir = run_dir_for(run["workspace_path"], run["run_id"])
    snap = run_dir / "config.sha256"
    if snap.exists() and snap.read_text().strip() != run["config_sha256"].strip():
        raise RunError(f"{snap} does not match the run's config SHA-256")
    if config_path is not None:
        try:
            other, _ = load_config(config_path)
        except ConfigError:
            raise
        if other.sha256() != run["config_sha256"].strip():
            raise RunError("the given configuration differs from this run's snapshot; "
                           "create a new run instead of continuing with changed configuration")
    return RunContext(conn, run, cfg, run_dir, make_guard(cfg))
