"""PostgreSQL access (psycopg 3, explicit SQL) and run lifecycle helpers."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from migrator import constants as C
from migrator.paths import utc_now

DEFAULT_DSN_ENV = "MIGRATOR_DATABASE_URL"
_ADVISORY_LOCK_KEY = 0x6D69677261746F72  # "migrator"


class DatabaseError(RuntimeError):
    pass


class InvalidTransition(DatabaseError):
    pass


def get_dsn(dsn_env: str = DEFAULT_DSN_ENV) -> str:
    dsn = os.environ.get(dsn_env)
    if not dsn:
        raise DatabaseError(f"environment variable {dsn_env} is not set")
    return dsn


def connect(dsn: str | None = None, *, dsn_env: str = DEFAULT_DSN_ENV,
            connect_timeout: int | None = None, autocommit: bool = True) -> psycopg.Connection:
    kwargs: dict[str, Any] = {"row_factory": dict_row, "autocommit": autocommit}
    if connect_timeout is not None:
        kwargs["connect_timeout"] = connect_timeout
    return psycopg.connect(dsn or get_dsn(dsn_env), **kwargs)


def sql_dir() -> Path:
    env = os.environ.get("MIGRATOR_SQL_DIR")
    candidates = [Path(env)] if env else []
    candidates.append(Path(__file__).resolve().parents[2] / "sql")
    for c in candidates:
        if c.is_dir():
            return c
    raise DatabaseError("cannot locate the sql/ directory; set MIGRATOR_SQL_DIR")


def _migration_files() -> list[Path]:
    return sorted(p for p in sql_dir().glob("[0-9][0-9][0-9]_*.sql"))


def migrate(conn: psycopg.Connection) -> list[str]:
    """Apply pending SQL migrations; refuse if an applied one was edited."""
    applied: list[str] = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))
        conn.execute("""CREATE TABLE IF NOT EXISTS schema_migration (
            version TEXT PRIMARY KEY, sha256 CHAR(64) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        done = {r["version"]: r["sha256"] for r in
                conn.execute("SELECT version, sha256 FROM schema_migration")}
        for path in _migration_files():
            text = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(text.encode()).hexdigest()
            if path.name in done:
                if done[path.name] != digest:
                    raise DatabaseError(f"applied migration {path.name} was modified on disk")
                continue
            conn.execute(text)
            conn.execute("INSERT INTO schema_migration(version, sha256) VALUES (%s, %s)",
                         (path.name, digest))
            applied.append(path.name)
    return applied


def migration_status(conn: psycopg.Connection) -> dict[str, list[str]]:
    exists = conn.execute("SELECT to_regclass('schema_migration') AS t").fetchone()["t"]
    done: set[str] = set()
    if exists:
        done = {r["version"] for r in conn.execute("SELECT version FROM schema_migration")}
    files = [p.name for p in _migration_files()]
    return {"applied": [f for f in files if f in done],
            "pending": [f for f in files if f not in done],
            "unknown": sorted(done - set(files))}


# --- run lifecycle ------------------------------------------------------------

def new_id() -> uuid.UUID:
    return uuid.uuid4()


def get_run(conn: psycopg.Connection, run_id: uuid.UUID | str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM migration_run WHERE run_id = %s", (str(run_id),)).fetchone()
    if row is None:
        raise DatabaseError(f"run {run_id} not found")
    return row


def transition(conn: psycopg.Connection, run_id: uuid.UUID | str, to_state: str,
               note: str | None = None) -> str:
    """Move the run to `to_state`, enforcing the state machine.  Returns old state."""
    row = conn.execute("SELECT state FROM migration_run WHERE run_id = %s FOR UPDATE",
                       (str(run_id),)).fetchone()
    if row is None:
        raise DatabaseError(f"run {run_id} not found")
    cur = row["state"]
    if to_state not in C.ALLOWED_TRANSITIONS.get(cur, frozenset()):
        raise InvalidTransition(f"run {run_id}: {cur} -> {to_state} is not allowed")
    conn.execute("UPDATE migration_run SET state = %s, updated_at = now() WHERE run_id = %s",
                 (to_state, str(run_id)))
    conn.execute("INSERT INTO run_state_history(run_id, from_state, to_state, note) "
                 "VALUES (%s, %s, %s, %s)", (str(run_id), cur, to_state, note))
    return cur


def require_state(run: dict[str, Any], *allowed: str) -> None:
    if run["state"] not in allowed:
        raise InvalidTransition(
            f"run {run['run_id']} is in state {run['state']}; this command needs one of: "
            + ", ".join(allowed))


def jsonb(obj: Any) -> Jsonb:
    return Jsonb(obj)


def now():
    return utc_now()
