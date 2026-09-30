"""Shared fixtures.  PostgreSQL comes from MIGRATOR_TEST_DATABASE_URL (an admin DSN
that may create databases) or from a throw-away local cluster started here."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

PG_BIN_CANDIDATES = sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)


def _pg_bin(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for d in PG_BIN_CANDIDATES:
        if (d / name).exists():
            return str(d / name)
    return None


@pytest.fixture(scope="session")
def pg_admin_dsn():
    env = os.environ.get("MIGRATOR_TEST_DATABASE_URL")
    if env:
        yield env
        return
    initdb, pg_ctl = _pg_bin("initdb"), _pg_bin("pg_ctl")
    if not initdb or not pg_ctl:
        pytest.skip("no PostgreSQL available (set MIGRATOR_TEST_DATABASE_URL)")
    root = Path(tempfile.mkdtemp(prefix="migrator-pg-"))
    prefix: list[str] = []
    if os.geteuid() == 0:
        import pwd
        try:
            pwd.getpwnam("postgres")
        except KeyError:
            pytest.skip("running as root and no 'postgres' user to run the test cluster")
        os.chmod(root, 0o755)
        shutil.chown(root, "postgres")
        prefix = ["runuser", "-u", "postgres", "--"]
    data, sock = root / "data", root / "sock"
    sock.mkdir()
    if prefix:
        shutil.chown(sock, "postgres")
    subprocess.run([*prefix, initdb, "-D", str(data), "-A", "trust", "-E", "UTF8"],
                   check=True, capture_output=True)
    port = 54000 + os.getpid() % 1000
    opts = f"-p {port} -k {sock} -c listen_addresses='' -c fsync=off -c synchronous_commit=off"
    subprocess.run([*prefix, pg_ctl, "-D", str(data), "-o", opts, "-w", "-l", str(root / "log"), "start"],
                   check=True, capture_output=True)
    try:
        yield f"host={sock} port={port} dbname=postgres user=postgres"
    finally:
        subprocess.run([*prefix, pg_ctl, "-D", str(data), "-m", "immediate", "stop"],
                       capture_output=True)
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def pg_dsn(pg_admin_dsn):
    """A fresh migrated database per test."""
    import psycopg
    name = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(pg_admin_dsn, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    conninfo = psycopg.conninfo.make_conninfo(pg_admin_dsn, dbname=name)
    from migrator import db
    with db.connect(conninfo) as conn:
        db.migrate(conn)
        conn.commit()
    yield conninfo
    with psycopg.connect(pg_admin_dsn, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture()
def conn(pg_dsn):
    from migrator import db
    c = db.connect(pg_dsn)
    yield c
    c.close()
