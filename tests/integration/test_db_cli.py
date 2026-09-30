import uuid

import psycopg
import pytest
from typer.testing import CliRunner

from migrator import db
from migrator.cli import app

pytestmark = pytest.mark.postgres


@pytest.fixture()
def empty_db(pg_admin_dsn):
    name = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(pg_admin_dsn, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    yield psycopg.conninfo.make_conninfo(pg_admin_dsn, dbname=name)
    with psycopg.connect(pg_admin_dsn, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def test_db_migrate_and_status(empty_db, monkeypatch):
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", empty_db)
    r = CliRunner()
    st = r.invoke(app, ["db", "status"])
    assert st.exit_code == 0 and '"pending": [\n    "001_initial.sql"' in st.output
    m = r.invoke(app, ["db", "migrate"])
    assert m.exit_code == 0 and "001_initial.sql" in m.output
    again = r.invoke(app, ["db", "migrate"])
    assert "up to date" in again.output
    st = r.invoke(app, ["db", "status"])
    assert '"pending": []' in st.output and "001_initial.sql" in st.output


def test_missing_dsn_is_a_clean_error(monkeypatch):
    monkeypatch.delenv("MIGRATOR_DATABASE_URL", raising=False)
    r = CliRunner().invoke(app, ["db", "status"])
    assert r.exit_code == 1 and "MIGRATOR_DATABASE_URL is not set" in r.output


def test_edited_applied_migration_is_refused(empty_db, tmp_path, monkeypatch):
    import shutil
    from pathlib import Path
    sql = tmp_path / "sql"
    shutil.copytree(Path(db.sql_dir()), sql)
    monkeypatch.setenv("MIGRATOR_SQL_DIR", str(sql))
    with db.connect(empty_db) as c:
        db.migrate(c)
        (sql / "001_initial.sql").write_text((sql / "001_initial.sql").read_text() + "\n-- edited\n")
        with pytest.raises(db.DatabaseError, match="modified on disk"):
            db.migrate(c)
        (sql / "001_initial.sql").write_text((sql / "001_initial.sql").read_text().replace("\n-- edited\n", ""))
        (sql / "002_more.sql").write_text("CREATE TABLE extra_t (x int);")
        assert db.migrate(c) == ["002_more.sql"]


def test_state_machine_rejects_illegal_transitions(empty_db, tmp_path):
    from migrator import constants as C
    assert "EXECUTING" not in C.RUN_STATES                      # there is no application-side execution phase
    for frm, tos in C.ALLOWED_TRANSITIONS.items():
        assert all(t in C.RUN_STATES for t in tos) and frm in C.RUN_STATES
    assert C.RECONCILED not in C.ALLOWED_TRANSITIONS[C.CREATED]


def test_commands_refuse_to_run_out_of_order(bare_env):
    from migrator import batches, classifier, inventory, planner, reconcile
    from migrator.db import InvalidTransition
    from tests.fake_jev import FakeJev
    ctx = bare_env.new_run()
    for fn in (lambda: classifier.run_classification(ctx, FakeJev(lambda s, q: ("MOVIES", 0.99))),
               lambda: planner.create_plan(ctx), lambda: batches.generate_batches(ctx),
               lambda: reconcile.reconcile(ctx)):
        with pytest.raises(InvalidTransition):
            fn()                                            # inventory has not completed yet
    inventory.run_inventory(ctx)
    with pytest.raises(InvalidTransition):
        planner.create_plan(ctx)                            # not classified yet
    hist = [r["to_state"] for r in ctx.conn.execute(
        "SELECT to_state FROM run_state_history WHERE run_id=%s ORDER BY id", (ctx.run_id,))]
    assert hist == ["CREATED", "DISCOVERING", "DISCOVERY_COMPLETE", "HASHING", "INVENTORY_COMPLETE"]
