import re

from typer.testing import CliRunner

from migrator.cli import app

runner = CliRunner()


def all_commands(group, prefix=""):
    out = []
    for c in group.registered_commands:
        out.append(prefix + (c.name or c.callback.__name__.replace("_cmd", "").replace("_", "-")))
    for g in group.registered_groups:
        out += all_commands(g.typer_instance, prefix + g.name + " ")
    return out


def test_there_is_no_execute_move_or_copy_command():
    cmds = all_commands(app)
    for forbidden in ("execute", "move", "copy", "run-batch", "apply", "migrate-files"):
        assert not [c for c in cmds if c.split()[-1] == forbidden or c == forbidden], cmds
    # `db migrate` only touches the database schema
    assert "db migrate" in cmds


def test_required_commands_exist():
    cmds = set(all_commands(app))
    required = {"db migrate", "db status", "run create", "run status", "run summary", "inventory", "classify",
                "review list", "review export", "review import", "review set", "review set-directory",
                "plan create", "plan show", "plan conflicts", "batches generate", "batches list",
                "batches verify", "audit emit", "audit sync", "audit status", "audit verify-chain",
                "reconcile", "prepare"}
    assert required <= cmds, required - cmds


def test_help_mentions_no_execution():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0 and "Never moves files" in r.output
    assert not re.search(r"\bexecute\b\s{2,}", r.output)


def test_run_create_rejects_invalid_config(tmp_path, monkeypatch):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nmigration: {name: x}\nworkspace: {path: relative}\nscope: {sources: [], targets: []}\n")
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", "host=127.0.0.1 port=1 dbname=x connect_timeout=1")
    r = runner.invoke(app, ["run", "create", "--config", str(bad)])
    assert r.exit_code == 1
    assert "workspace.path must be an absolute path" in r.output
