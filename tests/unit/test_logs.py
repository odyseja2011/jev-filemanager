import json
import logging

from migrator.logs import JsonFormatter, get_logger, redact


def test_redacts_secrets_from_env_and_dsn(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-supersecret-123")
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", "postgresql://user:hunter2@db/x")
    text = redact("key sk-or-supersecret-123 dsn postgresql://user:hunter2@db/x other postgresql://a:pw9@h/d")
    assert "sk-or-supersecret-123" not in text and "hunter2" not in text and "pw9" not in text


def test_structured_fields_and_full_paths_allowed():
    rec = logging.LogRecord("migrator.inventory", logging.INFO, "f", 1, "scanned %s", ("/mnt/data/MEDIA/a b",), None)
    rec.run_id, rec.trace_id, rec.operation_id = "R", "T", "O"
    d = json.loads(JsonFormatter().format(rec))
    assert d["level"] == "INFO" and d["component"] == "inventory" and d["message"] == "scanned /mnt/data/MEDIA/a b"
    assert (d["run_id"], d["trace_id"], d["operation_id"]) == ("R", "T", "O")
    assert "timestamp" in d


def test_adapter_carries_context():
    log = get_logger("x", run_id="R1")
    assert log.extra["run_id"] == "R1"
