import dataclasses
import uuid

from migrator import constants as C
from migrator.audit import (AuditEvent, EventSpec, Spool, build_event, emit_event, recompute_hash,
                            verify_trace_events)

RUN = str(uuid.uuid4())


def chain(n, trace=None):
    trace = trace or uuid.uuid4()
    events, prev = [], C.ZERO_HASH
    for i in range(1, n + 1):
        ev = build_event(RUN, EventSpec(trace, f"E{i}", "t", C.SRC_PYTHON, {"i": i}), i, prev)
        events.append(ev)
        prev = ev.event_hash
    return events


def test_valid_chain_verifies():
    assert verify_trace_events("t", chain(5)) == []


def test_hash_covers_all_required_fields():
    ev = chain(1)[0]
    for field, value in [("event_id", str(uuid.uuid4())), ("run_id", str(uuid.uuid4())),
                         ("trace_id", str(uuid.uuid4())), ("sequence_no", 9), ("event_type", "X"),
                         ("actor", "someone"), ("event_time", "2000-01-01T00:00:00.000000Z"),
                         ("payload", {"i": 2})]:
        mutated = dataclasses.replace(ev, **{field: value})
        assert recompute_hash(mutated) != ev.event_hash, field


def test_tampered_event_detected():
    evs = chain(4)
    evs[1] = dataclasses.replace(evs[1], payload={"i": 999})
    kinds = {p.kind for p in verify_trace_events("t", evs)}
    assert "MUTATED_EVENT" in kinds


def test_missing_event_detected():
    evs = chain(5)
    del evs[2]
    kinds = {p.kind for p in verify_trace_events("t", evs)}
    assert "GAP" in kinds and "BROKEN_LINK" in kinds


def test_reordered_or_duplicated_event_detected():
    evs = chain(3)
    kinds = {p.kind for p in verify_trace_events("t", [evs[0], evs[1], evs[1], evs[2]])}
    assert "DUPLICATE_OR_REORDERED" in kinds or "BROKEN_LINK" in kinds


def test_chain_must_start_at_one_from_zero_hash():
    evs = chain(3)
    assert verify_trace_events("t", evs[1:])   # starts at 2 -> gap


def test_event_time_and_payload_are_deterministic_json():
    a = build_event(RUN, EventSpec(uuid.UUID(int=1), "E", "t", C.SRC_PYTHON, {"b": 1, "a": 2}), 1,
                    C.ZERO_HASH, event_id=uuid.UUID(int=5))
    b = build_event(RUN, EventSpec(uuid.UUID(int=1), "E", "t", C.SRC_PYTHON, {"a": 2, "b": 1}), 1,
                    C.ZERO_HASH, event_time=None, event_id=uuid.UUID(int=5))
    assert recompute_hash(a) == a.event_hash
    assert a.payload == b.payload


def test_spool_emit_chains_locally_without_database(tmp_path):
    spool = Spool(tmp_path / "spool")
    trace = str(uuid.uuid4())
    head = (7, "a" * 64)
    e1 = emit_event(spool, run_id=RUN, trace_id=trace, event_type="COPY_STARTED", actor="bash",
                    expect_sequence=head[0], expect_hash=head[1], dsn=None).event
    e2 = emit_event(spool, run_id=RUN, trace_id=trace, event_type="COPY_FINISHED", actor="bash",
                    expect_sequence=head[0], expect_hash=head[1], dsn=None).event
    assert (e1.sequence_no, e1.previous_event_hash) == (8, "a" * 64)
    assert (e2.sequence_no, e2.previous_event_hash) == (9, e1.event_hash)
    files = spool.event_files(trace)
    assert len(files) == 2 and all(f.exists() for f in files)
    loaded = [Spool.load(f) for f in files]
    assert verify_trace_events(trace, loaded, 8, "a" * 64) == []


def test_emit_rejects_unknown_bash_event_and_missing_head(tmp_path):
    import pytest
    from migrator.audit import AuditError
    spool = Spool(tmp_path / "spool")
    with pytest.raises(AuditError):
        emit_event(spool, run_id=RUN, trace_id=str(uuid.uuid4()), event_type="ROUTE_ASSIGNED", actor="x",
                   expect_sequence=1, expect_hash="a" * 64)
    with pytest.raises(AuditError):
        emit_event(spool, run_id=RUN, trace_id=str(uuid.uuid4()), event_type="COPY_STARTED", actor="x")
    assert spool.traces() == [] or all(not spool.event_files(t) for t in spool.traces())


def test_unreachable_postgres_does_not_lose_event(tmp_path):
    spool = Spool(tmp_path / "spool")
    trace = str(uuid.uuid4())
    res = emit_event(spool, run_id=RUN, trace_id=trace, event_type="COPY_STARTED", actor="bash",
                     expect_sequence=1, expect_hash="b" * 64,
                     dsn="host=127.0.0.1 port=1 dbname=nope connect_timeout=1")
    assert res.db_synced is False
    assert len(spool.event_files(trace)) == 1
    assert spool.counts()["pending"] == 1


def test_audit_server_protocol_spools_before_replying_ok(tmp_path):
    from migrator.audit import AuditServer
    spool = Spool(tmp_path / "spool")
    srv = AuditServer(spool, dsn=None)
    trace, op = str(uuid.uuid4()), str(uuid.uuid4())
    assert srv.handle(["PING"]) == "OK"
    rec = [RUN, trace, str(uuid.uuid4()), op, str(uuid.uuid4()), "3", "c" * 64, "actor", "COPY_STARTED", "temp=/x y", "n=1"]
    assert srv.handle(rec) == "OK"
    files = spool.event_files(trace)                     # durable by the time OK was returned
    assert len(files) == 1
    ev = Spool.load(files[0])
    assert (ev.sequence_no, ev.previous_event_hash, ev.payload) == (4, "c" * 64, {"temp": "/x y", "n": "1"})
    assert srv.handle(rec)[:2] == "OK" and len(spool.event_files(trace)) == 2      # chains on locally
    assert srv.handle(rec[:5]).startswith("ERR")
    bad = list(rec)
    bad[8] = "ROUTE_ASSIGNED"
    assert srv.handle(bad).startswith("ERR")


def test_audit_server_over_a_real_pipe(tmp_path):
    import os
    import threading
    from migrator.audit import AuditServer
    spool = Spool(tmp_path / "spool")
    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    t = threading.Thread(target=lambda: AuditServer(spool, None).serve(r1, w2), daemon=True)
    t.start()
    trace = str(uuid.uuid4())
    fields = [RUN, trace, "-", "-", "-", "1", "d" * 64, "a", "COPY_STARTED", "k=multi\nline value"]
    os.write(w1, b"".join(f.encode() + b"\0" for f in fields) + b"\0")
    assert os.read(r2, 100) == b"OK\n"
    os.close(w1)
    t.join(5)
    assert Spool.load(spool.event_files(trace)[0]).payload == {"k": "multi\nline value"}
