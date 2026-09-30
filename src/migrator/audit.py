"""Append-only, per-trace hash-chained audit events.

* PostgreSQL is authoritative (`audit_event`, `trace_head`).
* Events emitted by generated Bash go through a durable local spool first
  (one immutable, fsynced file per event) and are synchronized afterwards.
* The audit code never touches migration source/target paths.
"""

from __future__ import annotations

import fcntl
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import psycopg
import psycopg.rows
from psycopg.types.json import Jsonb

from migrator import constants as C
from migrator.paths import (canonical_json, format_time, fsync_dir, parse_time,
                            sha256_hex, utc_now)


class AuditError(RuntimeError):
    pass


class StaleChainError(AuditError):
    """The expected previous hash does not match the known trace head."""


@dataclass(frozen=True)
class EventSpec:
    trace_id: uuid.UUID
    event_type: str
    actor: str
    source: str
    payload: dict[str, Any] = field(default_factory=dict)
    file_id: uuid.UUID | None = None
    operation_id: uuid.UUID | None = None
    batch_id: uuid.UUID | None = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    run_id: str
    trace_id: str
    file_id: str | None
    operation_id: str | None
    batch_id: str | None
    sequence_no: int
    event_type: str
    actor: str
    event_time: str          # canonical UTC string
    payload: dict[str, Any]
    previous_event_hash: str
    event_hash: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditEvent":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__})


def canonical_event(*, event_id, run_id, trace_id, file_id, operation_id, batch_id,
                    sequence_no, event_type, actor, event_time, payload, source) -> str:
    """Deterministic representation hashed into the chain."""
    return canonical_json({
        "event_id": str(event_id), "run_id": str(run_id), "trace_id": str(trace_id),
        "file_id": None if file_id is None else str(file_id),
        "operation_id": None if operation_id is None else str(operation_id),
        "batch_id": None if batch_id is None else str(batch_id),
        "sequence_no": int(sequence_no), "event_type": event_type, "actor": actor,
        "event_time": event_time, "payload": payload, "source": source,
    })


def compute_event_hash(previous_hash: str, canonical: str) -> str:
    return sha256_hex(previous_hash + canonical)


def build_event(run_id, spec: EventSpec, sequence_no: int, previous_hash: str,
                event_time: datetime | None = None, event_id: uuid.UUID | None = None) -> AuditEvent:
    eid = str(event_id or uuid.uuid4())
    t = format_time(event_time or utc_now())
    fields = dict(
        event_id=eid, run_id=str(run_id), trace_id=str(spec.trace_id),
        file_id=None if spec.file_id is None else str(spec.file_id),
        operation_id=None if spec.operation_id is None else str(spec.operation_id),
        batch_id=None if spec.batch_id is None else str(spec.batch_id),
        sequence_no=sequence_no, event_type=spec.event_type, actor=spec.actor,
        event_time=t, payload=spec.payload, source=spec.source)
    h = compute_event_hash(previous_hash, canonical_event(**fields))
    return AuditEvent(previous_event_hash=previous_hash, event_hash=h, **fields)


def recompute_hash(ev: AuditEvent) -> str:
    d = ev.to_dict()
    for k in ("previous_event_hash", "event_hash"):
        d.pop(k)
    return compute_event_hash(ev.previous_event_hash, canonical_event(**d))


# --- PostgreSQL ---------------------------------------------------------------

_INSERT_EVENT = """INSERT INTO audit_event (event_id, run_id, trace_id, file_id, operation_id,
    batch_id, sequence_no, event_type, actor, event_time, payload, previous_event_hash,
    event_hash, source) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
_UPSERT_HEAD = """INSERT INTO trace_head (trace_id, sequence_no, event_hash, updated_at)
    VALUES (%s, %s, %s, now())
    ON CONFLICT (trace_id) DO UPDATE SET sequence_no = EXCLUDED.sequence_no,
        event_hash = EXCLUDED.event_hash, updated_at = now()
    WHERE trace_head.sequence_no < EXCLUDED.sequence_no"""


def _event_row(ev: AuditEvent) -> tuple:
    return (ev.event_id, ev.run_id, ev.trace_id, ev.file_id, ev.operation_id, ev.batch_id,
            ev.sequence_no, ev.event_type, ev.actor, parse_time(ev.event_time),
            Jsonb(ev.payload), ev.previous_event_hash, ev.event_hash, ev.source)


def append_events(conn: psycopg.Connection, run_id: uuid.UUID | str,
                  specs: Sequence[EventSpec]) -> list[AuditEvent]:
    """Append events to their traces inside the caller's transaction.

    Trace heads are locked (`FOR UPDATE`, in trace-id order to avoid deadlocks)
    and updated in the same transaction as the inserted events.
    """
    if not specs:
        return []
    trace_ids = sorted({str(s.trace_id) for s in specs})
    heads: dict[str, tuple[int, str]] = {}
    for row in conn.execute("SELECT trace_id, sequence_no, event_hash FROM trace_head "
                            "WHERE trace_id = ANY(%s::uuid[]) ORDER BY trace_id FOR UPDATE",
                            (trace_ids,)):
        heads[str(row["trace_id"])] = (row["sequence_no"], row["event_hash"])
    out: list[AuditEvent] = []
    for spec in specs:
        t = str(spec.trace_id)
        seq, prev = heads.get(t, (0, C.ZERO_HASH))
        ev = build_event(run_id, spec, seq + 1, prev)
        heads[t] = (ev.sequence_no, ev.event_hash)
        out.append(ev)
    with conn.cursor() as cur:
        cur.executemany(_INSERT_EVENT, [_event_row(e) for e in out])
        last: dict[str, AuditEvent] = {}
        for e in out:
            last[e.trace_id] = e
        cur.executemany(_UPSERT_HEAD, [(e.trace_id, e.sequence_no, e.event_hash)
                                       for e in last.values()])
    return out


def append_event(conn: psycopg.Connection, run_id, spec: EventSpec) -> AuditEvent:
    return append_events(conn, run_id, [spec])[0]


def get_head(conn: psycopg.Connection, trace_id: str | uuid.UUID) -> tuple[int, str]:
    row = conn.execute("SELECT sequence_no, event_hash FROM trace_head WHERE trace_id = %s",
                       (str(trace_id),)).fetchone()
    return (row["sequence_no"], row["event_hash"]) if row else (0, C.ZERO_HASH)


def get_heads(conn: psycopg.Connection, trace_ids: Sequence[str]) -> dict[str, tuple[int, str]]:
    out: dict[str, tuple[int, str]] = {}
    for i in range(0, len(trace_ids), 5000):
        chunk = list(trace_ids[i:i + 5000])
        for row in conn.execute("SELECT trace_id, sequence_no, event_hash FROM trace_head "
                                "WHERE trace_id = ANY(%s::uuid[])", (chunk,)):
            out[str(row["trace_id"])] = (row["sequence_no"], row["event_hash"])
    return out


def push_event(conn: psycopg.Connection, ev: AuditEvent) -> bool:
    """Insert one spooled event iff it directly continues the DB trace head.

    Returns True when the event is (now) present in PostgreSQL.
    """
    with conn.transaction():
        row = conn.execute("SELECT sequence_no, event_hash FROM trace_head "
                           "WHERE trace_id = %s FOR UPDATE", (ev.trace_id,)).fetchone()
        hseq, hhash = (row["sequence_no"], row["event_hash"]) if row else (0, C.ZERO_HASH)
        if ev.sequence_no <= hseq:
            r = conn.execute("SELECT event_id FROM audit_event WHERE trace_id = %s AND sequence_no = %s",
                             (ev.trace_id, ev.sequence_no)).fetchone()
            return bool(r and str(r["event_id"]) == ev.event_id)
        if ev.sequence_no != hseq + 1 or ev.previous_event_hash != hhash:
            return False
        conn.execute(_INSERT_EVENT + " ON CONFLICT (event_id) DO NOTHING", _event_row(ev))
        conn.execute(_UPSERT_HEAD, (ev.trace_id, ev.sequence_no, ev.event_hash))
        return True


# --- chain verification (pure) ----------------------------------------------------

@dataclass
class ChainProblem:
    trace_id: str
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.kind} trace={self.trace_id}: {self.detail}"


def verify_trace_events(trace_id: str, events: Iterable[AuditEvent],
                        start_sequence: int = 1, start_hash: str = C.ZERO_HASH) -> list[ChainProblem]:
    problems: list[ChainProblem] = []
    expect_seq, prev = start_sequence, start_hash
    for ev in events:
        if ev.sequence_no != expect_seq:
            problems.append(ChainProblem(trace_id, "GAP" if ev.sequence_no > expect_seq else "DUPLICATE_OR_REORDERED",
                                         f"expected sequence {expect_seq}, found {ev.sequence_no}"))
            expect_seq = ev.sequence_no
        if ev.previous_event_hash != prev:
            problems.append(ChainProblem(trace_id, "BROKEN_LINK",
                                         f"sequence {ev.sequence_no}: previous hash does not match predecessor"))
        if recompute_hash(ev) != ev.event_hash:
            problems.append(ChainProblem(trace_id, "MUTATED_EVENT",
                                         f"sequence {ev.sequence_no}: stored hash does not match content"))
        prev = ev.event_hash
        expect_seq += 1
    return problems


def _row_to_event(row: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        event_id=str(row["event_id"]), run_id=str(row["run_id"]), trace_id=str(row["trace_id"]),
        file_id=None if row["file_id"] is None else str(row["file_id"]),
        operation_id=None if row["operation_id"] is None else str(row["operation_id"]),
        batch_id=None if row["batch_id"] is None else str(row["batch_id"]),
        sequence_no=row["sequence_no"], event_type=row["event_type"], actor=row["actor"],
        event_time=format_time(row["event_time"]), payload=row["payload"],
        previous_event_hash=row["previous_event_hash"].strip(),
        event_hash=row["event_hash"].strip(), source=row["source"])


@dataclass
class ChainReport:
    traces_checked: int = 0
    events_checked: int = 0
    problems: list[ChainProblem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_run_chain(conn: psycopg.Connection, run_id: uuid.UUID | str) -> ChainReport:
    """Recalculate every trace chain of the run from PostgreSQL."""
    rid = str(run_id)
    report = ChainReport()
    run = conn.execute("SELECT run_trace_id FROM migration_run WHERE run_id = %s", (rid,)).fetchone()
    if run is None:
        raise AuditError(f"run {rid} not found")
    known = {str(r["trace_id"]) for r in conn.execute(
        "SELECT trace_id FROM file_inventory WHERE run_id = %s", (rid,))}
    known.add(str(run["run_trace_id"]))
    heads = {str(r["trace_id"]): (r["sequence_no"], r["event_hash"].strip()) for r in conn.execute(
        "SELECT trace_id, sequence_no, event_hash FROM trace_head WHERE trace_id = ANY(%s::uuid[])",
        (list(known),))}

    seen: set[str] = set()
    cur_trace: str | None = None
    buf: list[AuditEvent] = []

    def flush() -> None:
        nonlocal buf
        if cur_trace is None:
            return
        report.traces_checked += 1
        report.events_checked += len(buf)
        report.problems.extend(verify_trace_events(cur_trace, buf))
        if cur_trace not in known:
            report.problems.append(ChainProblem(cur_trace, "UNKNOWN_TRACE",
                                                "events exist for a trace not in this run's inventory"))
        head = heads.get(cur_trace)
        if buf:
            last = buf[-1]
            if head is None:
                report.problems.append(ChainProblem(cur_trace, "MISSING_HEAD", "no trace_head row"))
            elif head != (last.sequence_no, last.event_hash):
                report.problems.append(ChainProblem(
                    cur_trace, "HEAD_MISMATCH",
                    f"trace_head is at {head[0]} but last event is {last.sequence_no}"))
        buf = []

    with conn.transaction(), conn.cursor(name="verify_chain") as cur:
        cur.itersize = 5000
        cur.execute("SELECT * FROM audit_event WHERE run_id = %s ORDER BY trace_id, sequence_no", (rid,))
        for row in cur:
            ev = _row_to_event(row)
            if ev.trace_id != cur_trace:
                flush()
                cur_trace = ev.trace_id
            seen.add(ev.trace_id)
            buf.append(ev)
        flush()
    for t in sorted(known - seen):
        report.traces_checked += 1
        report.problems.append(ChainProblem(t, "NO_EVENTS", "trace has no audit events"))
    return report


# --- local spool --------------------------------------------------------------------

class Spool:
    """Durable local event spool: `<dir>/<trace_id>/<seq>-<event_id>.json`."""

    def __init__(self, directory: str | os.PathLike):
        self.dir = Path(directory)

    def trace_dir(self, trace_id: str) -> Path:
        return self.dir / str(trace_id)

    def event_files(self, trace_id: str) -> list[Path]:
        d = self.trace_dir(trace_id)
        if not d.is_dir():
            return []
        return sorted(p for p in d.iterdir() if p.name.endswith(".json") and not p.name.startswith("."))

    def traces(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.name for p in self.dir.iterdir() if p.is_dir())

    @staticmethod
    def load(path: Path) -> AuditEvent:
        return AuditEvent.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def head(self, trace_id: str) -> tuple[int, str] | None:
        files = self.event_files(trace_id)
        if not files:
            return None
        ev = self.load(files[-1])
        return ev.sequence_no, ev.event_hash

    def is_synced(self, path: Path) -> bool:
        return path.with_suffix(".synced").exists()

    def mark_synced(self, path: Path) -> None:
        marker = path.with_suffix(".synced")
        if not marker.exists():
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT, 0o644)
            os.close(fd)

    def write(self, ev: AuditEvent) -> Path:
        """Durably persist the event; only returns once file *and* directory are fsynced."""
        d = self.trace_dir(ev.trace_id)
        created = not d.exists()
        d.mkdir(parents=True, exist_ok=True)
        final = d / f"{ev.sequence_no:012d}-{ev.event_id}.json"
        tmp = d / f".{final.name}.{os.getpid()}.tmp"
        data = (json.dumps(ev.to_dict(), sort_keys=True, ensure_ascii=True) + "\n").encode()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.link(tmp, final)   # never overwrites an existing event
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        fsync_dir(d)
        if created:
            fsync_dir(self.dir)
        return final

    def lock(self, trace_id: str):
        d = self.trace_dir(trace_id)
        d.mkdir(parents=True, exist_ok=True)
        fd = os.open(d / ".lock", os.O_WRONLY | os.O_CREAT, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def unlock(self, fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def counts(self) -> dict[str, int]:
        total = synced = 0
        for t in self.traces():
            for p in self.event_files(t):
                total += 1
                synced += self.is_synced(p)
        return {"events": total, "synced": synced, "pending": total - synced,
                "traces": len(self.traces())}


@dataclass
class EmitResult:
    event: AuditEvent
    db_synced: bool


def emit_event(spool: Spool, *, run_id: str, trace_id: str, event_type: str, actor: str,
               payload: dict[str, Any] | None = None, file_id: str | None = None,
               operation_id: str | None = None, batch_id: str | None = None,
               expect_sequence: int | None = None, expect_hash: str | None = None,
               dsn: str | None = None, source: str = C.SRC_BASH) -> EmitResult:
    """Spool an event durably, then best-effort push it to PostgreSQL.

    Success is reported only after the local file is fsynced.  This function
    records audit information only; it never touches migration files.
    """
    if source == C.SRC_BASH and event_type not in C.BASH_EVENT_TYPES:
        raise AuditError(f"event type {event_type!r} may not be emitted from Bash")
    uuid.UUID(trace_id)
    fd = spool.lock(trace_id)
    conn = None
    try:
        db_head: tuple[int, str] | None = None
        if dsn:
            try:
                conn = psycopg.connect(dsn, connect_timeout=3, autocommit=True,
                                       row_factory=psycopg.rows.dict_row)
                db_head = get_head(conn, trace_id)
            except Exception:
                conn = None
                db_head = None      # PostgreSQL unavailable: rely on spool / batch metadata
        head = spool.head(trace_id)
        if head is None:
            if expect_sequence is None or expect_hash is None:
                if db_head is None or db_head[0] == 0:
                    raise AuditError("no chain head known: pass --expect-sequence/--expect-hash")
                head = db_head
            else:
                head = (expect_sequence, expect_hash)
                if db_head is not None and db_head != head:
                    # Reconciliation (read-only observation) may legitimately append events to the
                    # trace before a batch runs.  Anything else (e.g. a newer plan) makes it stale.
                    benign = False
                    if db_head[0] > expect_sequence:
                        r = conn.execute("SELECT event_hash FROM audit_event WHERE trace_id = %s "
                                         "AND sequence_no = %s", (trace_id, expect_sequence)).fetchone()
                        later = conn.execute("SELECT source FROM audit_event WHERE trace_id = %s "
                                             "AND sequence_no > %s", (trace_id, expect_sequence)).fetchall()
                        benign = bool(r and r["event_hash"].strip() == expect_hash
                                      and all(x["source"] == C.SRC_RECONCILER for x in later))
                    if not benign:
                        raise StaleChainError(
                            f"trace head in PostgreSQL is {db_head[0]}:{db_head[1][:12]} but the batch "
                            f"expects {expect_sequence}:{expect_hash[:12]}; the batch is stale")
                    head = db_head
        elif db_head is not None and db_head[0] > head[0]:
            # The database moved on (e.g. reconciliation events).  Continue from its head, but only
            # if our own last event is really part of that chain.
            r = conn.execute("SELECT event_hash FROM audit_event WHERE trace_id = %s AND sequence_no = %s",
                             (trace_id, head[0])).fetchone()
            if r is None or r["event_hash"].strip() != head[1]:
                raise StaleChainError("local spool and PostgreSQL disagree about this trace; "
                                      "run `audit sync` and inspect the divergence")
            head = db_head
        spec = EventSpec(uuid.UUID(trace_id), event_type, actor, source, payload or {},
                         uuid.UUID(file_id) if file_id else None,
                         uuid.UUID(operation_id) if operation_id else None,
                         uuid.UUID(batch_id) if batch_id else None)
        ev = build_event(run_id, spec, head[0] + 1, head[1])
        path = spool.write(ev)
    finally:
        spool.unlock(fd)
    synced = False
    if conn is not None:
        try:
            synced = push_event(conn, ev)
            if synced:
                spool.mark_synced(path)
        except Exception:   # the durable spool copy is the guarantee; PostgreSQL is best-effort here
            synced = False
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return EmitResult(ev, synced)


# --- spool -> PostgreSQL synchronization ---------------------------------------------

@dataclass
class SyncReport:
    traces: int = 0
    imported: int = 0
    already_present: int = 0
    problems: list[ChainProblem] = field(default_factory=list)
    bash_events_imported: int = 0

    @property
    def ok(self) -> bool:
        return not self.problems


def sync_spool(conn: psycopg.Connection, run_id: uuid.UUID | str, spool: Spool) -> SyncReport:
    rid = str(run_id)
    rep = SyncReport()
    traces = spool.traces()
    known = set()
    for i in range(0, len(traces), 5000):
        chunk = traces[i:i + 5000]
        for r in conn.execute(
                "SELECT trace_id FROM file_inventory WHERE run_id = %s AND trace_id = ANY(%s::uuid[])",
                (rid, chunk)):
            known.add(str(r["trace_id"]))
    for trace in traces:
        rep.traces += 1
        files = spool.event_files(trace)
        events: list[AuditEvent] = []
        bad = False
        for p in files:
            try:
                events.append(Spool.load(p))
            except (ValueError, KeyError, TypeError) as exc:
                rep.problems.append(ChainProblem(trace, "UNREADABLE_SPOOL_EVENT", f"{p.name}: {exc}"))
                bad = True
        if bad or not events:
            continue
        if trace not in known:
            rep.problems.append(ChainProblem(trace, "UNKNOWN_TRACE", "spooled events for a trace not in this run"))
            continue
        internal: list[ChainProblem] = []
        prev_ev: AuditEvent | None = None
        for ev in events:
            if recompute_hash(ev) != ev.event_hash:
                internal.append(ChainProblem(trace, "MUTATED_EVENT",
                                             f"sequence {ev.sequence_no}: stored hash does not match content"))
            if prev_ev is not None and ev.sequence_no == prev_ev.sequence_no + 1:
                if ev.previous_event_hash != prev_ev.event_hash:
                    internal.append(ChainProblem(trace, "BROKEN_LINK",
                                                 f"sequence {ev.sequence_no}: previous hash does not match predecessor"))
            elif prev_ev is not None and ev.sequence_no <= prev_ev.sequence_no:
                internal.append(ChainProblem(trace, "DUPLICATE_OR_REORDERED",
                                             f"sequence {ev.sequence_no} follows {prev_ev.sequence_no}"))
            elif ev.sequence_no > 1:
                # first spooled event, or a jump because the database appended events in between
                # (e.g. reconciliation): the predecessor must exist in PostgreSQL and match.
                r = conn.execute("SELECT event_hash FROM audit_event WHERE trace_id = %s AND sequence_no = %s",
                                 (trace, ev.sequence_no - 1)).fetchone()
                if r is None:
                    internal.append(ChainProblem(trace, "GAP", f"predecessor of sequence {ev.sequence_no} "
                                                              "is not in PostgreSQL"))
                elif r["event_hash"].strip() != ev.previous_event_hash:
                    internal.append(ChainProblem(trace, "DIVERGED", f"sequence {ev.sequence_no} does not "
                                                                    "continue the database chain"))
            elif ev.previous_event_hash != C.ZERO_HASH:
                internal.append(ChainProblem(trace, "BROKEN_LINK", "first event must start from the zero hash"))
            prev_ev = ev
        if any(e.run_id != rid or e.trace_id != trace for e in events):
            internal.append(ChainProblem(trace, "FOREIGN_EVENT", "spooled event belongs to another run/trace"))
        if any(e.source != C.SRC_BASH or e.event_type not in C.BASH_EVENT_TYPES for e in events):
            internal.append(ChainProblem(trace, "UNEXPECTED_EVENT", "spool holds a non-Bash event"))
        if internal:
            rep.problems.extend(internal)
            continue
        with conn.transaction():
            row = conn.execute("SELECT sequence_no, event_hash FROM trace_head WHERE trace_id = %s FOR UPDATE",
                               (trace,)).fetchone()
            hseq, hhash = (row["sequence_no"], row["event_hash"].strip()) if row else (0, C.ZERO_HASH)
            todo: list[AuditEvent] = []
            diverged = False
            for ev, path in zip(events, files):
                if ev.sequence_no <= hseq:
                    if spool.is_synced(path):
                        rep.already_present += 1
                        continue
                    r = conn.execute("SELECT event_id, event_hash FROM audit_event "
                                     "WHERE trace_id = %s AND sequence_no = %s",
                                     (trace, ev.sequence_no)).fetchone()
                    if r and str(r["event_id"]) == ev.event_id and r["event_hash"].strip() == ev.event_hash:
                        rep.already_present += 1
                        spool.mark_synced(path)
                    else:
                        rep.problems.append(ChainProblem(
                            trace, "DIVERGED", f"sequence {ev.sequence_no} in the spool differs from PostgreSQL"))
                        diverged = True
                        break
                else:
                    todo.append(ev)
            if diverged or not todo:
                continue
            exp_prev = hhash
            if todo[0].sequence_no != hseq + 1:
                rep.problems.append(ChainProblem(
                    trace, "GAP", f"database head is {hseq} but the first spooled event to import is "
                                  f"{todo[0].sequence_no}"))
                continue
            if todo[0].previous_event_hash != exp_prev:
                rep.problems.append(ChainProblem(
                    trace, "DIVERGED", "spooled chain does not connect to the database trace head"))
                continue
            with conn.cursor() as cur:
                cur.executemany(_INSERT_EVENT + " ON CONFLICT (event_id) DO NOTHING",
                                [_event_row(e) for e in todo])
                cur.execute(_UPSERT_HEAD, (trace, todo[-1].sequence_no, todo[-1].event_hash))
            rep.imported += len(todo)
            rep.bash_events_imported += sum(1 for e in todo if e.source == C.SRC_BASH)
            for ev, path in zip(events, files):
                if ev.sequence_no > hseq:
                    spool.mark_synced(path)
    return rep
