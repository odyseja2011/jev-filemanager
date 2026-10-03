"""Recursive Jev classification, route resolution and human review.

Deterministic code owns filesystem facts, sampling, confidence gating and path
construction; Jev owns only the semantic choice among configured targets.
"""

from __future__ import annotations

import csv
import getpass
import hashlib
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

from migrator import audit as A
from migrator import constants as C
from migrator import db
from migrator import jev as J
from migrator.logs import get_logger
from migrator.models import Assign, ClassifyTask, DirNode, Effective
from migrator.paths import canonical_json, sha256_hex, utc_now, write_replaceable_file
from migrator.runs import RunContext

log = get_logger("classifier")

OUTCOME_ASSIGN, OUTCOME_DESCEND, OUTCOME_HOLD = "ASSIGN", "DESCEND", "HOLD"


class ClassifyError(RuntimeError):
    pass


# --- deterministic state construction -------------------------------------------------

def sample_names(names: Iterable[str], limit: int) -> list[str]:
    """Deterministic sample: order by SHA-256(name), keep the first `limit`,
    then present alphabetically.  Independent of filesystem enumeration order."""
    keyed = sorted(set(names), key=lambda n: (hashlib.sha256(n.encode("utf-8")).hexdigest(), n))
    return sorted(keyed[:max(limit, 0)])


def build_directory_state(current: str, ancestors: list[str], child_dirs: list[str],
                          files: list[str], samples: dict[str, int]) -> dict[str, Any]:
    n_dirs, n_files = samples["max_child_directory_names"], samples["max_file_names"]
    anc = ancestors[-samples["max_ancestor_names"]:] if samples["max_ancestor_names"] > 0 else []
    limit = samples["max_state_characters"]
    while True:
        state = {"current_directory": current, "ancestor_names": anc,
                 "child_directory_names": sample_names(child_dirs, n_dirs),
                 "file_names": sample_names(files, n_files)}
        if len(canonical_json(state)) <= limit or (n_dirs == 0 and n_files == 0):
            return state
        n_dirs, n_files = n_dirs // 2, n_files // 2


def build_file_state(name: str, ancestors: list[str], max_ancestors: int) -> dict[str, Any]:
    anc = ancestors[-max_ancestors:] if max_ancestors > 0 else []
    return {"file_name": name, "ancestor_names": anc}


def decision_cache_key(model: str, state_sha256: str, criteria_sha256: str,
                       policy_version: str = C.ROUTING_POLICY_VERSION) -> str:
    return sha256_hex(model + state_sha256 + criteria_sha256 + policy_version)


def _prepare(task: ClassifyTask, model: str) -> ClassifyTask:
    task.state_sha256 = sha256_hex(canonical_json(task.state))
    task.criteria_sha256 = sha256_hex(canonical_json(task.question))
    task.cache_key = decision_cache_key(model, task.state_sha256, task.criteria_sha256)
    return task


# --- loading ----------------------------------------------------------------------------

def load_source_dirs(ctx: RunContext) -> dict[str, DirNode]:
    rows = ctx.conn.execute(
        """SELECT d.directory_id, d.parent_directory_id, d.scan_root_id, d.absolute_path,
                  d.relative_path, d.basename, d.depth
           FROM directory_inventory d JOIN scan_root r USING (scan_root_id)
           WHERE d.run_id = %s AND r.root_type = 'SOURCE'""", (ctx.run_id,)).fetchall()
    nodes = {str(r["directory_id"]): DirNode(
        str(r["directory_id"]), None if r["parent_directory_id"] is None else str(r["parent_directory_id"]),
        str(r["scan_root_id"]), r["absolute_path"], r["relative_path"], r["basename"], r["depth"])
        for r in rows}
    for n in nodes.values():
        if n.parent_id is not None:
            n.parent = nodes[n.parent_id]
            n.parent.children.append(n)
    for n in nodes.values():
        n.children.sort(key=lambda c: c.basename)
    counts = {str(r["parent_directory_id"]): r["n"] for r in ctx.conn.execute(
        "SELECT parent_directory_id, count(*) AS n FROM file_inventory "
        "WHERE run_id = %s AND root_type = 'SOURCE' GROUP BY 1", (ctx.run_id,))}
    for n in nodes.values():
        n.subtree_files = counts.get(n.directory_id, 0)
    for n in sorted(nodes.values(), key=lambda x: -x.depth):
        if n.parent is not None:
            n.parent.subtree_files += n.subtree_files
    return nodes


def ancestor_names(node: DirNode) -> list[str]:
    names: list[str] = []
    cur = node.parent
    while cur is not None:
        names.append(cur.basename)
        cur = cur.parent
    return list(reversed(names))


def effective_decisions(ctx: RunContext) -> dict[tuple[str, str], Effective]:
    rows = ctx.conn.execute(
        """SELECT DISTINCT ON (subject_type, subject_id)
                  decision_id, subject_type, subject_id, decision_source, decision_status,
                  selected_choice, confidence, returned_model, state_sha256, applies_to_subtree
           FROM route_decision WHERE run_id = %s
           ORDER BY subject_type, subject_id, (decision_status = 'OK') DESC, created_at DESC,
                    decision_id DESC""", (ctx.run_id,)).fetchall()
    return {(r["subject_type"], str(r["subject_id"])): Effective(
        str(r["decision_id"]), r["subject_type"], str(r["subject_id"]), r["decision_source"],
        r["decision_status"], r["selected_choice"], r["confidence"], r["returned_model"],
        r["state_sha256"].strip(), r["applies_to_subtree"]) for r in rows}


def directory_outcome(dec: Effective, threshold: float, target_ids: set[str]) -> str:
    """How a directory decision affects recursion (cases A-D)."""
    if dec.status == C.DECISION_API_FAILED:
        return OUTCOME_HOLD
    if dec.source == C.SOURCE_HUMAN:
        return OUTCOME_ASSIGN if dec.applies_to_subtree else OUTCOME_DESCEND
    if dec.choice in target_ids and dec.confidence is not None and dec.confidence >= threshold:
        return OUTCOME_ASSIGN
    return OUTCOME_DESCEND   # DESCEND, or a target below the confidence threshold


# --- decision persistence ------------------------------------------------------------------

_INSERT_DECISION = """INSERT INTO route_decision (decision_id, run_id, subject_type, subject_id,
    decision_source, decision_status, supersedes_decision_id, cached_from_decision_id, cache_key,
    routing_policy_version, applies_to_subtree, state_json, state_sha256, question_json,
    criteria_sha256, selected_choice, confidence, probabilities, response_json, error_text,
    requested_model, returned_model, api_request_id, api_usage, decided_by, created_at)
    VALUES (%(decision_id)s, %(run_id)s, %(subject_type)s, %(subject_id)s, %(decision_source)s,
    %(decision_status)s, %(supersedes)s, %(cached_from)s, %(cache_key)s, %(policy)s,
    %(subtree)s, %(state_json)s, %(state_sha256)s, %(question_json)s, %(criteria_sha256)s,
    %(choice)s, %(confidence)s, %(probabilities)s, %(response_json)s, %(error_text)s,
    %(requested_model)s, %(returned_model)s, %(api_request_id)s, %(api_usage)s, %(decided_by)s,
    %(created_at)s)"""


def _decision_params(**kw: Any) -> dict[str, Any]:
    base = dict(decision_status=C.DECISION_OK, supersedes=None, cached_from=None, cache_key=None,
                policy=None, subtree=None, choice=None, confidence=None, probabilities=None,
                response_json=None, error_text=None, requested_model=None, returned_model=None,
                api_request_id=None, api_usage=None, decided_by=None, created_at=utc_now())
    base.update(kw)
    for k in ("state_json", "question_json", "probabilities", "response_json", "api_usage"):
        if base.get(k) is not None:
            base[k] = db.jsonb(base[k])
    return base


class Classifier:
    def __init__(self, ctx: RunContext, client: J.JevClient):
        self.ctx = ctx
        self.client = client
        self.cfg = ctx.cfg
        self.model = ctx.cfg.model
        self.threshold = ctx.cfg.threshold
        self.targets = {t.id: t.description for t in ctx.cfg.targets}
        self.samples = ctx.cfg["routing"]["samples"]
        self.max_depth = ctx.cfg["routing"]["max_depth"]
        self.stats = {"directory_calls": 0, "file_calls": 0, "cache_hits": 0, "api_failures": 0}
        self.dir_question = J.directory_question(self.targets)
        self.file_question = J.file_question(self.targets)

    # -- tasks -------------------------------------------------------------------------
    def _dir_task(self, node: DirNode, nodes: dict[str, DirNode]) -> ClassifyTask:
        files = [r["basename"] for r in self.ctx.conn.execute(
            "SELECT basename FROM file_inventory WHERE parent_directory_id = %s", (node.directory_id,))]
        state = build_directory_state(node.basename, ancestor_names(node),
                                      [c.basename for c in node.children], files, self.samples)
        return _prepare(ClassifyTask(C.SUBJECT_DIRECTORY, node.directory_id, state,
                                     self.dir_question, label=node.absolute_path), self.model)

    def _file_tasks(self, node: DirNode, eff: dict) -> list[ClassifyTask]:
        anc = ancestor_names(node) + [node.basename]
        out = []
        rows = self.ctx.conn.execute(
            """SELECT file_id, trace_id, basename FROM file_inventory
               WHERE parent_directory_id = %s AND hash_status = 'HASHED' ORDER BY basename""",
            (node.directory_id,)).fetchall()
        for r in rows:
            e = eff.get((C.SUBJECT_FILE, str(r["file_id"])))
            if e is not None and (e.source == C.SOURCE_HUMAN or e.status == C.DECISION_OK):
                continue
            state = build_file_state(r["basename"], anc, self.samples["max_ancestor_names"])
            out.append(_prepare(ClassifyTask(C.SUBJECT_FILE, str(r["file_id"]), state, self.file_question,
                                             file_trace_id=str(r["trace_id"]),
                                             label=f"{node.absolute_path}/{r['basename']}"), self.model))
        return out

    # -- execution ----------------------------------------------------------------------
    def _lookup_cache(self, key: str) -> dict | None:
        if not self.cfg["routing"]["cache_decisions"]:
            return None
        return self.ctx.conn.execute(
            """SELECT decision_id, selected_choice, confidence, probabilities, response_json,
                      returned_model, api_request_id, api_usage FROM route_decision
               WHERE cache_key = %s AND cached_from_decision_id IS NULL AND decision_status = 'OK'
               ORDER BY created_at LIMIT 1""", (key,)).fetchone()

    EXECUTE_CHUNK = 500

    def _execute_chunked(self, tasks: list[ClassifyTask], eff: dict) -> None:
        """Bounded batches: limits memory and commits progress every EXECUTE_CHUNK decisions."""
        for i in range(0, len(tasks), self.EXECUTE_CHUNK):
            self.execute(tasks[i:i + self.EXECUTE_CHUNK], eff)
            if len(tasks) > self.EXECUTE_CHUNK:
                log.info("  %d/%d requests of this level done", min(i + self.EXECUTE_CHUNK, len(tasks)),
                         len(tasks), extra={"run_id": self.ctx.run_id})

    def execute(self, tasks: list[ClassifyTask], eff: dict) -> list[str]:
        """Resolve tasks (cache, then Jev); persist decisions.  Returns new decision ids
        in task order."""
        if not tasks:
            return []
        conn = self.ctx.conn
        cached: dict[str, dict | None] = {}
        origin_by_key: dict[str, str] = {}      # cache key -> decision id created in this batch
        to_call: dict[str, ClassifyTask] = {}
        for t in tasks:
            if t.cache_key not in cached:
                cached[t.cache_key] = self._lookup_cache(t.cache_key)
            if cached[t.cache_key] is None and t.cache_key not in to_call:
                to_call[t.cache_key] = t
        results: dict[str, J.JevResponse | J.JevError] = {}

        def call(item: tuple[str, ClassifyTask]):
            key, t = item
            try:
                return key, self.client.decide(J.build_request(self.model, t.state, t.question))
            except J.JevError as exc:
                return key, exc
            except Exception as exc:  # never guess: any failure is an API failure
                return key, J.JevError(f"{type(exc).__name__}: {exc}", retryable=True)

        if to_call:
            with ThreadPoolExecutor(max_workers=self.cfg["openrouter"]["concurrency"]) as pool:
                for key, res in pool.map(call, list(to_call.items())):
                    results[key] = res
        new_ids: list[str] = []
        events: list[A.EventSpec] = []
        with conn.transaction():
            for t in tasks:
                prev = eff.get((t.kind, t.subject_id))
                did = str(uuid.uuid4())
                common = dict(decision_id=did, run_id=self.ctx.run_id, subject_type=t.kind,
                              subject_id=t.subject_id, decision_source=C.SOURCE_JEV,
                              supersedes=prev.decision_id if prev else None,
                              cache_key=t.cache_key, policy=C.ROUTING_POLICY_VERSION,
                              state_json=t.state, state_sha256=t.state_sha256,
                              question_json=t.question, criteria_sha256=t.criteria_sha256,
                              requested_model=self.model)
                src = cached.get(t.cache_key) or origin_by_key_row(origin_by_key, t.cache_key, conn)
                res = results.get(t.cache_key)
                if src is not None and not (isinstance(res, J.JevError)):
                    hit = True
                    row = src
                    p = _decision_params(**common, cached_from=str(row["decision_id"]),
                                         choice=row["selected_choice"], confidence=row["confidence"],
                                         probabilities=_j(row["probabilities"]),
                                         response_json=_j(row["response_json"]),
                                         returned_model=row["returned_model"], api_request_id=None,
                                         api_usage=None)
                    conn.execute(_INSERT_DECISION, p)
                    self.stats["cache_hits"] += 1
                    ev_payload = {"decision_id": did, "cache_hit": True,
                                  "cached_from": str(row["decision_id"])}
                    choice, conf = row["selected_choice"], row["confidence"]
                    failed = False
                elif isinstance(res, J.JevError):
                    hit = False
                    p = _decision_params(**common, decision_status=C.DECISION_API_FAILED,
                                         error_text=str(res)[:2000])
                    conn.execute(_INSERT_DECISION, p)
                    self.stats["api_failures"] += 1
                    ev_payload = {"decision_id": did, "error": str(res)[:500]}
                    choice = conf = None
                    failed = True
                else:
                    hit = False
                    p = _decision_params(**common, choice=res.choice, confidence=res.confidence,
                                         probabilities=res.probabilities, response_json=res.raw,
                                         returned_model=res.returned_model,
                                         api_request_id=res.request_id, api_usage=res.usage)
                    conn.execute(_INSERT_DECISION, p)
                    origin_by_key[t.cache_key] = did
                    self.stats["directory_calls" if t.kind == C.SUBJECT_DIRECTORY else "file_calls"] += 1
                    ev_payload = {"decision_id": did, "cache_hit": False}
                    choice, conf = res.choice, res.confidence
                    failed = False
                new_ids.append(did)
                if t.kind == C.SUBJECT_FILE and t.file_trace_id:
                    tid = uuid.UUID(t.file_trace_id)
                    events.append(A.EventSpec(tid, "CLASSIFICATION_REQUESTED", "migrator", C.SRC_PYTHON, {
                        "state_sha256": t.state_sha256, "criteria_sha256": t.criteria_sha256,
                        "requested_model": self.model, "decision_id": did}, file_id=uuid.UUID(t.subject_id)))
                    if failed:
                        events.append(A.EventSpec(tid, "CLASSIFICATION_API_FAILED", "migrator",
                                                  C.SRC_PYTHON, ev_payload, file_id=uuid.UUID(t.subject_id)))
                    else:
                        events.append(A.EventSpec(tid, "CLASSIFICATION_RECEIVED", "migrator", C.SRC_PYTHON,
                                                  {**ev_payload, "choice": choice, "confidence": conf},
                                                  file_id=uuid.UUID(t.subject_id)))
                eff[(t.kind, t.subject_id)] = Effective(
                    did, t.kind, t.subject_id, C.SOURCE_JEV,
                    C.DECISION_API_FAILED if failed else C.DECISION_OK, choice, conf, None,
                    t.state_sha256, None)
            A.append_events(conn, self.ctx.run_id, events)
        return new_ids

    # -- recursion -----------------------------------------------------------------------
    def run(self) -> dict[str, int]:
        nodes = load_source_dirs(self.ctx)
        eff = effective_decisions(self.ctx)
        target_ids = set(self.targets)
        roots = sorted((n for n in nodes.values() if n.parent is None), key=lambda n: n.absolute_path)
        dir_level: list[DirNode] = []
        file_dirs: list[DirNode] = []
        for root in roots:      # Jev never routes a configured root as a whole subtree
            e = eff.get((C.SUBJECT_DIRECTORY, root.directory_id))
            if e is not None and e.source == C.SOURCE_HUMAN:
                if not e.applies_to_subtree:       # human routed the root's direct files only
                    dir_level.extend(root.children)
                continue                           # human subtree decision: nothing left to ask
            file_dirs.append(root)
            dir_level.extend(root.children)
        level = 0
        while dir_level or file_dirs:
            level += 1
            dir_tasks: list[ClassifyTask] = []
            dir_nodes: list[DirNode] = []
            next_dirs: list[DirNode] = []
            next_file_dirs: list[DirNode] = []
            for node in dir_level:
                if node.subtree_files == 0 or node.depth > self.max_depth:
                    continue
                e = eff.get((C.SUBJECT_DIRECTORY, node.directory_id))
                if e is not None and (e.source == C.SOURCE_HUMAN or e.status == C.DECISION_OK):
                    self._follow(node, e, target_ids, next_dirs, next_file_dirs)
                else:
                    dir_tasks.append(self._dir_task(node, nodes))
                    dir_nodes.append(node)
            file_tasks: list[ClassifyTask] = []
            for node in file_dirs:
                file_tasks.extend(self._file_tasks(node, eff))
            log.info("level %d: %d directory and %d file requests", level, len(dir_tasks), len(file_tasks),
                     extra={"run_id": self.ctx.run_id})
            self._execute_chunked(dir_tasks, eff)
            for node in dir_nodes:
                self._follow(node, eff[(C.SUBJECT_DIRECTORY, node.directory_id)], target_ids,
                             next_dirs, next_file_dirs)
            self._execute_chunked(file_tasks, eff)
            dir_level, file_dirs = next_dirs, next_file_dirs
        return dict(self.stats)

    def _follow(self, node: DirNode, e: Effective, target_ids: set[str],
                next_dirs: list[DirNode], next_file_dirs: list[DirNode]) -> None:
        if directory_outcome(e, self.threshold, target_ids) == OUTCOME_DESCEND:
            if e.source != C.SOURCE_HUMAN:   # human direct-only decisions already route the files
                next_file_dirs.append(node)
            next_dirs.extend(node.children)


def origin_by_key_row(origin: dict[str, str], key: str, conn) -> dict | None:
    did = origin.get(key)
    if did is None:
        return None
    return conn.execute("""SELECT decision_id, selected_choice, confidence, probabilities,
                                  response_json, returned_model FROM route_decision
                           WHERE decision_id = %s""", (did,)).fetchone()


def _j(v: Any) -> Any:
    return v


# --- route resolution ------------------------------------------------------------------------

def resolve_routes(ctx: RunContext) -> dict[str, int]:
    """(Re)compute the final route of every SOURCE regular file from the effective
    decisions.  Changed routes are upserted and audited (ROUTE_ASSIGNED etc.)."""
    conn = ctx.conn
    cfg = ctx.cfg
    threshold = cfg.threshold
    target_ids = set(cfg.target_ids)
    max_depth = cfg["routing"]["max_depth"]
    hardlink_status = C.ROUTE_REVIEW if cfg["inventory"]["hardlinks"]["action"] == "review" else C.ROUTE_BLOCKED
    nodes = load_source_dirs(ctx)
    eff = effective_decisions(ctx)

    state: dict[str, tuple[Assign | None, Assign | None, str | None]] = {}
    for node in sorted(nodes.values(), key=lambda n: (n.depth, n.absolute_path)):
        inh, hold = (None, None)
        if node.parent is not None:
            inh, _own, hold = state[node.parent.directory_id]
        own: Assign | None = None
        dec = eff.get((C.SUBJECT_DIRECTORY, node.directory_id))
        if node.parent is None and (dec is None or dec.source != C.SOURCE_HUMAN):
            pass                  # Jev never routes a configured root as a whole; humans may
        elif dec is None:
            if inh is None and hold is None:
                hold = "MAX_DEPTH" if node.depth > max_depth else "NOT_CLASSIFIED"
        elif dec.status == C.DECISION_API_FAILED:
            if inh is None:
                hold = "CLASSIFICATION_API_FAILED"
        else:
            cand: Assign | None = None
            if dec.source == C.SOURCE_HUMAN and dec.choice in target_ids:
                a = Assign(dec.choice, dec.decision_id, C.SOURCE_HUMAN, None, node.directory_id)
                if dec.applies_to_subtree:
                    cand = a
                else:
                    own = a
            elif dec.source == C.SOURCE_JEV and dec.choice in target_ids \
                    and dec.confidence is not None and dec.confidence >= threshold:
                cand = Assign(dec.choice, dec.decision_id, C.SOURCE_JEV, dec.confidence, node.directory_id)
            if cand is not None and not (inh is not None and inh.source == C.SOURCE_HUMAN
                                         and cand.source == C.SOURCE_JEV):
                inh, hold = cand, None
        state[node.directory_id] = (inh, own, hold)

    counts = {C.ROUTE_READY: 0, C.ROUTE_REVIEW: 0, C.ROUTE_BLOCKED: 0}
    upserts: list[tuple] = []
    events: list[A.EventSpec] = []
    decision_info = {e.decision_id: e for e in eff.values()}

    def flush() -> None:
        if not upserts:
            return
        with conn.transaction():
            with conn.cursor() as cur:
                cur.executemany(
                    """INSERT INTO file_route (file_route_id, run_id, file_id, decision_id, route_origin_type,
                           route_directory_id, target_id, confidence, route_status, reason_code)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (run_id, file_id) DO UPDATE SET decision_id = EXCLUDED.decision_id,
                           route_origin_type = EXCLUDED.route_origin_type,
                           route_directory_id = EXCLUDED.route_directory_id,
                           target_id = EXCLUDED.target_id, confidence = EXCLUDED.confidence,
                           route_status = EXCLUDED.route_status, reason_code = EXCLUDED.reason_code""",
                    upserts)
            A.append_events(conn, ctx.run_id, events)
        upserts.clear()
        events.clear()

    last_path = ""
    while True:
        page = conn.execute(
            """SELECT file_id, trace_id, parent_directory_id, hash_status, absolute_path FROM file_inventory
               WHERE run_id = %s AND root_type = 'SOURCE' AND absolute_path > %s
               ORDER BY absolute_path LIMIT 5000""", (ctx.run_id, last_path)).fetchall()
        if not page:
            break
        last_path = page[-1]["absolute_path"]
        existing = {str(r["file_id"]): r for r in conn.execute(
            "SELECT file_id, decision_id, route_origin_type, route_directory_id, target_id, route_status, "
            "reason_code FROM file_route WHERE run_id = %s AND file_id = ANY(%s::uuid[])",
            (ctx.run_id, [str(r["file_id"]) for r in page]))}
        for r in page:
            fid = str(r["file_id"])
            inh, own, hold = state[str(r["parent_directory_id"])]
            fdec = eff.get((C.SUBJECT_FILE, fid))
            decision_id: str | None = None
            origin: str | None = None
            route_dir: str | None = None
            target: str | None = None
            conf: float | None = None
            status, reason = C.ROUTE_REVIEW, None
            if fdec is not None and fdec.source == C.SOURCE_HUMAN and fdec.choice in target_ids:
                decision_id, origin, target, status = fdec.decision_id, C.ROUTE_DIRECT, fdec.choice, C.ROUTE_READY
            elif own is not None:
                decision_id, origin, route_dir = own.decision_id, C.ROUTE_INHERITED, own.route_directory_id
                target, conf, status = own.target_id, own.confidence, C.ROUTE_READY
            elif inh is not None:
                decision_id, origin, route_dir = inh.decision_id, C.ROUTE_INHERITED, inh.route_directory_id
                target, conf, status = inh.target_id, inh.confidence, C.ROUTE_READY
            elif fdec is not None:
                decision_id = fdec.decision_id
                if fdec.status == C.DECISION_API_FAILED:
                    reason = "CLASSIFICATION_API_FAILED"
                elif fdec.choice in target_ids and fdec.confidence is not None and fdec.confidence >= threshold:
                    origin, target, conf, status = C.ROUTE_DIRECT, fdec.choice, fdec.confidence, C.ROUTE_READY
                elif fdec.choice in target_ids:
                    reason, conf = "LOW_CONFIDENCE", fdec.confidence
                else:
                    reason = "JEV_REVIEW"
            else:
                reason = hold or "NOT_CLASSIFIED"
            hs = r["hash_status"]
            if hs != C.HASH_HASHED:      # hash gate: no valid SHA-256 -> never automatic
                status = hardlink_status if hs == C.HASH_BLOCKED_HARDLINK else C.ROUTE_BLOCKED
                reason = {"BLOCKED_HARDLINK": "BLOCKED_HARDLINK", "UNSTABLE": "HASH_UNSTABLE",
                          "FAILED": "HASH_FAILED"}.get(hs, "HASH_PENDING")
            counts[status] += 1
            key = (decision_id, origin, route_dir, target, status, reason)
            old = existing.get(fid)
            if old is not None and (
                    (None if old["decision_id"] is None else str(old["decision_id"]),
                     old["route_origin_type"],
                     None if old["route_directory_id"] is None else str(old["route_directory_id"]),
                     old["target_id"], old["route_status"], old["reason_code"]) == key):
                continue
            upserts.append((str(uuid.uuid4()), ctx.run_id, fid, decision_id, origin, route_dir, target,
                            conf, status, reason))
            info = decision_info.get(decision_id) if decision_id else None
            etype = {C.ROUTE_READY: "ROUTE_ASSIGNED", C.ROUTE_REVIEW: "CLASSIFICATION_REVIEW_REQUIRED",
                     C.ROUTE_BLOCKED: "ROUTE_BLOCKED"}[status]
            events.append(A.EventSpec(r["trace_id"], etype, "migrator", C.SRC_PYTHON, {
                "route_status": status, "target_id": target, "route_origin_type": origin,
                "route_directory_id": route_dir, "decision_id": decision_id, "reason_code": reason,
                "decision_source": info.source if info else None,
                "confidence": conf, "returned_model": info.returned_model if info else None,
                "state_sha256": info.state_sha256 if info else None}, file_id=r["file_id"]))
        flush()
    return {"ready": counts[C.ROUTE_READY], "review": counts[C.ROUTE_REVIEW],
            "blocked": counts[C.ROUTE_BLOCKED]}


def write_decisions_jsonl(ctx: RunContext) -> Path:
    """Stream every decision to decisions.jsonl (server-side cursor; bounded memory)."""
    path = ctx.path("decisions", "decisions.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    ctx.guard.check(tmp)
    with open(tmp, "w", encoding="ascii") as out, ctx.conn.transaction(), \
            ctx.conn.cursor(name="decisions_jsonl") as cur:
        cur.itersize = 1000
        cur.execute("SELECT * FROM route_decision WHERE run_id = %s ORDER BY created_at, decision_id",
                    (ctx.run_id,))
        for row in cur:
            row = {k: (str(v) if isinstance(v, uuid.UUID) else (v.isoformat() if hasattr(v, "isoformat") else v))
                   for k, v in row.items()}
            out.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    return path


def run_classification(ctx: RunContext, client: J.JevClient) -> dict[str, Any]:
    conn = ctx.conn
    db.require_state(ctx.refresh(), C.INVENTORY_COMPLETE, C.CLASSIFYING, C.CLASSIFIED, C.REVIEW_REQUIRED)
    A.require_spool_synced(conn, ctx.run_id, ctx.spool)
    with conn.transaction():
        db.transition(conn, ctx.run_id, C.CLASSIFYING)
        A.append_event(conn, ctx.run_id, A.EventSpec(
            uuid.UUID(str(ctx.run["run_trace_id"])), "CLASSIFICATION_STARTED", "migrator", C.SRC_PYTHON,
            {"model": ctx.cfg.model, "threshold": ctx.cfg.threshold}))
    stats = Classifier(ctx, client).run()
    routes = resolve_routes(ctx)
    write_decisions_jsonl(ctx)
    with conn.transaction():
        final = C.CLASSIFIED if routes["review"] == 0 and routes["blocked"] == 0 else C.REVIEW_REQUIRED
        A.append_event(conn, ctx.run_id, A.EventSpec(
            uuid.UUID(str(ctx.run["run_trace_id"])), "CLASSIFICATION_COMPLETE", "migrator", C.SRC_PYTHON,
            {**stats, **routes}))
        db.transition(conn, ctx.run_id, final)
    return {**stats, **routes, "state": final}


# --- human review ------------------------------------------------------------------------------

REVIEW_COLUMNS = ["kind", "subject_id", "absolute_path", "route_status", "reason_code", "jev_choice",
                  "jev_confidence", "parent_directory_id", "parent_directory_path",
                  "human_target", "human_subtree"]


def review_rows(ctx: RunContext) -> list[dict[str, Any]]:
    rows = ctx.conn.execute(
        """SELECT f.file_id, f.absolute_path, f.hash_status, fr.route_status, fr.reason_code,
                  d.selected_choice, d.confidence, f.parent_directory_id, p.absolute_path AS parent_path
           FROM file_route fr JOIN file_inventory f USING (file_id)
                JOIN directory_inventory p ON p.directory_id = f.parent_directory_id
                LEFT JOIN route_decision d ON d.decision_id = fr.decision_id
           WHERE fr.run_id = %s AND fr.route_status <> 'READY' ORDER BY f.absolute_path COLLATE "C" """,
        (ctx.run_id,)).fetchall()
    return [{"kind": "FILE", "subject_id": str(r["file_id"]), "absolute_path": r["absolute_path"],
             "route_status": r["route_status"], "reason_code": r["reason_code"] or "",
             "jev_choice": r["selected_choice"] or "",
             "jev_confidence": "" if r["confidence"] is None else r["confidence"],
             "parent_directory_id": str(r["parent_directory_id"]),
             "parent_directory_path": r["parent_path"], "human_target": "", "human_subtree": ""}
            for r in rows]


def export_review_csv(ctx: RunContext, output: str | Path | None = None) -> Path:
    import io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=REVIEW_COLUMNS, lineterminator="\n")
    w.writeheader()
    for row in review_rows(ctx):
        w.writerow(row)
    out = Path(output) if output else ctx.path("review", "review.csv")
    if output is not None:
        from migrator.paths import is_within
        resolved = os.path.abspath(output)
        for root in ctx.cfg.migration_roots:
            if is_within(resolved, root):
                raise ClassifyError(f"refusing to write {resolved}: it lies beneath migration root {root}")
    if output is None:
        write_replaceable_file(out, buf.getvalue().encode(), ctx.guard)
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(buf.getvalue())
        # keep a copy in the run directory as well
        write_replaceable_file(ctx.path("review", "review.csv"), buf.getvalue().encode(), ctx.guard)
    return out


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _check_uuid(value: str, what: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise ClassifyError(f"{what} id {value!r} is not a UUID") from None


def _check_target(ctx: RunContext, target: str) -> None:
    if target not in ctx.cfg.target_ids:
        raise ClassifyError(f"unknown target {target!r}; configured: {', '.join(ctx.cfg.target_ids)}")


def _human_decision(ctx: RunContext, subject_type: str, subject_id: str, target: str, *,
                    subtree: bool | None, state: dict[str, Any]) -> str:
    eff = effective_decisions(ctx)
    prev = eff.get((subject_type, subject_id))
    question = {"type": "human_override", "allowed": sorted(ctx.cfg.target_ids)}
    did = str(uuid.uuid4())
    p = _decision_params(
        decision_id=did, run_id=ctx.run_id, subject_type=subject_type, subject_id=subject_id,
        decision_source=C.SOURCE_HUMAN, supersedes=prev.decision_id if prev else None,
        subtree=subtree, state_json=state, state_sha256=sha256_hex(canonical_json(state)),
        question_json=question, criteria_sha256=sha256_hex(canonical_json(question)),
        choice=target, decided_by=_actor())
    ctx.conn.execute(_INSERT_DECISION, p)
    return did


def set_file_target(ctx: RunContext, file_id: str, target: str, *, resolve: bool = True) -> str:
    _check_target(ctx, target)
    _check_uuid(file_id, "file")
    A.require_spool_synced(ctx.conn, ctx.run_id, ctx.spool)
    row = ctx.conn.execute("SELECT file_id, trace_id, absolute_path FROM file_inventory "
                           "WHERE run_id = %s AND file_id = %s AND root_type = 'SOURCE'",
                           (ctx.run_id, file_id)).fetchone()
    if row is None:
        raise ClassifyError(f"file {file_id} is not a SOURCE file of run {ctx.run_id}")
    with ctx.conn.transaction():
        did = _human_decision(ctx, C.SUBJECT_FILE, file_id, target, subtree=None,
                              state={"override": "human", "absolute_path": row["absolute_path"]})
        A.append_event(ctx.conn, ctx.run_id, A.EventSpec(
            row["trace_id"], "HUMAN_DECISION_RECORDED", _actor(), C.SRC_HUMAN,
            {"decision_id": did, "target_id": target}, file_id=row["file_id"]))
    if resolve:
        resolve_routes(ctx)
    return did


def set_directory_target(ctx: RunContext, directory_id: str, target: str, *, subtree: bool,
                         resolve: bool = True) -> str:
    _check_target(ctx, target)
    _check_uuid(directory_id, "directory")
    A.require_spool_synced(ctx.conn, ctx.run_id, ctx.spool)
    row = ctx.conn.execute(
        """SELECT d.directory_id, d.absolute_path FROM directory_inventory d JOIN scan_root r USING (scan_root_id)
           WHERE d.run_id = %s AND d.directory_id = %s AND r.root_type = 'SOURCE'""",
        (ctx.run_id, directory_id)).fetchone()
    if row is None:
        raise ClassifyError(f"directory {directory_id} is not a SOURCE directory of run {ctx.run_id}")
    with ctx.conn.transaction():
        did = _human_decision(ctx, C.SUBJECT_DIRECTORY, directory_id, target, subtree=subtree,
                              state={"override": "human", "absolute_path": row["absolute_path"],
                                     "subtree": subtree})
        A.append_event(ctx.conn, ctx.run_id, A.EventSpec(
            uuid.UUID(str(ctx.run["run_trace_id"])), "HUMAN_DIRECTORY_DECISION_RECORDED", _actor(),
            C.SRC_HUMAN, {"decision_id": did, "directory_id": directory_id, "target_id": target,
                          "subtree": subtree}))
    if resolve:
        resolve_routes(ctx)
    return did


def import_review_csv(ctx: RunContext, path: str | Path) -> dict[str, int]:
    """All-or-nothing validation, then one HUMAN decision per filled-in row."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    todo = []
    errors = []
    for i, row in enumerate(rows, start=2):
        target = (row.get("human_target") or "").strip()
        if not target:
            continue
        kind = (row.get("kind") or "").strip().upper()
        if target not in ctx.cfg.target_ids:
            errors.append(f"line {i}: unknown target {target!r}")
        elif kind not in (C.SUBJECT_FILE, C.SUBJECT_DIRECTORY):
            errors.append(f"line {i}: kind must be FILE or DIRECTORY")
        else:
            todo.append((kind, (row.get("subject_id") or "").strip(), target,
                         (row.get("human_subtree") or "").strip().lower() in ("1", "true", "yes", "y")))
    for n, (kind, sid, _t, _s) in enumerate(todo):
        try:
            uuid.UUID(sid)
        except ValueError:
            errors.append(f"row {n + 1} with a target: subject_id {sid!r} is not a UUID")
            continue
        if kind == C.SUBJECT_FILE:
            ok = ctx.conn.execute("SELECT 1 FROM file_inventory WHERE run_id = %s AND file_id = %s "
                                  "AND root_type = 'SOURCE'", (ctx.run_id, sid)).fetchone()
        else:
            ok = ctx.conn.execute("""SELECT 1 FROM directory_inventory d JOIN scan_root r USING (scan_root_id)
                                     WHERE d.run_id = %s AND d.directory_id = %s AND r.root_type = 'SOURCE'""",
                                  (ctx.run_id, sid)).fetchone()
        if not ok:
            errors.append(f"{kind} {sid} is not a SOURCE {kind.lower()} of this run")
    if errors:
        raise ClassifyError("review import rejected (nothing was applied):\n  " + "\n  ".join(errors))
    A.require_spool_synced(ctx.conn, ctx.run_id, ctx.spool)
    routes: dict[str, int] = {}
    with ctx.conn.transaction():          # all rows or none
        for kind, sid, target, subtree in todo:
            if kind == C.SUBJECT_FILE:
                set_file_target(ctx, sid, target, resolve=False)
            else:
                set_directory_target(ctx, sid, target, subtree=subtree, resolve=False)
        if todo:
            routes = resolve_routes(ctx)
    write_decisions_jsonl(ctx)
    return {"applied": len(todo), **routes}
