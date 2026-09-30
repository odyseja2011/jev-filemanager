"""Two-pass inventory: discovery (pass A) then SHA-256 hashing (pass B).

Read-only with respect to source/target roots.  Symlinks are counted, never
followed, recorded or migrated.
"""

from __future__ import annotations

import gzip
import io
import os
import stat as statmod
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterator

from migrator import audit as A
from migrator import constants as C
from migrator import db
from migrator.hashing import HashResult, hash_file
from migrator.logs import get_logger
from migrator.paths import GlobSet, is_utf8_clean, sha256_hex, utc_now, write_new_file
from migrator.runs import RunContext

log = get_logger("inventory")

CHUNK = 5000
HASH_CHUNK = 500
MANIFEST_FIELDS = ["trace_id", "root_id", "relative_path", "absolute_path", "size_bytes",
                   "mtime_ns", "st_dev", "st_ino", "st_nlink", "sha256", "hash_status"]

_DIR_COLS = ("directory_id", "run_id", "scan_root_id", "parent_directory_id", "absolute_path",
             "relative_path", "basename", "depth", "st_dev", "st_ino")
_FILE_COLS = ("file_id", "trace_id", "run_id", "scan_root_id", "parent_directory_id", "root_type",
              "absolute_path", "relative_path", "basename", "size_bytes", "mtime_ns", "ctime_ns",
              "st_dev", "st_ino", "st_nlink", "hash_status")


class InventoryError(RuntimeError):
    pass


@dataclass
class RootStats:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    other: int = 0
    undecodable: int = 0
    unreadable_dirs: list[str] = field(default_factory=list)


class _Writer:
    """Buffers directory/file rows and flushes them with COPY."""

    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.dirs: list[tuple] = []
        self.files: list[tuple] = []
        self.file_events: list[A.EventSpec] = []

    def add_dir(self, row: tuple) -> None:
        self.dirs.append(row)
        if len(self.dirs) >= CHUNK:
            self.flush()

    def add_file(self, row: tuple, spec: A.EventSpec) -> None:
        self.files.append(row)
        self.file_events.append(spec)
        if len(self.files) >= CHUNK:
            self.flush()

    def flush(self) -> None:
        conn = self.ctx.conn
        if not self.dirs and not self.files:
            return
        with conn.transaction():
            with conn.cursor() as cur:
                if self.dirs:
                    with cur.copy(f"COPY directory_inventory ({','.join(_DIR_COLS)}) FROM STDIN") as cp:
                        for r in self.dirs:
                            cp.write_row(r)
                if self.files:
                    with cur.copy(f"COPY file_inventory ({','.join(_FILE_COLS)}) FROM STDIN") as cp:
                        for r in self.files:
                            cp.write_row(r)
            A.append_events(conn, self.ctx.run_id, self.file_events)
        self.dirs, self.files, self.file_events = [], [], []


def _walk_root(ctx: RunContext, w: _Writer, *, scan_root_id: str, root_type: str, config_id: str,
               root_path: str, cross_mounts: bool, include: GlobSet | None,
               exclude: GlobSet | None) -> RootStats:
    stats = RootStats()
    run_id = ctx.run_id
    root_st = os.lstat(root_path)
    root_dir_id = str(uuid.uuid4())
    w.add_dir((root_dir_id, run_id, scan_root_id, None, root_path, "",
               os.path.basename(root_path), 0, root_st.st_dev, root_st.st_ino))
    stats.dirs += 1
    stack: list[tuple[str, str, int, str]] = [(root_path, root_dir_id, 0, "")]
    while stack:
        path, dir_id, depth, rel = stack.pop()
        try:
            with os.scandir(path) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            log.warning("cannot read directory %s: %s", path, exc, extra={"run_id": run_id})
            stats.unreadable_dirs.append(path)
            continue
        subdirs: list[tuple[str, str, int, str]] = []
        for e in entries:
            name = e.name
            if not is_utf8_clean(name):
                stats.undecodable += 1
                log.warning("skipping undecodable name %r under %s", name, path, extra={"run_id": run_id})
                continue
            try:
                if e.is_symlink():
                    stats.symlinks += 1
                    continue
                child_rel = f"{rel}/{name}" if rel else name
                child_abs = os.path.join(path, name)
                if e.is_dir(follow_symlinks=False):
                    if exclude and (exclude.matches(child_rel) or exclude.matches(child_rel + "/")):
                        continue
                    st = e.stat(follow_symlinks=False)
                    if not cross_mounts and st.st_dev != root_st.st_dev:
                        log.info("not crossing mount boundary at %s", child_abs, extra={"run_id": run_id})
                        continue
                    child_id = str(uuid.uuid4())
                    w.add_dir((child_id, run_id, scan_root_id, dir_id, child_abs, child_rel, name,
                               depth + 1, st.st_dev, st.st_ino))
                    stats.dirs += 1
                    subdirs.append((child_abs, child_id, depth + 1, child_rel))
                elif e.is_file(follow_symlinks=False):
                    if exclude and exclude.matches(child_rel):
                        continue
                    if include and not include.matches(child_rel):
                        continue
                    st = e.stat(follow_symlinks=False)
                    trace_id = uuid.uuid4()
                    file_id = uuid.uuid4()
                    hardlink = root_type == C.ROOT_SOURCE and st.st_nlink > 1
                    status = C.HASH_BLOCKED_HARDLINK if hardlink else C.HASH_PENDING
                    w.add_file((str(file_id), str(trace_id), run_id, scan_root_id, dir_id, root_type,
                                child_abs, child_rel, name, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                                st.st_dev, st.st_ino, st.st_nlink, status),
                               A.EventSpec(trace_id, "FILE_DISCOVERED", "migrator", C.SRC_PYTHON, {
                                   "root_type": root_type, "root_id": config_id,
                                   "absolute_path": child_abs, "relative_path": child_rel,
                                   "size_bytes": st.st_size, "mtime_ns": st.st_mtime_ns,
                                   "st_nlink": st.st_nlink, "hash_status": status}, file_id=file_id))
                    stats.files += 1
                else:
                    stats.other += 1
            except OSError as exc:
                log.warning("cannot stat %s/%s: %s", path, name, exc, extra={"run_id": run_id})
                stats.other += 1
        stack.extend(reversed(subdirs))
    w.flush()
    return stats


def discover(ctx: RunContext) -> dict[str, dict]:
    """Pass A.  Walk every source then target root; finish before hashing starts."""
    conn, cfg, run_id = ctx.conn, ctx.cfg, ctx.run_id
    db.require_state(ctx.refresh(), C.CREATED)
    problems = []
    for s in cfg.sources:
        if not os.path.isdir(s.path):
            problems.append(f"source {s.id}: {s.path} is not a readable directory")
    if problems:
        raise InventoryError("; ".join(problems))
    with conn.transaction():
        db.transition(conn, run_id, C.DISCOVERING)
    roots = conn.execute("SELECT * FROM scan_root WHERE run_id = %s ORDER BY root_type DESC, config_id",
                         (run_id,)).fetchall()
    w = _Writer(ctx)
    summary: dict[str, dict] = {}
    for root in roots:
        cid, rtype = root["config_id"], root["root_type"]
        with conn.transaction():
            conn.execute("UPDATE scan_root SET discovery_started_at = now() WHERE scan_root_id = %s",
                         (str(root["scan_root_id"]),))
        if not os.path.isdir(root["absolute_path"]):
            log.warning("root %s does not exist; treated as empty", root["absolute_path"],
                        extra={"run_id": run_id})
            stats = RootStats()
        else:
            if rtype == C.ROOT_SOURCE:
                src = next(s for s in cfg.sources if s.id == cid)
                include, exclude = GlobSet(src.include), GlobSet(src.exclude)
            else:
                include, exclude = None, None
            stats = _walk_root(ctx, w, scan_root_id=str(root["scan_root_id"]), root_type=rtype,
                               config_id=cid, root_path=root["absolute_path"],
                               cross_mounts=root["cross_mounts"], include=include, exclude=exclude)
        with conn.transaction():
            conn.execute("""UPDATE scan_root SET discovery_completed_at = now(), regular_file_count = %s,
                            directory_count = %s, symlink_skipped_count = %s, other_skipped_count = %s,
                            undecodable_skipped_count = %s WHERE scan_root_id = %s""",
                         (stats.files, stats.dirs, stats.symlinks, stats.other, stats.undecodable,
                          str(root["scan_root_id"])))
        summary[f"{rtype}:{cid}"] = {"files": stats.files, "dirs": stats.dirs,
                                     "symlinks_skipped": stats.symlinks, "other_skipped": stats.other,
                                     "undecodable_skipped": stats.undecodable,
                                     "unreadable_directories": stats.unreadable_dirs}
        log.info("discovered %s:%s files=%d dirs=%d symlinks_skipped=%d", rtype, cid, stats.files,
                 stats.dirs, stats.symlinks, extra={"run_id": run_id})
    with conn.transaction():
        A.append_event(conn, run_id, A.EventSpec(
            uuid.UUID(str(ctx.run["run_trace_id"])), "DISCOVERY_COMPLETE", "migrator", C.SRC_PYTHON,
            {"roots": summary}))
        db.transition(conn, run_id, C.DISCOVERY_COMPLETE)
    return summary


def _sig_changed(row: dict, res: HashResult) -> bool:
    return res.signature is not None and res.signature != (row["st_dev"], row["st_ino"],
                                                            row["size_bytes"], row["mtime_ns"])


def hash_inventory(ctx: RunContext, *, hasher: Callable[..., HashResult] = hash_file) -> dict:
    """Pass B.  Hash every regular file in SOURCE and TARGET inventories."""
    conn, cfg, run_id = ctx.conn, ctx.cfg, ctx.run_id
    db.require_state(ctx.refresh(), C.DISCOVERY_COMPLETE, C.HASHING)
    with conn.transaction():
        db.transition(conn, run_id, C.HASHING)
    ck = cfg["inventory"]["checksum"]
    block, retries, workers = ck["read_block_mib"] * 1024 * 1024, ck["stability_retries"], ck["workers"]
    # Hardlinked source files are terminal without a hash: emit their event once.
    with conn.transaction():
        rows = conn.execute(
            """SELECT f.file_id, f.trace_id, f.st_nlink FROM file_inventory f
               WHERE f.run_id = %s AND f.hash_status = 'BLOCKED_HARDLINK'
                 AND NOT EXISTS (SELECT 1 FROM audit_event e WHERE e.trace_id = f.trace_id
                                 AND e.event_type = 'HASH_SKIPPED_HARDLINK')""", (run_id,)).fetchall()
        A.append_events(conn, run_id, [A.EventSpec(
            r["trace_id"], "HASH_SKIPPED_HARDLINK", "migrator", C.SRC_PYTHON,
            {"st_nlink": r["st_nlink"], "reason": "hardlinked source files are never migrated automatically"},
            file_id=r["file_id"]) for r in rows])
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            with conn.transaction():
                batch = conn.execute(
                    """SELECT file_id, trace_id, absolute_path, size_bytes, mtime_ns, st_dev, st_ino
                       FROM file_inventory WHERE run_id = %s AND hash_status IN ('PENDING','HASHING')
                       ORDER BY absolute_path LIMIT %s""", (run_id, HASH_CHUNK)).fetchall()
                if not batch:
                    break
                conn.execute("UPDATE file_inventory SET hash_status = 'HASHING' WHERE file_id = ANY(%s::uuid[])",
                             ([str(r["file_id"]) for r in batch],))
                A.append_events(conn, run_id, [A.EventSpec(
                    r["trace_id"], "FILE_HASH_STARTED", "migrator", C.SRC_PYTHON, {}, file_id=r["file_id"])
                    for r in batch])
            results = list(pool.map(lambda r: hasher(r["absolute_path"], block_size=block, retries=retries),
                                    batch))
            specs, updates = [], []
            for r, res in zip(batch, results):
                now = utc_now()
                if res.status == C.HASH_HASHED:
                    changed = _sig_changed(r, res)
                    dev, ino, size, mtime = res.signature
                    updates.append((res.sha256, C.HASH_HASHED, None, now, size, mtime, res.ctime_ns,
                                    dev, ino, str(r["file_id"])))
                    payload = {"sha256": res.sha256, "size_bytes": size, "attempts": res.attempts}
                    if changed:
                        payload["stat_changed_since_discovery"] = True
                    specs.append(A.EventSpec(r["trace_id"], "FILE_HASHED", "migrator", C.SRC_PYTHON,
                                             payload, file_id=r["file_id"]))
                else:
                    updates.append((None, res.status, res.error, now, r["size_bytes"], r["mtime_ns"],
                                    None, r["st_dev"], r["st_ino"], str(r["file_id"])))
                    etype = "HASH_UNSTABLE" if res.status == C.HASH_UNSTABLE else "HASH_FAILED"
                    specs.append(A.EventSpec(r["trace_id"], etype, "migrator", C.SRC_PYTHON,
                                             {"error": res.error, "attempts": res.attempts},
                                             file_id=r["file_id"]))
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.executemany(
                        """UPDATE file_inventory SET sha256 = %s, hash_status = %s, hash_error = %s,
                               hashed_at = %s, size_bytes = %s, mtime_ns = %s,
                               ctime_ns = COALESCE(%s, ctime_ns), st_dev = %s, st_ino = %s
                           WHERE file_id = %s""", updates)
                A.append_events(conn, run_id, specs)
            done += len(batch)
            log.info("hashed %d files so far", done, extra={"run_id": run_id})
    with conn.transaction():
        conn.execute("""UPDATE scan_root sr SET
              hash_success_count = (SELECT count(*) FROM file_inventory f WHERE f.scan_root_id = sr.scan_root_id AND f.hash_status = 'HASHED'),
              hash_failure_count = (SELECT count(*) FROM file_inventory f WHERE f.scan_root_id = sr.scan_root_id AND f.hash_status IN ('FAILED','UNSTABLE'))
              WHERE sr.run_id = %s""", (run_id,))
        pending = conn.execute("SELECT count(*) AS n FROM file_inventory WHERE run_id = %s "
                               "AND hash_status IN ('PENDING','HASHING')", (run_id,)).fetchone()["n"]
        if pending:
            raise InventoryError(f"{pending} files have not reached a terminal hash state")
        A.append_event(conn, run_id, A.EventSpec(
            uuid.UUID(str(ctx.run["run_trace_id"])), "INVENTORY_COMPLETE", "migrator", C.SRC_PYTHON, {}))
        db.transition(conn, run_id, C.INVENTORY_COMPLETE)
    return {"hashed_this_invocation": done}


# --- manifests --------------------------------------------------------------------------

def _esc(v: object) -> str:
    return ("" if v is None else str(v)).replace("\\", "\\\\").replace("\t", "\\t")


def manifest_bytes(ctx: RunContext, root_type: str) -> bytes:
    """Deterministic gzip of NUL-terminated, TAB-separated records (tabs and
    backslashes inside fields are backslash-escaped; newlines are safe)."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=6) as gz:
        gz.write(("\t".join(MANIFEST_FIELDS)).encode() + b"\0")
        with ctx.conn.transaction(), ctx.conn.cursor(name=f"manifest_{root_type.lower()}") as cur:
            cur.itersize = 5000
            cur.execute("""SELECT f.trace_id, r.config_id AS root_id, f.relative_path, f.absolute_path,
                                  f.size_bytes, f.mtime_ns, f.st_dev, f.st_ino, f.st_nlink, f.sha256,
                                  f.hash_status
                           FROM file_inventory f JOIN scan_root r USING (scan_root_id)
                           WHERE f.run_id = %s AND f.root_type = %s
                           ORDER BY f.absolute_path COLLATE "C" """, (ctx.run_id, root_type))
            for row in cur:
                rec = "\t".join(_esc(row[k]) for k in MANIFEST_FIELDS)
                gz.write(rec.encode("utf-8") + b"\0")
    return buf.getvalue()


def write_manifests(ctx: RunContext) -> dict[str, str]:
    out: dict[str, str] = {}
    for rtype in (C.ROOT_SOURCE, C.ROOT_TARGET):
        stem = rtype.lower() + "-manifest"
        gz_path, sha_path = ctx.path(f"{stem}.tsv0.gz"), ctx.path(f"{stem}.sha256")
        if gz_path.exists():
            digest = sha256_hex(gz_path.read_bytes())
            out[rtype] = digest
            continue
        data = manifest_bytes(ctx, rtype)
        digest = sha256_hex(data)
        write_new_file(gz_path, data, guard=ctx.guard)
        write_new_file(sha_path, f"{digest}  {gz_path.name}\n".encode(), guard=ctx.guard)
        out[rtype] = digest
    return out


def _unesc(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append("\t" if s[i + 1] == "t" else s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def read_manifest(path: str | os.PathLike) -> Iterator[dict[str, str]]:
    """Parse a manifest produced by `write_manifests`."""
    with gzip.open(path, "rb") as f:
        raw = f.read()
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    header = records[0].decode().split("\t")
    for rec in records[1:]:
        fields = []
        for part in rec.decode("utf-8").split("\t"):
            fields.append(_unesc(part))
        yield dict(zip(header, fields))


def run_inventory(ctx: RunContext, *, hasher: Callable[..., HashResult] = hash_file) -> dict:
    """discovery -> hashing -> manifests; resumable at hashing."""
    state = ctx.refresh()["state"]
    result: dict = {}
    if state == C.CREATED:
        result["discovery"] = discover(ctx)
        state = C.DISCOVERY_COMPLETE
    elif state == C.DISCOVERING:
        raise InventoryError("discovery was interrupted; create a new run (discovery is not resumable)")
    if state in (C.DISCOVERY_COMPLETE, C.HASHING):
        result["hashing"] = hash_inventory(ctx, hasher=hasher)
        state = C.INVENTORY_COMPLETE
    result["manifests"] = write_manifests(ctx)
    return result
