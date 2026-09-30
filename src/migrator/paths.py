"""Path helpers, canonical serialization and guarded workspace writes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class PathSafetyError(ValueError):
    """A path escaped its allowed root or is otherwise unsafe."""


# --- canonical serialization ---------------------------------------------------

def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_time(dt: datetime) -> str:
    """Canonical UTC timestamp string with fixed microsecond precision."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_time(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


# --- containment ---------------------------------------------------------------

def is_within(path: str | os.PathLike, root: str | os.PathLike) -> bool:
    """True if `path` equals or is beneath `root` (purely lexical, normalized)."""
    p = os.path.normpath(os.fspath(path))
    r = os.path.normpath(os.fspath(root))
    if p == r:
        return True
    return p.startswith(r.rstrip(os.sep) + os.sep)


def roots_overlap(a: str, b: str) -> bool:
    return is_within(a, b) or is_within(b, a)


def safe_join(root: str, *parts: str) -> str:
    """Join `parts` beneath `root`, refusing anything that escapes it.

    Names are never altered: no sanitization, transliteration or renaming.
    """
    root_n = os.path.normpath(root)
    if not os.path.isabs(root_n):
        raise PathSafetyError(f"root is not absolute: {root!r}")
    for part in parts:
        if "\x00" in part:
            raise PathSafetyError("NUL byte in path component")
    joined = os.path.normpath(os.path.join(root_n, *parts))
    if joined == root_n or not is_within(joined, root_n):
        raise PathSafetyError(f"path {joined!r} escapes root {root_n!r}")
    return joined


def relative_to(path: str, root: str) -> str:
    """Relative path of `path` beneath `root` ('' when equal)."""
    p, r = os.path.normpath(path), os.path.normpath(root)
    if p == r:
        return ""
    if not is_within(p, r):
        raise PathSafetyError(f"{p!r} is not beneath {r!r}")
    return p[len(r.rstrip(os.sep)) + 1:]


def is_utf8_clean(s: str) -> bool:
    """False for names holding undecodable bytes (surrogateescape) — they cannot
    be stored in PostgreSQL text and are skipped and counted by the scanner."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return "\x00" not in s


# --- glob matching --------------------------------------------------------------

def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a `**`-aware glob (relative, '/' separated) into a regex."""
    i, n, out = 0, len(pattern), []
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 2)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.DOTALL)


class GlobSet:
    def __init__(self, patterns: Iterable[str]):
        self._res = [glob_to_regex(p) for p in patterns]

    def matches(self, rel: str) -> bool:
        return any(r.match(rel) for r in self._res)

    def __bool__(self) -> bool:
        return bool(self._res)


# --- guarded writes (workspace only) ---------------------------------------------

class WorkspaceGuard:
    """Only lets the application write beneath the workspace, never beneath a
    configured source or target root."""

    def __init__(self, workspace: str, forbidden_roots: Iterable[str]):
        self.workspace = os.path.normpath(workspace)
        self.forbidden = [os.path.normpath(r) for r in forbidden_roots]

    def check(self, path: str | os.PathLike) -> str:
        p = os.path.normpath(os.fspath(path))
        if not is_within(p, self.workspace):
            raise PathSafetyError(f"refusing to write outside workspace: {p}")
        for r in self.forbidden:
            if is_within(p, r):
                raise PathSafetyError(f"refusing to write beneath migration root {r}: {p}")
        return p


def fsync_dir(path: str | os.PathLike) -> None:
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new_file(path: str | os.PathLike, data: bytes, *, mode: int = 0o444,
                   guard: WorkspaceGuard | None = None) -> None:
    """Durably create `path` with `data`; fails if it already exists (immutable)."""
    if guard is not None:
        guard.check(path)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.link(tmp, p)  # fails with FileExistsError instead of overwriting
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    fsync_dir(p.parent)


def write_replaceable_file(path: str | os.PathLike, data: bytes,
                           guard: WorkspaceGuard | None = None) -> None:
    """For derived reports that are regenerated (summary.json, csv)."""
    if guard is not None:
        guard.check(path)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
