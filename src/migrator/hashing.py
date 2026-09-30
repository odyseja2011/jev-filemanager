"""Streaming SHA-256 with stability detection.  Read-only on the hashed file."""

from __future__ import annotations

import hashlib
import os
import stat as statmod
from dataclasses import dataclass
from typing import Callable, IO

from migrator import constants as C

StatSig = tuple[int, int, int, int]  # (st_dev, st_ino, size, mtime_ns)


def stat_signature(st: os.stat_result) -> StatSig:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


@dataclass(frozen=True)
class HashResult:
    status: str                      # HASHED / FAILED / UNSTABLE
    sha256: str | None
    error: str | None
    attempts: int
    signature: StatSig | None        # stat signature the hash corresponds to
    ctime_ns: int | None = None


def open_nofollow(path: str) -> IO[bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags), "rb", buffering=0)


def hash_file(path: str, *, block_size: int = 8 * 1024 * 1024, retries: int = 2,
              lstat: Callable[[str], os.stat_result] = os.lstat,
              opener: Callable[[str], IO[bytes]] = open_nofollow) -> HashResult:
    """SHA-256 of `path`, re-hashing (up to `retries` extra times) if the file
    changes while being read.  `stat_before`/`stat_after` must agree on
    st_dev, st_ino, size and mtime_ns."""
    attempts = 0
    for _ in range(retries + 1):
        attempts += 1
        try:
            before = lstat(path)
            if not statmod.S_ISREG(before.st_mode):
                return HashResult(C.HASH_FAILED, None, "not a regular file", attempts, None)
            digest = hashlib.sha256()
            buf = bytearray(block_size)
            view = memoryview(buf)
            with opener(path) as fh:
                while True:
                    n = fh.readinto(buf)
                    if not n:
                        break
                    digest.update(view[:n])
            after = lstat(path)
        except OSError as exc:
            return HashResult(C.HASH_FAILED, None, f"{type(exc).__name__}: {exc}", attempts, None)
        if stat_signature(before) == stat_signature(after):
            return HashResult(C.HASH_HASHED, digest.hexdigest(), None, attempts,
                              stat_signature(after), after.st_ctime_ns)
    return HashResult(C.HASH_UNSTABLE, None, "file kept changing while being hashed",
                      attempts, None)
