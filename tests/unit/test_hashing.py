import hashlib
import os

from migrator import constants as C
from migrator.hashing import hash_file, open_nofollow

KNOWN = hashlib.sha256(b"abc").hexdigest()


def test_known_sha256_fixture(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    assert KNOWN == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    r = hash_file(str(p), block_size=2)
    assert (r.status, r.sha256, r.attempts) == (C.HASH_HASHED, KNOWN, 1)


def test_empty_and_sparse_files(tmp_path):
    e = tmp_path / "empty"
    e.write_bytes(b"")
    assert hash_file(str(e)).sha256 == hashlib.sha256(b"").hexdigest()
    s = tmp_path / "sparse"
    with open(s, "wb") as f:
        f.truncate(64 * 1024 * 1024)
    assert hash_file(str(s), block_size=4 * 1024 * 1024).sha256 == \
        hashlib.sha256(bytes(64 * 1024 * 1024)).hexdigest()


def _mutating_opener(path_to_mutate, times):
    """Opener that modifies the file mid-read for the first `times` opens."""
    state = {"n": 0}

    def opener(path):
        state["n"] += 1
        fh = open_nofollow(path)
        if state["n"] <= times:
            with open(path_to_mutate, "ab") as w:
                w.write(b"x")
            ns = 1_000_000_000 * state["n"]
            os.utime(path_to_mutate, ns=(ns, ns))
        return fh

    return opener


def test_retry_succeeds_when_file_settles(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    r = hash_file(str(p), retries=2, opener=_mutating_opener(p, 1))
    assert r.status == C.HASH_HASHED and r.attempts == 2
    assert r.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()


def test_retries_exhausted_is_unstable(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    r = hash_file(str(p), retries=2, opener=_mutating_opener(p, 99))
    assert r.status == C.HASH_UNSTABLE and r.sha256 is None and r.attempts == 3


def test_unreadable_file_fails(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")

    def denied(path):
        raise PermissionError(13, "Permission denied")

    r = hash_file(str(p), opener=denied)
    assert r.status == C.HASH_FAILED and "PermissionError" in r.error


def test_symlink_is_not_hashed(tmp_path):
    t = tmp_path / "t"
    t.write_bytes(b"x")
    link = tmp_path / "l"
    link.symlink_to(t)
    assert hash_file(str(link)).status == C.HASH_FAILED


def test_missing_file_fails(tmp_path):
    assert hash_file(str(tmp_path / "nope")).status == C.HASH_FAILED
