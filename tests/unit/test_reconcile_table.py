import pytest

from migrator import constants as C
from migrator.reconcile import ABSENT, OTHER, REGULAR, classify_outcome

E, X = "e" * 64, "x" * 64


@pytest.mark.parametrize("src,tgt,s_sha,t_sha,expected", [
    (REGULAR, ABSENT, E, None, C.REC_NOT_EXECUTED),
    (ABSENT, REGULAR, None, E, C.REC_VERIFIED_MOVED),
    (REGULAR, REGULAR, E, E, C.REC_BOTH_PRESENT),
    (REGULAR, REGULAR, E, X, C.REC_TARGET_MISMATCH),
    (ABSENT, REGULAR, None, X, C.REC_TARGET_MISMATCH),
    (ABSENT, ABSENT, None, None, C.REC_BOTH_MISSING),
    (REGULAR, ABSENT, X, None, C.REC_SOURCE_CHANGED),
    (OTHER, ABSENT, None, None, C.REC_SOURCE_CHANGED),
    (ABSENT, OTHER, None, None, C.REC_TARGET_MISMATCH),
    (REGULAR, REGULAR, E, None, C.REC_TARGET_MISMATCH),     # target unreadable
])
def test_state_matrix(src, tgt, s_sha, t_sha, expected):
    assert classify_outcome(src, tgt, E, s_sha, t_sha) == expected


def test_success_requires_sha_not_just_presence():
    assert classify_outcome(ABSENT, REGULAR, E, None, X) != C.REC_VERIFIED_MOVED
