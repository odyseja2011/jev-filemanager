"""Optional live test against the real OpenRouter Decisions API (excluded from normal CI).

Run with:  OPENROUTER_API_KEY=... pytest -m live_jev
It validates the request/response assumptions in migrator/jev.py against the real service.
"""
import os

import pytest

from migrator.jev import OpenRouterJevClient, build_request, directory_question, file_question

pytestmark = [pytest.mark.live_jev,
              pytest.mark.skipif(not os.environ.get("OPENROUTER_API_KEY"), reason="OPENROUTER_API_KEY not set")]

TARGETS = {"MOVIES": "Movies and feature-length live-action film content.",
           "MUSIC": "Music recordings, albums, discographies, soundtracks and individual songs.",
           "BOOKS": "Ebooks, books, comics, manga, light novels, manuals and other reading material."}


def client():
    return OpenRouterJevClient(endpoint=os.environ.get("OPENROUTER_ENDPOINT", "https://openrouter.ai/api/alpha/decisions"),
                               api_key=os.environ["OPENROUTER_API_KEY"], timeout=60, retries=2)


def test_live_file_decision():
    req = build_request("typesafe/jev-1.13", {"file_name": "Blade Runner 2049 (2017).mkv",
                                              "ancestor_names": ["MEDIA", "Old Downloads"]}, file_question(TARGETS))
    r = client().decide(req)
    assert r.choice in {*TARGETS, "REVIEW"} and 0.0 <= r.confidence <= 1.0
    assert r.returned_model


def test_live_directory_decision():
    state = {"current_directory": "FILMY", "ancestor_names": ["MEDIA", "MULTIMEDIA"],
             "child_directory_names": ["Alien", "Blade Runner", "Dune"],
             "file_names": ["Arrival (2016).mkv", "Interstellar (2014).mkv"]}
    r = client().decide(build_request("typesafe/jev-1.13", state, directory_question(TARGETS)))
    assert r.choice in {*TARGETS, "DESCEND"}
