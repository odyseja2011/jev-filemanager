"""Deterministic fake Jev client for tests (never used by production code)."""
from __future__ import annotations

import copy
import threading
from typing import Any, Callable

from migrator.jev import JevError, JevResponse


class FakeJev:
    """rules(state, question) -> (choice, confidence) | JevError | None (-> REVIEW/DESCEND@0.5)."""

    def __init__(self, rules: Callable[[dict, dict], Any], model: str = "typesafe/jev-1.13-2026-01-01"):
        self.rules = rules
        self.model = model
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def decide(self, request: dict[str, Any]) -> JevResponse:
        with self._lock:
            self.requests.append(copy.deepcopy(request))
        state, q = request["state"], request["questions"]["route"]
        out = self.rules(state, q)
        if isinstance(out, JevError):
            raise out
        choice, conf = out
        assert choice in q["criteria"], f"fake returned {choice!r} outside criteria"
        crit = list(q["criteria"])
        probs = {c: (conf if c == choice else round((1 - conf) / max(len(crit) - 1, 1), 6)) for c in crit}
        body = {"id": f"req-{len(self.requests)}", "model": self.model,
                "answers": {"route": {"choice": choice, "confidence": conf, "probabilities": probs}},
                "usage": {"total_tokens": 42}}
        return JevResponse(choice, conf, probs, self.model, body["id"], body["usage"], body)

    @property
    def directory_requests(self):
        return [r for r in self.requests if "current_directory" in r["state"]]

    @property
    def file_requests(self):
        return [r for r in self.requests if "file_name" in r["state"]]


def standard_rules(state: dict, question: dict):
    """Name-based rules used by the fixtures (these live in the TEST, not in the product)."""
    if "current_directory" in state:
        table = {
            "MULTIMEDIA": ("DESCEND", 0.9), "FILMY": ("MOVIES", 0.97), "SERIALE": ("SERIES", 0.95),
            "Unsorted": ("DESCEND", 0.8), "Lowconf": ("MUSIC", 0.6),
        }
        return table.get(state["current_directory"], ("DESCEND", 0.5))
    name = state["file_name"].lower()
    if name.endswith(".epub"):
        return ("BOOKS", 0.99)
    if "blade" in name:
        return ("MOVIES", 0.95)
    if name.endswith(".mp3"):
        return ("MUSIC", 0.93)
    if "maybe" in name:
        return ("MOVIES", 0.5)
    return ("REVIEW", 0.9)
