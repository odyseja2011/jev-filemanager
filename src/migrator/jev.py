"""Jev 1.13 (OpenRouter Decisions API) client and request construction.

Jev receives *names only*: file names, directory names and path components.
Never file bytes, hashes, sizes, dates, ownership/ACLs or media metadata.

NOTE: the request/response shape below follows the project specification
(`state` + `questions.route` of type `choice`; response `answers.route.choice`,
`.probabilities`, `.confidence`).  It could not be cross-checked against the
provider documentation from the build environment (egress to openrouter.ai was
blocked) — see README "Known gaps".
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import httpx

from migrator.constants import DESCEND, REVIEW

DIRECTORY_INSTRUCTIONS = (
    "Choose the single destination category that applies to this entire directory subtree. "
    "Choose DESCEND when the directory is mixed, ambiguous, contains content belonging to "
    "different destinations, or its children need separate classification."
)
DESCEND_DESCRIPTION = ("Do not route the directory as one subtree. Inspect its files and "
                       "child directories separately.")
FILE_INSTRUCTIONS = ("Choose the single destination category for this file, judging only by the "
                     "file name and the names of the directories that contain it. Choose REVIEW "
                     "when the destination cannot be determined safely from those names.")
REVIEW_DESCRIPTION = ("The destination cannot be determined safely from the file and directory "
                      "names provided.")


class JevError(Exception):
    """Classification API call failed (after bounded retries) or answered invalidly."""

    def __init__(self, message: str, *, retryable: bool = False, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


@dataclass
class JevResponse:
    choice: str
    confidence: float
    probabilities: dict[str, float] | None
    returned_model: str | None
    request_id: str | None
    usage: dict[str, Any] | None
    raw: dict[str, Any] = field(default_factory=dict)


class JevClient(Protocol):
    def decide(self, request: dict[str, Any]) -> JevResponse: ...


# --- request construction -----------------------------------------------------------

def directory_question(targets: dict[str, str]) -> dict[str, Any]:
    criteria = dict(targets)
    criteria[DESCEND] = DESCEND_DESCRIPTION
    return {"type": "choice", "instructions": DIRECTORY_INSTRUCTIONS, "criteria": criteria}


def file_question(targets: dict[str, str]) -> dict[str, Any]:
    criteria = dict(targets)
    criteria[REVIEW] = REVIEW_DESCRIPTION
    return {"type": "choice", "instructions": FILE_INSTRUCTIONS, "criteria": criteria}


def build_request(model: str, state: dict[str, Any], question: dict[str, Any]) -> dict[str, Any]:
    return {"model": model, "state": state, "questions": {"route": question}}


# --- HTTP client ----------------------------------------------------------------------

def _valid_probabilities(p: Any, criteria: set[str]) -> dict[str, float] | None:
    if p is None:
        return None
    if isinstance(p, dict) and all(isinstance(v, (int, float)) for v in p.values()):
        return {str(k): float(v) for k, v in p.items()}
    raise JevError("probabilities in the response are malformed")


def parse_response(body: Any, request: dict[str, Any], headers: Any = None) -> JevResponse:
    criteria = set(request["questions"]["route"]["criteria"])
    try:
        route = body["answers"]["route"]
        choice, confidence = route["choice"], route["confidence"]
    except (KeyError, TypeError) as exc:
        raise JevError(f"response lacks answers.route.choice/confidence: {exc!r}") from exc
    if choice not in criteria:
        raise JevError(f"Jev returned a choice outside the configured criteria: {choice!r}")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) \
            or not (0.0 <= float(confidence) <= 1.0):
        raise JevError(f"invalid confidence in response: {confidence!r}")
    probs = _valid_probabilities(route.get("probabilities"), criteria)
    req_id = body.get("id") if isinstance(body, dict) else None
    if req_id is None and headers is not None:
        req_id = headers.get("x-request-id") or headers.get("x-generation-id")
    return JevResponse(choice=choice, confidence=float(confidence), probabilities=probs,
                       returned_model=body.get("model") if isinstance(body, dict) else None,
                       request_id=None if req_id is None else str(req_id),
                       usage=body.get("usage") if isinstance(body, dict) else None, raw=body)


class OpenRouterJevClient:
    """Bounded retries with exponential backoff and jitter for timeouts, HTTP 429,
    HTTP 5xx and transient network errors.  No fallback model, ever."""

    def __init__(self, *, endpoint: str, api_key: str, timeout: float = 30.0, retries: int = 3,
                 backoff_base: float = 1.0, sleep: Callable[[float], None] = time.sleep,
                 rng: random.Random | None = None, transport: httpx.BaseTransport | None = None):
        if not api_key:
            raise JevError("OpenRouter API key is empty")
        self.endpoint = endpoint
        self.retries = retries
        self.backoff_base = backoff_base
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._http = httpx.Client(timeout=timeout, transport=transport, headers={
            "Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})

    @classmethod
    def from_config(cls, cfg) -> "OpenRouterJevClient":
        o = cfg["openrouter"]
        key = os.environ.get(o["api_key_env"], "")
        if not key:
            raise JevError(f"environment variable {o['api_key_env']} is not set")
        return cls(endpoint=o["endpoint"], api_key=key, timeout=float(o["timeout_seconds"]),
                   retries=int(o["retries"]))

    def close(self) -> None:
        self._http.close()

    def _delay(self, attempt: int) -> float:
        return self.backoff_base * (2 ** attempt) * (0.5 + self._rng.random())

    def decide(self, request: dict[str, Any]) -> JevResponse:
        last = "unknown error"
        for attempt in range(self.retries + 1):
            try:
                r = self._http.post(self.endpoint, json=request)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = f"{type(exc).__name__}"
            else:
                if r.status_code == 429 or r.status_code >= 500:
                    last = f"HTTP {r.status_code}"
                elif r.status_code >= 400:
                    raise JevError(f"HTTP {r.status_code}: {r.text[:300]}", status_code=r.status_code)
                else:
                    try:
                        body = r.json()
                    except ValueError as exc:
                        raise JevError(f"response is not JSON: {exc}") from exc
                    return parse_response(body, request, r.headers)
            if attempt < self.retries:
                self._sleep(self._delay(attempt))
        raise JevError(f"giving up after {self.retries + 1} attempts: {last}", retryable=True)
