import httpx
import pytest

from migrator.jev import (JevError, OpenRouterJevClient, build_request, directory_question, file_question,
                          parse_response)

TARGETS = {"MOVIES": "films", "MUSIC": "songs"}
REQ = build_request("typesafe/jev-1.13", {"file_name": "x.mkv", "ancestor_names": []}, file_question(TARGETS))


def ok_body(choice="MOVIES", conf=0.97):
    return {"id": "gen-1", "model": "typesafe/jev-1.13-20260101",
            "answers": {"route": {"choice": choice, "confidence": conf,
                                  "probabilities": {"MOVIES": 0.9, "MUSIC": 0.05, "REVIEW": 0.05}}},
            "usage": {"total_tokens": 10}}


def client(handler, retries=3):
    sleeps = []
    c = OpenRouterJevClient(endpoint="https://example.test/decisions", api_key="k-secret", retries=retries,
                            sleep=sleeps.append, transport=httpx.MockTransport(handler))
    c.sleeps = sleeps
    return c


def test_parses_choice_confidence_probabilities_model_id_usage():
    r = client(lambda req: httpx.Response(200, json=ok_body())).decide(REQ)
    assert (r.choice, r.confidence) == ("MOVIES", 0.97)
    assert r.probabilities["MOVIES"] == 0.9
    assert r.returned_model == "typesafe/jev-1.13-20260101"      # snapshot differs from the alias
    assert r.request_id == "gen-1" and r.usage == {"total_tokens": 10}
    assert r.raw["answers"]["route"]["choice"] == "MOVIES"       # full response kept


def test_request_shape_and_auth_header():
    seen = {}

    def handler(req):
        seen["json"] = req.read()
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(200, json=ok_body())

    client(handler).decide(REQ)
    import json
    body = json.loads(seen["json"])
    assert set(body) == {"model", "state", "questions"}
    q = body["questions"]["route"]
    assert q["type"] == "choice" and set(q["criteria"]) == {"MOVIES", "MUSIC", "REVIEW"}
    assert seen["auth"] == "Bearer k-secret"


def test_directory_question_offers_descend_file_question_offers_review():
    assert "DESCEND" in directory_question(TARGETS)["criteria"]
    assert "REVIEW" not in directory_question(TARGETS)["criteria"]
    assert "REVIEW" in file_question(TARGETS)["criteria"]
    assert "DESCEND" not in file_question(TARGETS)["criteria"]


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_retries_then_succeeds(status):
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(status) if len(calls) < 3 else httpx.Response(200, json=ok_body())

    c = client(handler)
    assert c.decide(REQ).choice == "MOVIES"
    assert len(calls) == 3 and len(c.sleeps) == 2
    assert c.sleeps[1] > 0


def test_backoff_is_exponential_with_jitter():
    def handler(req):
        return httpx.Response(503)

    c = client(handler, retries=3)
    with pytest.raises(JevError):
        c.decide(REQ)
    assert len(c.sleeps) == 3
    for i, s in enumerate(c.sleeps):
        assert 0.5 * 2 ** i <= s <= 1.5 * 2 ** i


def test_timeout_and_network_errors_are_retried_then_fail():
    calls = []

    def handler(req):
        calls.append(1)
        raise httpx.ConnectTimeout("t")

    c = client(handler, retries=2)
    with pytest.raises(JevError) as ei:
        c.decide(REQ)
    assert ei.value.retryable and len(calls) == 3


def test_client_errors_are_permanent_not_retried():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(400, text="bad request")

    with pytest.raises(JevError) as ei:
        client(handler).decide(REQ)
    assert len(calls) == 1 and not ei.value.retryable


@pytest.mark.parametrize("body", [
    {"answers": {}}, {"answers": {"route": {"choice": "NOPE", "confidence": 0.9}}},
    {"answers": {"route": {"choice": "MOVIES", "confidence": 1.5}}},
    {"answers": {"route": {"choice": "MOVIES", "confidence": "high"}}},
    {"answers": {"route": {"choice": "MOVIES", "confidence": True}}},
    {"answers": {"route": {"choice": "MOVIES", "confidence": 0.9, "probabilities": "x"}}},
])
def test_invalid_responses_are_rejected_not_guessed(body):
    with pytest.raises(JevError):
        parse_response(body, REQ)


def test_choice_outside_configured_criteria_is_rejected():
    with pytest.raises(JevError):
        parse_response(ok_body(choice="DESCEND"), REQ)     # file question has no DESCEND
