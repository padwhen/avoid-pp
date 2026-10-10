"""C08-AC3: fake mode needs no API key, and readiness reflects initialisation."""

from __future__ import annotations

import os

from translation_guard.config import DetectorMode, Settings


def test_fake_mode_needs_no_api_key(monkeypatch):
    """A clean environment with no provider credentials must still work."""
    for key in list(os.environ):
        if "API_KEY" in key or "ANTHROPIC" in key or "OPENAI" in key:
            monkeypatch.delenv(key, raising=False)

    settings = Settings()
    assert settings.mode is DetectorMode.FAKE


def test_ready_when_initialisation_succeeds(client):
    assert client.get("/readyz").status_code == 200
    assert client.get("/readyz").json()["status"] == "ready"


def test_liveness_answers_regardless_of_readiness(broken_client):
    """Liveness is about the process, not its dependencies."""
    assert broken_client.get("/healthz").status_code == 200
    assert broken_client.get("/healthz").json()["status"] == "ok"


def test_not_ready_when_initialisation_fails(broken_client):
    """A detector that cannot start leaves the service live but NOT ready, so
    traffic is routed away rather than the process being killed and restarted
    into the same failure."""
    response = broken_client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_assessments_refused_while_not_ready(broken_client, valid_request):
    """The central rule: an unavailable detector never yields a clean verdict."""
    response = broken_client.post("/internal/v1/assessments", json=valid_request)
    assert response.status_code == 503

    body = response.json()
    assert "assessment" not in body
    assert body["error"]["code"] == "detector_unavailable"
    assert body["request_id"] == valid_request["request_id"]
