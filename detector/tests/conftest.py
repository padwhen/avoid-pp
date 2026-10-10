from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from translation_guard.api import create_app
from translation_guard.config import Settings

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"


@pytest.fixture
def settings() -> Settings:
    return Settings(fail_initialisation=False)


@pytest.fixture
def client(settings: Settings):
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def broken_client():
    """A service whose detector fails to initialise."""
    with TestClient(create_app(Settings(fail_initialisation=True))) as c:
        yield c


def fixture(name: str) -> dict[str, Any]:
    path = CONTRACTS / "fixtures" / "valid" / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def valid_request() -> dict[str, Any]:
    return fixture("assessment-request.finnish-with-embedded-dutch.json")
