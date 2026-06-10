# tests/test_api.py
"""
API tests using FastAPI's TestClient. Run offline against the mock target.
"""
import pytest
from fastapi.testclient import TestClient

import api
from core.orchestrator import load_goals
from core.probes import load_probes

client = TestClient(api.app)

_PROBE_COUNT = len(load_probes())
_GOAL_COUNT = len(load_goals())


@pytest.fixture(autouse=True)
def _dev_mode_auth(monkeypatch):
    """
    Neutralize any ambient RANGE_API_KEY (for example from a local .env) so the
    default tests run in development mode without needing a header. Auth
    enforcement is verified separately in test_auth_enforced_when_key_set.
    """
    monkeypatch.setenv("RANGE_API_KEY", "")
    yield


def test_health_is_public():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_returns_scorecard_and_gate():
    r = client.post("/scan", json={"target": "mock", "fail_under": 80})
    assert r.status_code == 200
    data = r.json()
    assert 0.0 <= data["resilience"] <= 100.0
    assert data["grade"] in {"A", "B", "C", "D", "F"}
    assert data["gate_passed"] is False  # the mock is weak
    assert len(data["probes"]) == _PROBE_COUNT


def test_attack_runs_multi_turn():
    r = client.post("/attack", json={"target": "mock", "goal": "extract-pii", "max_turns": 5})
    assert r.status_code == 200
    data = r.json()
    assert data["succeeded"] is True
    assert data["turns_used"] >= 1


def test_unknown_target_is_rejected():
    r = client.post("/scan", json={"target": "does-not-exist"})
    assert r.status_code == 400


def test_unknown_goal_is_rejected():
    r = client.post("/attack", json={"target": "mock", "goal": "nope"})
    assert r.status_code == 400


def test_catalog_endpoints():
    assert len(client.get("/probes").json()) == _PROBE_COUNT
    assert len(client.get("/goals").json()) == _GOAL_COUNT


def test_auth_enforced_when_key_set(monkeypatch):
    """When RANGE_API_KEY is set, protected endpoints require the header."""
    monkeypatch.setenv("RANGE_API_KEY", "secret123")
    # Missing key is rejected.
    assert client.get("/probes").status_code == 401
    # Correct key is accepted.
    ok = client.get("/probes", headers={"X-API-Key": "secret123"})
    assert ok.status_code == 200
    # Health stays public regardless.
    assert client.get("/health").status_code == 200
