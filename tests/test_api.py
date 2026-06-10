# tests/test_api.py
"""
API tests using FastAPI's TestClient. Run offline against the mock target.
"""
from fastapi.testclient import TestClient

import api
from core.orchestrator import load_goals
from core.probes import load_probes

client = TestClient(api.app)

_PROBE_COUNT = len(load_probes())
_GOAL_COUNT = len(load_goals())


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
