# api.py
"""
REST service for the AI Red Team Range.

Exposes the scanner and the agentic attacker over HTTP so they can run inside CI
pipelines, platform gates, and other services.

Auth: every endpoint except /health requires an X-API-Key header matching the
RANGE_API_KEY environment variable. If RANGE_API_KEY is unset the service runs in
development mode (auth disabled) and warns, mirroring the convention used across
the rest of the toolchain.

Run:
    uvicorn api:app --reload
    # docs at http://localhost:8000/docs

Example:
    curl -X POST http://localhost:8000/scan \
         -H "X-API-Key: change-me" -H "Content-Type: application/json" \
         -d '{"target": "mock", "fail_under": 80}'
"""
from __future__ import annotations

import os
import warnings

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from core.eval_log import log_run
from core.orchestrator import build_strategy, get_goal, load_goals, run_goal
from core.probes import load_probes, run_all
from core.scoring import Scorecard, build_scorecard
from core.targets import build_target

load_dotenv()

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_API_KEY_NAME = "X-API-Key"
_api_key_header = APIKeyHeader(name=_API_KEY_NAME, auto_error=False)


def _require_key(api_key: str = Security(_api_key_header)) -> str:
    expected = os.getenv("RANGE_API_KEY", "").strip()
    if not expected:
        warnings.warn(
            "RANGE_API_KEY is not set; authentication is disabled (development mode).",
            stacklevel=2,
        )
        return "dev-mode"
    if api_key == expected:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Provide a valid X-API-Key header.",
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Red Team Range API",
    description=(
        "Attack LLM targets, score their resilience against the OWASP LLM Top 10 "
        "and MITRE ATLAS, and gate unsafe models in CI. All endpoints except "
        "/health require an X-API-Key header."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str = "mock"
    model: str | None = None
    catalog: str | None = None
    fail_under: float | None = Field(
        default=None,
        description="If set, response includes gate_passed based on this threshold.",
    )


class AttackRequest(BaseModel):
    target: str = "mock"
    model: str | None = None
    goal: str = Field(..., description="Goal id from config/goals.yaml")
    attacker: str = "scripted"
    max_turns: int = 5


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def _scorecard_to_dict(card: Scorecard) -> dict:
    return {
        "target": card.target_name,
        "model": card.model,
        "resilience": card.resilience,
        "grade": card.grade,
        "total_probes": card.total_probes,
        "vulnerabilities": card.vulnerabilities,
        "by_owasp": {
            k: {"total": v.total, "vulnerable": v.vulnerable, "passed": v.passed}
            for k, v in card.by_owasp.items()
        },
        "by_severity": {
            k: {"total": v.total, "vulnerable": v.vulnerable, "passed": v.passed}
            for k, v in card.by_severity.items()
        },
        "probes": [
            {
                "id": r.probe.id,
                "name": r.probe.name,
                "owasp": r.probe.owasp,
                "atlas": r.probe.atlas,
                "severity": r.probe.severity,
                "vulnerable": r.vulnerable,
                "rationale": r.rationale,
            }
            for r in card.results
        ],
    }


# ---------------------------------------------------------------------------
# Public endpoint
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health() -> dict:
    return {"status": "ok", "version": app.version}


# ---------------------------------------------------------------------------
# Catalog endpoints
# ---------------------------------------------------------------------------

@app.get("/probes", tags=["Catalog"])
def list_probes(_key: str = Security(_require_key)) -> list[dict]:
    return [
        {
            "id": p.id,
            "name": p.name,
            "owasp": p.owasp,
            "atlas": p.atlas,
            "severity": p.severity,
        }
        for p in load_probes()
    ]


@app.get("/goals", tags=["Catalog"])
def list_goals(_key: str = Security(_require_key)) -> list[dict]:
    return [
        {"id": g.id, "description": g.description, "owasp": g.owasp, "atlas": g.atlas}
        for g in load_goals()
    ]


# ---------------------------------------------------------------------------
# Scan + attack
# ---------------------------------------------------------------------------

@app.post("/scan", tags=["Scan"])
def scan(req: ScanRequest, _key: str = Security(_require_key)) -> dict:
    """Run the full probe catalog against a target and return the scorecard."""
    try:
        target = build_target(req.target, model=req.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    probes = load_probes(req.catalog)
    results = run_all(target, probes)
    card = build_scorecard(target.name, target.model, results)
    run_id = log_run(card, catalog=req.catalog or "config/attacks.yaml")

    payload = _scorecard_to_dict(card)
    payload["run_id"] = run_id
    if req.fail_under is not None:
        payload["fail_under"] = req.fail_under
        payload["gate_passed"] = card.resilience >= req.fail_under
    return payload


@app.post("/attack", tags=["Attack"])
def attack(req: AttackRequest, _key: str = Security(_require_key)) -> dict:
    """Run the agentic multi-turn attacker against a target for one goal."""
    try:
        target = build_target(req.target, model=req.model)
        goal = get_goal(req.goal)
        strategy = build_strategy(req.attacker, model=req.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    transcript = run_goal(target, goal, strategy=strategy, max_turns=req.max_turns)
    return {
        "goal": transcript.goal_id,
        "description": transcript.description,
        "owasp": transcript.owasp,
        "atlas": transcript.atlas,
        "target": transcript.target_name,
        "model": transcript.model,
        "succeeded": transcript.succeeded,
        "turns_used": transcript.turns_used,
        "max_turns": transcript.max_turns,
        "turns": [
            {
                "turn": t.turn,
                "strategy": t.strategy,
                "prompt": t.prompt,
                "response": t.response,
                "success": t.success,
                "rationale": t.rationale,
            }
            for t in transcript.turns
        ],
    }
