# core/eval_log.py
"""
Append only JSONL logging for every scan run.

Each run produces one line with a run UUID, timestamp, target, model, the
resilience score, and per probe outcomes. This gives the project an auditable
history of how a model's security posture changes over time, which is exactly
what a governance reviewer or a CI pipeline wants.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .scoring import Scorecard

_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
_LOG_FILE = _LOG_DIR / "scan_log.jsonl"


def log_run(scorecard: Scorecard, catalog: str = "config/attacks.yaml") -> str:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    record = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": scorecard.target_name,
        "model": scorecard.model,
        "catalog": catalog,
        "resilience": scorecard.resilience,
        "grade": scorecard.grade,
        "total_probes": scorecard.total_probes,
        "vulnerabilities": scorecard.vulnerabilities,
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
            for r in scorecard.results
        ],
    }
    with _LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return run_id
