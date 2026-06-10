# core/probes.py
"""
Loads the attack catalog and runs probes against a target.

A probe fires one or more adversarial prompts at the target and grades each
response with its detector. If any prompt succeeds, the probe is marked as a
vulnerability for that target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .detectors import detect
from .targets import Target

_DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "config" / "attacks.yaml"


@dataclass
class Probe:
    id: str
    name: str
    owasp: str
    atlas: str
    severity: str
    prompts: list[str]
    detector: dict


@dataclass
class ProbeResult:
    probe: Probe
    vulnerable: bool
    rationale: str
    sample_prompt: str
    sample_response: str
    attempts: int = 1
    details: list[dict] = field(default_factory=list)


def load_probes(catalog_path: str | Path | None = None) -> list[Probe]:
    path = Path(catalog_path) if catalog_path else _DEFAULT_CATALOG
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    probes = []
    for raw in data.get("probes", []):
        probes.append(
            Probe(
                id=raw["id"],
                name=raw["name"],
                owasp=raw.get("owasp", "Uncategorized"),
                atlas=raw.get("atlas", "N/A"),
                severity=raw.get("severity", "medium"),
                prompts=raw.get("prompts", []),
                detector=raw.get("detector", {"type": "string_match", "markers": []}),
            )
        )
    return probes


def run_probe(target: Target, probe: Probe) -> ProbeResult:
    """
    Fire every prompt in the probe. The probe is vulnerable if ANY prompt
    succeeds (one working attack is enough to fail the model).
    """
    details: list[dict] = []
    first_hit: tuple[str, str, str] | None = None

    for prompt in probe.prompts:
        resp = target.generate(prompt)
        verdict = detect(resp.text, probe.detector)
        details.append(
            {
                "prompt": prompt,
                "response": resp.text,
                "success": verdict.success,
                "rationale": verdict.rationale,
            }
        )
        if verdict.success and first_hit is None:
            first_hit = (prompt, resp.text, verdict.rationale)

    if first_hit:
        prompt, response, rationale = first_hit
        return ProbeResult(
            probe=probe,
            vulnerable=True,
            rationale=rationale,
            sample_prompt=prompt,
            sample_response=response,
            attempts=len(probe.prompts),
            details=details,
        )

    last = details[-1] if details else {"prompt": "", "response": "", "rationale": "no prompts"}
    return ProbeResult(
        probe=probe,
        vulnerable=False,
        rationale="Target defended against all prompts in this probe.",
        sample_prompt=last["prompt"],
        sample_response=last["response"],
        attempts=len(probe.prompts),
        details=details,
    )


def run_all(target: Target, probes: list[Probe]) -> list[ProbeResult]:
    return [run_probe(target, p) for p in probes]
