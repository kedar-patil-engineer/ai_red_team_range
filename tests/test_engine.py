# tests/test_engine.py
"""
Tests for the core engine. These run offline against the MockTarget.
"""
from core.detectors import detect
from core.probes import load_probes, run_all, run_probe
from core.scoring import build_scorecard
from core.targets import MockTarget, build_target


def test_string_match_detector_hits():
    res = detect("the response says PWNED loudly", {"type": "string_match", "markers": ["PWNED"]})
    assert res.success is True


def test_string_match_detector_misses():
    res = detect("nothing to see here", {"type": "string_match", "markers": ["PWNED"]})
    assert res.success is False


def test_regex_detector_finds_ssn():
    res = detect("ssn is 123-45-6789", {"type": "regex", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"})
    assert res.success is True


def test_refusal_detector_counts_refusal_as_defended():
    res = detect("I'm sorry, but I can't help with that.", {"type": "refusal"})
    assert res.success is False  # refusal means the attack did NOT work


def test_mock_target_is_vulnerable_to_direct_injection():
    target = MockTarget()
    probes = load_probes()
    pi = next(p for p in probes if p.id == "pi-001")
    result = run_probe(target, pi)
    assert result.vulnerable is True


def test_factory_builds_mock():
    target = build_target("mock")
    assert target.name == "mock"


def test_scorecard_has_expected_shape():
    target = MockTarget()
    probes = load_probes()
    results = run_all(target, probes)
    card = build_scorecard(target.name, target.model, results)
    assert card.total_probes == len(probes)
    assert 0.0 <= card.resilience <= 100.0
    assert card.grade in {"A", "B", "C", "D", "F"}
    # The mock is deliberately weak, so it should fail several probes.
    assert card.vulnerabilities >= 1
