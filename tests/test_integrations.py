# tests/test_integrations.py
"""
Tests for the optional engine adapters.

On Python 3.14 (the primary environment) garak and pyrit are not installed, so
these tests assert the graceful not-available behavior: status reports False and
the run entry points raise IntegrationNotAvailable rather than ImportError. The
modules must still import cleanly because the engine imports are lazy.
"""
import pytest

from core.integrations import IntegrationNotAvailable, integration_status
from core.integrations import garak_adapter, pyrit_adapter


def test_status_reports_both_engines():
    status = integration_status()
    assert set(status.keys()) == {"garak", "pyrit"}
    assert isinstance(status["garak"], bool)
    assert isinstance(status["pyrit"], bool)


def test_adapter_modules_import_without_engines():
    # The point: importing the adapters must not require the engines.
    assert hasattr(garak_adapter, "scan_with_garak")
    assert hasattr(pyrit_adapter, "run_pyrit_goal")


@pytest.mark.skipif(garak_adapter.is_available(), reason="garak is installed")
def test_garak_run_raises_when_absent():
    with pytest.raises(IntegrationNotAvailable):
        garak_adapter.run_garak("openai", "gpt-4o-mini")


@pytest.mark.skipif(pyrit_adapter.is_available(), reason="pyrit is installed")
def test_pyrit_run_raises_when_absent():
    from core.orchestrator import get_goal

    with pytest.raises(IntegrationNotAvailable):
        pyrit_adapter.run_pyrit_goal(get_goal("force-jailbreak"))


def test_garak_report_parsing_with_synthetic_data(tmp_path):
    # Verify the report parser without needing garak installed.
    report = tmp_path / "garak_run.report.jsonl"
    report.write_text(
        '{"entry_type": "eval", "probe": "promptinject.HijackHateHumans", '
        '"detector": "mitigation.MitigationBypass", "passed": 3, "total": 10}\n'
        '{"entry_type": "config", "ignored": true}\n',
        encoding="utf-8",
    )
    results = garak_adapter.parse_garak_report(report)
    assert len(results) == 1
    r = results[0]
    assert r.vulnerable is True            # 7 of 10 attempts got through
    assert "Prompt Injection" in r.probe.owasp
    assert r.probe.severity == "critical"  # 0.7 fail rate
