# External Engine Integrations (Garak and PyRIT)

The Range ships its own attack engine that runs on Python 3.14 with no external
dependencies. It can also orchestrate two industry standard red team engines as
extra probe sources:

- **Garak** (NVIDIA): a broad LLM vulnerability scanner.
- **PyRIT** (Microsoft): an automated multi-turn AI red teaming framework.

Both engines target Python 3.10 to 3.12 and may not import on newer interpreters,
so they are kept optional and isolated in a separate virtual environment. The
core Range never depends on them; the adapters import them lazily and fail with
clear guidance when they are absent.

## Why a separate environment

Your primary interpreter here is Python 3.14. Garak and PyRIT often lag new
Python releases. Rather than hold the whole project back, the adapters live
behind `core/integrations/` and you run them from a dedicated 3.11 environment.

## Setup

```bash
py -3.11 -m venv .venv-integrations
.venv-integrations\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-integrations.txt
```

Check what is available at any time:

```bash
python cli.py --integrations
```

## Garak

```python
from core.integrations.garak_adapter import scan_with_garak
from core.scoring import build_scorecard

results = scan_with_garak(
    model_type="openai",
    model_name="gpt-4o-mini",
    probes="promptinject,dan",
)
card = build_scorecard("garak:openai", "gpt-4o-mini", results)
print(card.resilience, card.grade)
```

The adapter runs garak as a subprocess, parses its JSONL report, maps each garak
probe family to an OWASP LLM Top 10 category, and returns standard `ProbeResult`
objects. That means garak findings flow into the same scorecard and the same
resilience score as the Range's native probes.

## PyRIT

```python
from core.integrations.pyrit_adapter import run_pyrit_goal
from core.orchestrator import get_goal

transcript = run_pyrit_goal(
    goal=get_goal("force-jailbreak"),
    target_model="gpt-4o-mini",
    attacker_model="gpt-4o-mini",
    max_turns=5,
)
print(transcript.succeeded, transcript.turns_used)
```

The adapter delegates the goal to PyRIT's red teaming orchestrator and converts
the resulting conversation into the Range's `AttackTranscript`, so a PyRIT driven
attack reads exactly like a native agentic attack.

> PyRIT's public API changes quickly. The adapter follows the
> RedTeamingOrchestrator pattern; if your installed version renames classes,
> adjust `_run_orchestrator` in `core/integrations/pyrit_adapter.py`. It is
> isolated there for exactly this reason.
