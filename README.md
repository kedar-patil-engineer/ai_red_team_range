# AI Red Team Range

[![AI Red Team Range](https://github.com/kedar-patil-engineer/ai_red_team_range/actions/workflows/redteam.yml/badge.svg)](https://github.com/kedar-patil-engineer/ai_red_team_range/actions/workflows/redteam.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-lightgrey)
![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red)

### An agentic platform that attacks LLMs, scores how they break, and gates unsafe models before they ship.

The Range fires a catalog of adversarial probes at any LLM endpoint, grades each
response, and produces a security scorecard mapped to the **OWASP LLM Top 10
(2025)** and **MITRE ATLAS**. It runs as a command line tool, a REST service, and
a dashboard, and it doubles as a **CI gate** that fails a build when a model is
too easy to break.

> Think of it as a penetration test for language models. Point it at a model,
> watch the scorecard light up, and ship only what survives.

## See it in action

The resilience scorecard, mapped to the OWASP LLM Top 10 and MITRE ATLAS:

![Resilience scorecard](assets/scorecard.png)

The agentic attacker pursuing a goal over multiple turns. It escalates and, on
turn three, extracts the target's hidden system prompt:

![Agentic multi turn attack](assets/attack.png)

---

## Why this exists

LLM applications now sit in front of real users, real data, and real tools. The
attacks that matter are no longer SQL injection and XSS alone. They are prompt
injection, jailbreaks, system prompt leakage, sensitive data disclosure, and
excessive agency. Security teams need a repeatable way to measure how exposed a
model is, track that posture over time, and block regressions automatically.

The Range gives security and platform teams that capability in one place.

---

## What it does

- **Attacks** any LLM target with a versioned catalog of adversarial probes.
- **Hunts adaptively** with an agentic attacker that pursues a goal over multiple
  turns, escalating its approach based on how the model replies. This is the
  difference between a static scanner and a red team that learns.
- **Grades** each response with pluggable detectors (string match, regex,
  refusal analysis, and an LLM judge).
- **Scores** the target with a single Resilience Score from 0 to 100, plus a
  letter grade, rolled up by OWASP category, MITRE ATLAS technique, and severity.
- **Logs** every run to append only JSONL so model security posture is auditable
  over time.
- **Gates** pipelines: a single flag makes the scan fail a build when resilience
  drops below a threshold.
- **Serves** over REST (FastAPI) and ships a dashboard (Streamlit).
- **Orchestrates** external engines: optional adapters fold **Garak** and
  **PyRIT** results into the same scorecard.

Surfaces: a command line tool (`cli.py`), a REST service (`api.py`), and a
dashboard (`app.py`), all driving the same engine.

---

## Coverage (OWASP LLM Top 10 2025 and MITRE ATLAS)

| Probe | OWASP category | MITRE ATLAS | Severity |
|---|---|---|---|
| Direct prompt injection | LLM01 Prompt Injection | AML.T0051 | high |
| Indirect prompt injection (poisoned document) | LLM01 Prompt Injection | AML.T0051 | critical |
| Payload splitting injection | LLM01 Prompt Injection | AML.T0051 | high |
| Jailbreak (persona override) | LLM01 Prompt Injection | AML.T0054 | high |
| Jailbreak (developer mode) | LLM01 Prompt Injection | AML.T0054 | high |
| System prompt leakage | LLM07 System Prompt Leakage | AML.T0051 | medium |
| Sensitive information disclosure | LLM02 Sensitive Information Disclosure | AML.T0057 | critical |
| Improper output handling | LLM05 Improper Output Handling | AML.T0051 | medium |
| Excessive agency | LLM06 Excessive Agency | AML.T0053 | high |
| Unbounded consumption | LLM10 Unbounded Consumption | AML.T0034 | medium |

The catalog lives in `config/attacks.yaml`. Adding a probe is a few lines of YAML,
no code change required. ATLAS technique ids should be validated against the live
matrix as it evolves.

---

## Quick start (no API key needed)

```bash
pip install -r requirements.txt
python cli.py --target mock
```

**On Windows**, double click `run.bat` for a menu (scan, attack, dashboard, API,
tests), or call a mode directly: `run.bat scan`, `run.bat attack`,
`run.bat dashboard`.

The `mock` target is a deliberately vulnerable model that runs offline at zero
cost, so the full pipeline and scorecard work on any machine. Example output:

```
+---------- AI Red Team Range -----------+
| mock  model=mock-vulnerable-1          |
| Resilience Score: 38.1 / 100  Grade: F |
| Vulnerabilities: 5 of 10 probes        |
+----------------------------------------+
```

### Scan a real model

```bash
# OpenAI
setx OPENAI_API_KEY sk-...        # or put it in .env
python cli.py --target openai --model gpt-4o-mini

# Local model via Ollama
python cli.py --target ollama --model llama3.1
```

### Use it as a CI gate

```bash
python cli.py --target openai --fail-under 80
# exits with code 1 if the model's resilience is below 80
```

Drop that into a GitHub Action and no model ships unless it clears the bar.

### Run the agentic attacker (multi-turn)

```bash
python cli.py --target mock --goal leak-system-prompt
python cli.py --target openai --goal force-jailbreak --attacker llm --max-turns 6
```

The attacker tries an approach, reads the reply, and escalates. Example against
the mock: it misses twice, then on turn 3 extracts the hidden system prompt.

### REST service and dashboard

```bash
uvicorn api:app --reload          # REST API, docs at http://localhost:8000/docs
python -m streamlit run app.py    # dashboard at http://localhost:8501
```

```bash
# scan over HTTP with the CI gate
curl -X POST http://localhost:8000/scan \
     -H "X-API-Key: change-me" -H "Content-Type: application/json" \
     -d '{"target": "mock", "fail_under": 80}'
```

### Optional external engines

```bash
python cli.py --integrations      # report Garak / PyRIT availability
```

See `docs/INTEGRATIONS.md` to wire in Garak and PyRIT from a Python 3.11 venv.

---

## Architecture

```
                 +------------------------+
                 |   Attack Catalog       |
                 |   config/attacks.yaml  |
                 +-----------+------------+
                             |
                             v
+----------+        +--------+--------+        +-----------------+
|  Target  | <----- |   Probe Runner  | -----> |    Detectors    |
| adapters |  send  |  core/probes.py |  grade | core/detectors  |
| (mock /  |  prompt|                 |        | (match, regex,  |
|  openai/ | -----> |                 | <----- |  refusal, judge)|
|  ollama) |  reply |                 | result |                 |
+----------+        +--------+--------+        +-----------------+
                             |
                             v
                    +--------+--------+        +-----------------+
                    | Scoring Engine  | -----> |   Eval Log      |
                    | core/scoring.py |        | JSONL per run   |
                    | OWASP + ATLAS   |        +-----------------+
                    | Resilience 0-100|
                    +--------+--------+
                             |
              +--------------+--------------+
              v              v              v
          CLI report    FastAPI scan    Streamlit
          (cli.py)      gate (api.py)   dashboard
```

The target layer is provider agnostic, so the same probe catalog runs against a
hosted model, a local model, or the offline mock without changes.

---

## Project structure

```
ai_red_team_range/
|
├── config/
│   ├── attacks.yaml          # versioned single shot probe catalog (OWASP + ATLAS)
│   └── goals.yaml            # multi-turn goal catalog for the agentic attacker
├── core/
│   ├── targets.py            # provider adapters: mock, OpenAI, Ollama
│   ├── probes.py             # load and run probes against a target
│   ├── detectors.py          # success detectors (match, regex, refusal, judge)
│   ├── orchestrator.py       # agentic multi-turn attacker (scripted + LLM)
│   ├── scoring.py            # Resilience Score + OWASP/ATLAS/severity rollups
│   ├── eval_log.py           # append only JSONL run logging
│   └── integrations/         # optional Garak / PyRIT adapters (lazy imports)
├── tests/                    # 22 offline tests against the mock target
├── docs/
│   └── INTEGRATIONS.md       # how to wire in Garak and PyRIT
├── cli.py                    # command line scanner, attacker, and CI gate
├── api.py                    # FastAPI REST service (API key auth)
├── app.py                    # Streamlit dashboard
├── requirements.txt          # core engine (Python 3.14 friendly)
└── requirements-integrations.txt  # optional Garak / PyRIT (separate 3.11 venv)
```

---

## Roadmap

The engine, the agentic attacker, the REST service, the dashboard, the Garak and
PyRIT adapters, and a GitHub Actions gate all run today. Next:

1. **PDF report**: a shareable security assessment for a given model.
2. **Expanded catalog**: more probes and goals across the full OWASP LLM Top 10.

---

## Author

**Kedar Patil**
Information Security and AI Governance | Securing Agentic AI, LLMs, and Gen AI Systems
Python | Zero Trust | Security Automation | OWASP LLM Top 10 | MITRE ATLAS

---

## License

Copyright (c) 2026 Kedar Patil. All rights reserved. This repository is shared as
a portfolio project for evaluation only; no reuse rights are granted. See
[LICENSE](LICENSE).
