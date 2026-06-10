# cli.py
"""
Command line runner for the AI Red Team Range.

Examples:
    python cli.py --target mock
    python cli.py --target openai --model gpt-4o-mini
    python cli.py --target ollama --model llama3.1
    python cli.py --target mock --fail-under 80    # CI gate: exit 1 if weak

The mock target runs offline with no API key, so this works anywhere.
"""
from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.eval_log import log_run
from core.orchestrator import build_strategy, get_goal, run_goal
from core.probes import load_probes, run_all
from core.scoring import Scorecard, build_scorecard
from core.targets import build_target

load_dotenv()
console = Console()

_GRADE_COLOR = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}


def _render(scorecard: Scorecard) -> None:
    color = _GRADE_COLOR.get(scorecard.grade, "white")
    console.print(
        Panel.fit(
            f"[bold]{scorecard.target_name}[/bold]  model=[cyan]{scorecard.model}[/cyan]\n"
            f"Resilience Score: [bold {color}]{scorecard.resilience} / 100[/bold {color}]  "
            f"Grade: [bold {color}]{scorecard.grade}[/bold {color}]\n"
            f"Vulnerabilities: [red]{scorecard.vulnerabilities}[/red] of {scorecard.total_probes} probes",
            title="AI Red Team Range",
            border_style=color,
        )
    )

    table = Table(title="Probe Results", show_lines=False, header_style="bold")
    table.add_column("ID")
    table.add_column("Attack")
    table.add_column("OWASP")
    table.add_column("ATLAS")
    table.add_column("Sev")
    table.add_column("Result")

    for r in scorecard.results:
        if r.vulnerable:
            result = "[bold red]VULNERABLE[/bold red]"
        else:
            result = "[green]defended[/green]"
        table.add_row(
            r.probe.id,
            r.probe.name,
            r.probe.owasp,
            r.probe.atlas,
            r.probe.severity,
            result,
        )
    console.print(table)


def _render_transcript(t) -> None:
    color = "red" if t.succeeded else "green"
    outcome = "GOAL ACHIEVED" if t.succeeded else "TARGET HELD"
    console.print(
        Panel.fit(
            f"[bold]Goal:[/bold] {t.description}\n"
            f"Target: [cyan]{t.target_name}[/cyan]  model=[cyan]{t.model}[/cyan]  "
            f"attacker=[magenta]{t.turns[0].strategy if t.turns else 'n/a'}[/magenta]\n"
            f"OWASP: {t.owasp}   ATLAS: {t.atlas}\n"
            f"Outcome: [bold {color}]{outcome}[/bold {color}] in {t.turns_used} of {t.max_turns} turns",
            title="Agentic Attack Run",
            border_style=color,
        )
    )
    for turn in t.turns:
        mark = "[bold red]HIT[/bold red]" if turn.success else "[dim]miss[/dim]"
        console.print(f"[bold]Turn {turn.turn}[/bold] ({mark})")
        console.print(f"  [magenta]attacker[/magenta]: {turn.prompt}")
        console.print(f"  [cyan]target[/cyan]: {turn.response}")
        console.print(f"  [dim]{turn.rationale}[/dim]\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="AI Red Team Range scanner")
    parser.add_argument("--target", default="mock", help="mock | openai | ollama")
    parser.add_argument("--model", default=None, help="model name for the target")
    parser.add_argument("--catalog", default=None, help="path to attacks.yaml")
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        help="exit with code 1 if resilience is below this score (CI gate)",
    )
    parser.add_argument(
        "--goal",
        default=None,
        help="run the agentic multi-turn attacker for this goal id (see config/goals.yaml)",
    )
    parser.add_argument(
        "--attacker",
        default="scripted",
        help="attacker strategy for multi-turn mode: scripted | llm",
    )
    parser.add_argument("--max-turns", type=int, default=5, help="turn budget for multi-turn mode")
    parser.add_argument(
        "--integrations",
        action="store_true",
        help="report which optional engines (Garak, PyRIT) are available, then exit",
    )
    args = parser.parse_args()

    if args.integrations:
        from core.integrations import integration_status

        status = integration_status()
        table = Table(title="Optional Engine Integrations", header_style="bold")
        table.add_column("Engine")
        table.add_column("Available")
        for engine, available in status.items():
            mark = "[green]yes[/green]" if available else "[yellow]no (use 3.11 venv)[/yellow]"
            table.add_row(engine, mark)
        console.print(table)
        return 0

    # Multi-turn agentic mode
    if args.goal:
        target = build_target(args.target, model=args.model)
        goal = get_goal(args.goal)
        strategy = build_strategy(args.attacker, model=args.model)
        with console.status(f"Attacker pursuing goal {goal.id!r} against {target.name}..."):
            transcript = run_goal(target, goal, strategy=strategy, max_turns=args.max_turns)
        _render_transcript(transcript)
        return 1 if (transcript.succeeded and args.fail_under is not None) else 0

    # Full scan mode
    target = build_target(args.target, model=args.model)
    probes = load_probes(args.catalog)

    with console.status(f"Running {len(probes)} probes against {target.name}..."):
        results = run_all(target, probes)

    scorecard = build_scorecard(target.name, target.model, results)
    _render(scorecard)

    run_id = log_run(scorecard, catalog=args.catalog or "config/attacks.yaml")
    console.print(f"[dim]Logged run {run_id} to logs/scan_log.jsonl[/dim]")

    if args.fail_under is not None and scorecard.resilience < args.fail_under:
        console.print(
            f"[bold red]GATE FAILED:[/bold red] resilience {scorecard.resilience} "
            f"is below threshold {args.fail_under}."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
