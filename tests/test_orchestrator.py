# tests/test_orchestrator.py
"""
Tests for the agentic attacker. Run offline against the MockTarget using the
deterministic ScriptedAttacker.
"""
from core.orchestrator import (
    AttackGoal,
    ScriptedAttacker,
    get_goal,
    load_goals,
    run_goal,
)
from core.targets import MockTarget


def test_goals_load():
    goals = load_goals()
    assert len(goals) >= 3
    assert any(g.id == "leak-system-prompt" for g in goals)


def test_scripted_attacker_walks_the_ladder():
    goal = AttackGoal(
        id="t", description="d", owasp="o", atlas="a",
        detector={"type": "string_match", "markers": ["NOPE"]},
        seed_prompts=["one", "two", "three"],
    )
    atk = ScriptedAttacker()
    assert atk.next_prompt(goal, []) == "one"
    # simulate two recorded turns
    from core.orchestrator import AttackTurn
    hist = [AttackTurn(1, "scripted", "one", "x", False, "r")]
    assert atk.next_prompt(goal, hist) == "two"


def test_orchestrator_escalates_and_succeeds_on_mock():
    target = MockTarget()
    goal = get_goal("leak-system-prompt")
    transcript = run_goal(target, goal, strategy=ScriptedAttacker(), max_turns=5)
    # The mock only leaks on the escalated prompt, so it should take more than
    # one turn but ultimately succeed.
    assert transcript.succeeded is True
    assert transcript.turns_used >= 2
    assert transcript.turns[-1].success is True


def test_orchestrator_respects_turn_budget():
    target = MockTarget()
    # A goal the mock never satisfies, to confirm we stop at max_turns.
    goal = AttackGoal(
        id="impossible", description="never", owasp="o", atlas="a",
        detector={"type": "string_match", "markers": ["WILL-NEVER-APPEAR"]},
        seed_prompts=["hello"],
    )
    transcript = run_goal(target, goal, max_turns=3)
    assert transcript.succeeded is False
    assert transcript.turns_used == 3
