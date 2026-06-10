# core/integrations/pyrit_adapter.py
"""
PyRIT adapter.

PyRIT (https://github.com/Azure/PyRIT) is Microsoft's framework for automated,
multi-turn AI red teaming. This adapter lets the Range delegate a goal to PyRIT's
red teaming orchestrator and fold the resulting conversation back into the
Range's own AttackTranscript format, so a PyRIT driven attack reads the same as a
native agentic attack.

PyRIT typically needs Python 3.10 to 3.12, so install it in the integrations venv
(see requirements-integrations.txt). If PyRIT is missing, the entry points raise
IntegrationNotAvailable with setup guidance.

Note: PyRIT's public API evolves quickly. The orchestration call below follows
the RedTeamingOrchestrator pattern; verify class and argument names against the
PyRIT version you install, then adjust _run_orchestrator if needed.
"""
from __future__ import annotations

from core.orchestrator import AttackGoal, AttackTranscript, AttackTurn

from .base import IntegrationNotAvailable, is_module_available


def is_available() -> bool:
    return is_module_available("pyrit")


def _require_pyrit() -> None:
    if not is_available():
        raise IntegrationNotAvailable(
            "pyrit is not installed. Install it in the integrations venv "
            "(requirements-integrations.txt) to use this adapter."
        )


def _conversation_to_transcript(
    goal: AttackGoal,
    target_label: str,
    model: str,
    messages: list[dict],
    succeeded: bool,
) -> AttackTranscript:
    """
    Convert a flat list of PyRIT conversation messages into our AttackTranscript.
    Expects messages alternating attacker (assistant) and target (user/response)
    roles; we pair them into numbered turns.
    """
    turns: list[AttackTurn] = []
    attacker_prompt: str | None = None
    n = 0
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role in ("assistant", "attacker"):
            attacker_prompt = content
        elif role in ("user", "target", "response") and attacker_prompt is not None:
            n += 1
            turns.append(
                AttackTurn(
                    turn=n,
                    strategy="pyrit",
                    prompt=attacker_prompt,
                    response=content,
                    success=succeeded and msg is messages[-1],
                    rationale="PyRIT RedTeamingOrchestrator turn.",
                )
            )
            attacker_prompt = None

    return AttackTranscript(
        goal_id=goal.id,
        description=goal.description,
        owasp=goal.owasp,
        atlas=goal.atlas,
        target_name=f"pyrit:{target_label}",
        model=model,
        succeeded=succeeded,
        turns_used=len(turns),
        max_turns=len(turns),
        turns=turns,
    )


def run_pyrit_goal(
    goal: AttackGoal,
    target_model: str = "gpt-4o-mini",
    attacker_model: str = "gpt-4o-mini",
    max_turns: int = 5,
) -> AttackTranscript:
    """
    Pursue a goal using PyRIT's red teaming orchestrator and return an
    AttackTranscript. Requires PyRIT installed in the active environment.
    """
    _require_pyrit()
    return _run_orchestrator(goal, target_model, attacker_model, max_turns)


def _run_orchestrator(
    goal: AttackGoal,
    target_model: str,
    attacker_model: str,
    max_turns: int,
) -> AttackTranscript:
    """
    Thin wrapper over PyRIT. Isolated so the version specific calls live in one
    place. Adjust here if the installed PyRIT version renames these classes.
    """
    # Imported lazily so the module loads even when PyRIT is absent.
    from pyrit.orchestrator import RedTeamingOrchestrator
    from pyrit.prompt_target import OpenAIChatTarget
    from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion

    objective_target = OpenAIChatTarget(model_name=target_model)
    adversarial_chat = OpenAIChatTarget(model_name=attacker_model)

    scorer = SelfAskTrueFalseScorer(
        chat_target=adversarial_chat,
        true_false_question=TrueFalseQuestion(true_description=goal.description),
    )

    orchestrator = RedTeamingOrchestrator(
        objective_target=objective_target,
        adversarial_chat=adversarial_chat,
        objective_scorer=scorer,
        max_turns=max_turns,
    )

    result = orchestrator.run_attack(objective=goal.description)

    # Normalize whatever the orchestrator returns into a list of message dicts.
    messages = getattr(result, "conversation", None) or getattr(result, "messages", []) or []
    normalized = [
        {"role": getattr(m, "role", m.get("role", "")) if not isinstance(m, dict) else m.get("role", ""),
         "content": getattr(m, "content", m.get("content", "")) if not isinstance(m, dict) else m.get("content", "")}
        for m in messages
    ]
    succeeded = bool(getattr(result, "achieved_objective", False) or getattr(result, "success", False))

    return _conversation_to_transcript(goal, target_model, target_model, normalized, succeeded)
