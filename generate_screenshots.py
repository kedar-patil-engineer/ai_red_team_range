# generate_screenshots.py
"""
Renders polished, LinkedIn ready PNG images from the tool's REAL output:
  assets/scorecard.png   the resilience scorecard for the mock scan
  assets/attack.png      the agentic attack transcript (system prompt leak)

Run:  python generate_screenshots.py
Everything shown is produced by the actual engine, not mocked up by hand.
"""
from __future__ import annotations

import os
from PIL import Image, ImageDraw, ImageFont

from core.targets import MockTarget
from core.probes import load_probes, run_all
from core.scoring import build_scorecard
from core.orchestrator import get_goal, run_goal, ScriptedAttacker

# ---------------------------------------------------------------------------
# Theme (GitHub dark)
# ---------------------------------------------------------------------------
BG      = (13, 17, 23)      # page
PANEL   = (22, 27, 34)      # window
BAR     = (28, 33, 40)      # title bar
BORDER  = (48, 54, 61)
TEXT    = (201, 209, 217)
MUTE    = (139, 148, 158)
RED     = (248, 81, 73)
GREEN   = (63, 185, 80)
AMBER   = (210, 153, 34)
BLUE    = (88, 166, 255)
PURPLE  = (188, 140, 255)
REDBG   = (45, 21, 24)
GREENBG = (18, 38, 24)

W = 1280
OUTER = 26
PAD = 34
FONTDIR = "C:/Windows/Fonts"


def font(name, size):
    return ImageFont.truetype(os.path.join(FONTDIR, name), size)


REG  = lambda s: font("consola.ttf", s)
BOLD = lambda s: font("consolab.ttf", s)


def wrap(text, fnt, max_w):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if fnt.getlength(trial) <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


# ---------------------------------------------------------------------------
# Drawing primitives that record onto a draw context
# ---------------------------------------------------------------------------
def window(draw, h, title):
    draw.rounded_rectangle([OUTER, OUTER, W - OUTER, h - OUTER], radius=14,
                           fill=PANEL, outline=BORDER, width=2)
    draw.rounded_rectangle([OUTER, OUTER, W - OUTER, OUTER + 46], radius=14,
                           fill=BAR, outline=BORDER, width=2)
    draw.rectangle([OUTER, OUTER + 30, W - OUTER, OUTER + 46], fill=BAR)
    cy = OUTER + 23
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([OUTER + 18 + i * 22, cy - 7, OUTER + 18 + i * 22 + 14, cy + 7], fill=col)
    draw.text((OUTER + 110, cy - 11), title, font=BOLD(18), fill=MUTE)


def chip(draw, x, y, text, fg, bg):
    f = BOLD(18)
    tw = f.getlength(text)
    pad = 12
    draw.rounded_rectangle([x, y, x + tw + pad * 2, y + 30], radius=8, fill=bg)
    draw.text((x + pad, y + 5), text, font=f, fill=fg)
    return x + tw + pad * 2


def grade_color(g):
    return GREEN if g in ("A", "B") else AMBER if g == "C" else RED


# ---------------------------------------------------------------------------
# Scorecard image
# ---------------------------------------------------------------------------
def render_scorecard(path):
    target = MockTarget()
    card = build_scorecard(target.name, target.model, run_all(target, load_probes()))

    left = OUTER + PAD
    rows = card.results
    # height: bar + meta + bignum + table header + rows + footer
    h = OUTER + 46 + 30 + 110 + 50 + len(rows) * 38 + 70 + OUTER
    img = Image.new("RGB", (W, h), BG)
    d = ImageDraw.Draw(img)
    window(d, h, "AI Red Team Range  -  resilience scan")

    y = OUTER + 46 + 28
    d.text((left, y), f"target  {card.target_name}    model  {card.model}", font=REG(20), fill=MUTE)
    y += 44

    gc = grade_color(card.grade)
    d.text((left, y), f"{card.resilience}", font=BOLD(64), fill=gc)
    rw = BOLD(64).getlength(f"{card.resilience}")
    d.text((left + rw + 8, y + 34), "/ 100", font=REG(26), fill=MUTE)
    d.text((left + rw + 170, y + 6), f"GRADE {card.grade}", font=BOLD(34), fill=gc)
    d.text((left + rw + 170, y + 50), f"{card.vulnerabilities} of {card.total_probes} probes vulnerable",
           font=REG(20), fill=TEXT)
    y += 110

    # table header
    cols = [left, left + 90, left + 560, left + 770, W - OUTER - PAD - 200]
    for cx, label in zip(cols, ["ID", "ATTACK", "OWASP", "SEVERITY", "RESULT"]):
        d.text((cx, y), label, font=BOLD(17), fill=MUTE)
    y += 28
    d.line([left, y, W - OUTER - PAD, y], fill=BORDER, width=1)
    y += 10

    for r in rows:
        owasp = r.probe.owasp.split(":")[0]
        name = r.probe.name
        if REG(19).getlength(name) > 460:
            while REG(19).getlength(name + "...") > 460 and len(name) > 4:
                name = name[:-1]
            name += "..."
        d.text((cols[0], y), r.probe.id, font=REG(19), fill=TEXT)
        d.text((cols[1], y), name, font=REG(19), fill=TEXT)
        d.text((cols[2], y), owasp, font=REG(19), fill=BLUE)
        sev_col = RED if r.probe.severity in ("critical", "high") else AMBER
        d.text((cols[3], y), r.probe.severity, font=REG(19), fill=sev_col)
        if r.vulnerable:
            chip(d, cols[4], y - 3, "VULNERABLE", RED, REDBG)
        else:
            chip(d, cols[4], y - 3, "DEFENDED", GREEN, GREENBG)
        y += 38

    y += 16
    d.line([left, y, W - OUTER - PAD, y], fill=BORDER, width=1)
    y += 14
    d.text((left, y), "Mapped to OWASP LLM Top 10 (2025)  -  MITRE ATLAS  -  severity weighted score",
           font=REG(18), fill=MUTE)
    img.save(path)
    print("wrote", path, img.size)


# ---------------------------------------------------------------------------
# Attack transcript image
# ---------------------------------------------------------------------------
def render_attack(path):
    t = run_goal(MockTarget(), get_goal("leak-system-prompt"), ScriptedAttacker(), max_turns=5)
    left = OUTER + PAD
    content_w = W - 2 * (OUTER + PAD)
    body_w = content_w - 40

    # measure height
    line_h = 26
    y = OUTER + 46 + 28 + 40 + 50
    blocks = []
    for turn in t.turns:
        atk_lines = wrap("attacker> " + turn.prompt, REG(19), body_w)
        tgt_lines = wrap("target> " + turn.response, REG(19), body_w)
        blocks.append((turn, atk_lines, tgt_lines))
        y += 34 + (len(atk_lines) + len(tgt_lines)) * line_h + 18
    h = y + 40 + OUTER

    img = Image.new("RGB", (W, h), BG)
    d = ImageDraw.Draw(img)
    window(d, h, "AI Red Team Range  -  agentic multi turn attack")

    y = OUTER + 46 + 28
    d.text((left, y), f"goal  {t.goal_id}    attacker  {t.turns[0].strategy}    target  {t.model}",
           font=REG(20), fill=MUTE)
    y += 40
    outcome = "GOAL ACHIEVED" if t.succeeded else "TARGET HELD"
    oc = RED if t.succeeded else GREEN
    obg = REDBG if t.succeeded else GREENBG
    xend = chip(d, left, y, outcome, oc, obg)
    d.text((xend + 16, y + 4), f"in {t.turns_used} of {t.max_turns} turns", font=REG(20), fill=TEXT)
    y += 50

    for turn, atk_lines, tgt_lines in blocks:
        hit = turn.success
        label = "HIT" if hit else "miss"
        lc = RED if hit else MUTE
        d.text((left, y), f"Turn {turn.turn}", font=BOLD(20), fill=TEXT)
        d.text((left + 90, y), f"[{label}]", font=BOLD(20), fill=lc)
        y += 34
        for ln in atk_lines:
            d.text((left + 20, y), ln, font=REG(19), fill=PURPLE)
            y += line_h
        tgt_col = RED if hit else TEXT
        for ln in tgt_lines:
            d.text((left + 20, y), ln, font=REG(19), fill=tgt_col)
            y += line_h
        y += 18

    img.save(path)
    print("wrote", path, img.size)


if __name__ == "__main__":
    os.makedirs("assets", exist_ok=True)
    render_scorecard("assets/scorecard.png")
    render_attack("assets/attack.png")
