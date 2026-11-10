"""Turns findings into two separate judgements.

Threat score (0-100): how likely is the site to be fraudulent or malicious?
  Findings combine as independent evidence (noisy-OR), so many weak signals
  add up but no single weak signal condemns a site. Strong evidence from two
  different engines adds a corroboration bonus. Some findings (distrusted key,
  confirmed community report) set a floor.

Security posture (A-F): how well is the site configured? A phishing page can
  have perfect headers and a bank can miss a CSP, so this is reported apart.
"""
from __future__ import annotations

import math

from .models import Finding

VERDICTS = [  # (minimum score, label, css level)
    (70, "Dangerous", "danger"),
    (45, "Suspicious", "high"),
    (20, "Caution", "warn"),
    (0, "Low risk", "ok"),
]
GRADES = [(90, "A"), (80, "B"), (70, "C"), (55, "D"), (0, "F")]


def threat_score(findings: list[Finding]) -> int:
    relevant = [f for f in findings if f.axis in ("threat", "both") and (f.weight or 0) > 0]
    risk = 1 - math.prod(1 - min(f.weight, 95) / 100 for f in relevant) if relevant else 0.0
    strong_engines = {f.engine for f in relevant if f.weight >= 40}
    if len(strong_engines) >= 2:
        risk = min(1.0, risk + 0.10)
    score = round(risk * 100)
    floor = max((f.floor or 0 for f in findings), default=0)
    return max(score, floor)


def verdict_for(score: int) -> tuple[str, str]:
    for minimum, label, level in VERDICTS:
        if score >= minimum:
            return label, level
    return VERDICTS[-1][1], VERDICTS[-1][2]


def posture(findings: list[Finding]) -> tuple[int, str]:
    penalty = 0
    for f in findings:
        if f.axis in ("posture", "both"):
            penalty += f.posture_weight if f.posture_weight is not None else (f.weight or 0)
    score = max(0, 100 - penalty)
    for minimum, grade in GRADES:
        if score >= minimum:
            return score, grade
    return score, "F"
