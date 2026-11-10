from __future__ import annotations

from dataclasses import asdict, dataclass

# Contribution of a finding to the threat score (percent, combined noisy-OR).
SEVERITY_WEIGHT = {"info": 0, "low": 7, "medium": 18, "high": 40, "critical": 65}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """One observation made by an analysis engine.

    axis:
      threat  - evidence the site is fraudulent or malicious
      posture - security-hygiene weakness (says nothing about intent)
      both    - trust failure that is a hygiene problem *and* enables fraud
    """

    id: str
    engine: str  # url | content | certificate | security | intel
    axis: str  # threat | posture | both
    severity: str
    title: str
    detail: str = ""
    advice: str = ""
    weight: int | None = None
    posture_weight: int | None = None
    floor: int | None = None  # minimum threat score this finding forces

    def __post_init__(self) -> None:
        if self.weight is None:
            self.weight = SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict:
        return asdict(self)
