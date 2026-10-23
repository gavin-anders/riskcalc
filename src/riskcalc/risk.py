from __future__ import annotations

from pydantic import BaseModel, Field
from datetime import datetime

from riskcalc.constants import RiskRating

#
# Types
#


class RiskContribution(BaseModel):
    source: str  # controls.network_segmentation
    reason: str  # Network segmentation limits potential attack paths
    value: float | int  # -8


class Risk(BaseModel):
    evaluated_at: datetime = Field(default_factory=datetime.now)
    raw_score: float
    score: float = Field(ge=0, le=100)
    rating: RiskRating
    contributions: list[RiskContribution] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)

    @property
    def report(self) -> str:
        """
        Terminal report
        """
        report = (
            f"Evaluated at: {self.evaluated_at}\n"
            f"Raw score: {self.raw_score}\n"
            f"Score: {self.score}\n"
            f"Rating: {self.rating}\n"
            "Contributions:\n"
            + "\n".join([f"  - {c.source} ({c.value})" for c in self.contributions])
            + f"\nMissing context: {', '.join(self.missing_context)}\n"
        )

        return report
