from __future__ import annotations

from typing import Tuple, TYPE_CHECKING, get_args
from pydantic import Field, BaseModel

from riskcalc.constants import *
from riskcalc.profiling.fields import Score
from riskcalc.profiling import (
    ThreatIntelProfileContext,
    EnvironmentProfileContext,
    ControlProfileContext,
    BusinessProfileContext,
    RemediationProfileContext,
    ExposureProfileContext,
)

if TYPE_CHECKING:
    from riskcalc.profiling import ProfileContext


class ProfileRatings(BaseModel):
    informational: Score = Field(default=0)
    low: Score = Field(default=20)
    medium: Score = Field(default=50)
    high: Score = Field(default=70)
    critical: Score = Field(default=90)


class ProfileVulnerability(BaseModel):
    cvss_weight: Score = Field(default=DEFAULT_WEIGHT)

    def calculate_base_score(self, cvss_base_value: float) -> int:
        """
        For now just use the CVSS base value as is and apply the weight.
        """
        return int(cvss_base_value) * self.cvss_weight

    def minimum_score(self) -> float:
        return 0.0

    def maximum_score(self) -> float:
        return float(self.cvss_weight)


class ProfileContexts(BaseModel):
    threat_intel: ThreatIntelProfileContext
    environment: EnvironmentProfileContext
    control: ControlProfileContext
    business: BusinessProfileContext
    remediation: RemediationProfileContext
    exposure: ExposureProfileContext

    def context_values(self) -> list[Tuple[str, ProfileContext | None]]:
        def _context_namespace(annotation) -> str:
            cls = next(
                (a for a in get_args(annotation) if a is not type(None)), annotation
            )
            return cls.NAMESPACE

        return [
            (_context_namespace(field.annotation), getattr(self, name))
            for name, field in type(self).model_fields.items()
        ]

    def get_context(self, name: str) -> ProfileContext | None:
        for context_name, context in self.context_values():
            if context_name == name:
                return context
        return None

    def minimum_score(self) -> float:
        return sum(
            context.minimum_score()
            for name in self.model_fields
            if (context := getattr(self, name)) is not None
        )

    def maximum_score(self) -> float:
        return sum(
            context.maximum_score()
            for name in self.model_fields
            if (context := getattr(self, name)) is not None
        )


class ScoreConfig(BaseModel):
    minimum: Score = Field(default=SCORE_LOWER_BOUND)
    maximum: Score = Field(default=SCORE_UPPER_BOUND)


class RiskProfile(BaseModel):
    name: str
    version: str
    score: ScoreConfig = Field(default_factory=ScoreConfig)
    ratings: ProfileRatings = Field(default_factory=ProfileRatings)
    vulnerability: ProfileVulnerability
    contexts: ProfileContexts

    def minimum_score(self) -> float:
        total = 0.0
        total += self.vulnerability.minimum_score()
        total += self.contexts.minimum_score()
        return total

    def maximum_score(self) -> float:
        total = 0.0
        total += self.vulnerability.maximum_score()
        total += self.contexts.maximum_score()
        return total

    def rating_for(self, score: float) -> RiskRating:
        thresholds = [
            (self.ratings.informational, RiskRating.INFORMATIONAL),
            (self.ratings.low, RiskRating.LOW),
            (self.ratings.medium, RiskRating.MEDIUM),
            (self.ratings.high, RiskRating.HIGH),
            (self.ratings.critical, RiskRating.CRITICAL),
        ]

        rating = RiskRating.INFORMATIONAL

        for threshold, candidate in thresholds:
            if score >= threshold:
                rating = candidate
            else:
                break

        return rating
