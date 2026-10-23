from __future__ import annotations

from abc import abstractmethod

from pydantic import BaseModel, Field, model_validator
from typing import Generic, TypeVar, Annotated
from enum import StrEnum

from riskcalc.constants import (
    DEFAULT_SCORE,
    SCORE_UPPER_BOUND,
    SCORE_LOWER_BOUND,
    SCORE_DELTA_LOWER_BOUND,
    SCORE_DELTA_UPPER_BOUND,
)

TEnum = TypeVar("TEnum", bound=StrEnum)

ScoreDelta = Annotated[
    int,
    Field(
        ge=SCORE_DELTA_LOWER_BOUND,
        le=SCORE_DELTA_UPPER_BOUND,
    ),
]
Score = Annotated[
    int,
    Field(ge=SCORE_LOWER_BOUND, le=SCORE_UPPER_BOUND),
]


class ProfileField(BaseModel):
    @abstractmethod
    def evaluate(self, value) -> int:
        raise NotImplementedError


#
# Bool Fields
#
class _BooleanField(BaseModel):
    """
    Base for the boolean-keyed fields. YAML parses bare ``true`` / ``false``
    mapping keys as Python bools, so normalise them back to the ``true`` /
    ``false`` field names before validation.
    """

    @model_validator(mode="before")
    @classmethod
    def _normalise_bool_keys(cls, data):
        if not isinstance(data, dict):
            return data
        return {
            ("true" if key is True else "false" if key is False else key): value
            for key, value in data.items()
        }


class BooleanDeltaField(_BooleanField):
    true: ScoreDelta = DEFAULT_SCORE
    false: ScoreDelta = DEFAULT_SCORE

    def evaluate(self, value: bool) -> ScoreDelta:
        return self.true if value else self.false

    def minimum_score(self) -> int:
        return min(self.true, self.false)

    def maximum_score(self) -> int:
        return max(self.true, self.false)


class BooleanScoreField(_BooleanField):
    true: Score = DEFAULT_SCORE
    false: Score = DEFAULT_SCORE

    def evaluate(self, value: bool) -> Score:
        return self.true if value else self.false

    def minimum_score(self) -> int:
        return min(self.true, self.false)

    def maximum_score(self) -> int:
        return max(self.true, self.false)


#
# Threshold fields
#
class ThresholdDeltaField(BaseModel):
    gte: float | None = None
    lte: float | None = None
    score: ScoreDelta = DEFAULT_SCORE

    def matches(self, value: float) -> bool:
        if self.gte is not None and value < self.gte:
            return False

        if self.lte is not None and value > self.lte:
            return False

        return True

    def evaluate(self, value: float) -> int:
        if not self.matches(value):
            return 0

        return self.score


class ThresholdScoreField(BaseModel):
    gte: float | None = None
    lte: float | None = None
    score: Score = DEFAULT_SCORE

    def matches(self, value: float) -> bool:
        if self.gte is not None and value < self.gte:
            return False

        if self.lte is not None and value > self.lte:
            return False

        return True

    def evaluate(self, value: float) -> int:
        if not self.matches(value):
            return 0

        return self.score

    def minimum_score(self) -> int:
        # evaluate() returns 0 when the value is out of range.
        return min(DEFAULT_SCORE, self.score)

    def maximum_score(self) -> int:
        return max(DEFAULT_SCORE, self.score)


#
# Enum fields
#
class EnumDeltaField(BaseModel, Generic[TEnum]):
    values: dict[TEnum, ScoreDelta] = Field(default_factory=dict)

    def evaluate(self, value: TEnum) -> int:
        return self.values.get(value, DEFAULT_SCORE)

    def minimum_score(self) -> int:
        # An unmapped enum member falls back to DEFAULT_SCORE via evaluate().
        return min([DEFAULT_SCORE, *self.values.values()])

    def maximum_score(self) -> int:
        return max([DEFAULT_SCORE, *self.values.values()])


class EnumScoreField(BaseModel, Generic[TEnum]):
    values: dict[TEnum, Score] = Field(default_factory=dict)

    def evaluate(self, value: TEnum) -> int:
        return self.values.get(value, DEFAULT_SCORE)

    def minimum_score(self) -> int:
        # An unmapped enum member falls back to DEFAULT_SCORE via evaluate().
        return min([DEFAULT_SCORE, *self.values.values()])

    def maximum_score(self) -> int:
        return max([DEFAULT_SCORE, *self.values.values()])
