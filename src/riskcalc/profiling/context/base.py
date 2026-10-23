from __future__ import annotations

from abc import abstractmethod
from typing import ClassVar, TypeVar, Generic
from pydantic import BaseModel, computed_field

from riskcalc.profiling.fields import (
    ThresholdDeltaField,
    ThresholdScoreField,
    ProfileField,
)
from riskcalc.constants import *

TContextRequest = TypeVar("TContextRequest", bound=BaseModel)


class ProfileContext(BaseModel, Generic[TContextRequest]):
    NAMESPACE: ClassVar[str]

    @computed_field
    @property
    def namespace(self) -> str:
        return self.NAMESPACE

    def _evaluate_thresholds(
        self,
        thesholds: list[ThresholdScoreField] | list[ThresholdDeltaField],
        value: float | int,
    ) -> float:
        """
        Order the thresholds from highest band to lowest and return the score
        of the first band the value falls into. If no band matches, contribute
        DEFAULT_SCORE.
        """
        # Sort in descending order so higher scores/deltas come first
        thresholds = sorted(
            thesholds,
            key=lambda threshold: (
                threshold.gte if threshold.gte is not None else float("-inf")
            ),
            reverse=True,
        )
        for threshold in thresholds:
            if threshold.matches(value):
                return threshold.score

        return DEFAULT_SCORE

    def minimum_score(self) -> float:
        """
        Theoretical minimum raw score this context can contribute, summed
        across its configured fields. A list field (threshold list) is a
        single contribution slot whose floor is 0 when nothing matches.
        """
        total = 0.0
        for name in type(self).model_fields:
            field = getattr(self, name)
            if isinstance(field, list):
                total += min([DEFAULT_SCORE, *(item.minimum_score() for item in field)])
            else:
                total += field.minimum_score()
        return total

    def maximum_score(self) -> float:
        """
        Theoretical maximum raw score this context can contribute, summed
        across its configured fields.
        """
        total = 0.0
        for name in type(self).model_fields:
            field = getattr(self, name)
            if isinstance(field, list):
                total += max([DEFAULT_SCORE, *(item.maximum_score() for item in field)])
            else:
                total += field.maximum_score()
        return total

    def evaluate(self, request: TContextRequest) -> dict[str, float | int | None]:
        # one contribution slot per configured field on this profile context;
        # fields whose request value is unset (None) stay None
        contributions: dict[str, float | int | None] = {
            name: None for name in type(self).model_fields
        }

        # for each field on the profile context use its evaluate() to determine the
        # contribution, accounting for threshold lists via the helper
        for name in type(self).model_fields:
            if name not in type(request).model_fields:
                raise ValueError(
                    f"Field '{name}' has no counterpart in the `{self.NAMESPACE}`"
                    " context request"
                )

            comparitor: ProfileField | list[ThresholdScoreField] = getattr(self, name)
            value = getattr(request, name)
            if value is None:
                continue

            if isinstance(comparitor, list):
                # assumption: all lists are threshold lists
                contributions[name] = self._evaluate_thresholds(comparitor, value)
            else:
                contributions[name] = comparitor.evaluate(value)

        return contributions
