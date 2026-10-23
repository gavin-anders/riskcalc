from __future__ import annotations

from pydantic import Field
from typing import ClassVar

from riskcalc.profiling.context.base import ProfileContext
from riskcalc.profiling.fields import (
    BooleanDeltaField,
    EnumScoreField,
)
from riskcalc.request import RemediationContextRequest
from riskcalc.constants import *


class RemediationProfileContext(ProfileContext[RemediationContextRequest]):
    NAMESPACE: ClassVar[str] = REMEDIATION_CTX_NAMESPACE

    patch_available: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    workaround_available: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    remediation_complexity: EnumScoreField[RemediationComplexity] = Field(
        default_factory=EnumScoreField[RemediationComplexity]
    )
