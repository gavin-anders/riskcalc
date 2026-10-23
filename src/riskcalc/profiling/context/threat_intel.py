from __future__ import annotations

from pydantic import Field
from typing import ClassVar

from riskcalc.profiling.context.base import ProfileContext
from riskcalc.profiling.fields import (
    BooleanDeltaField,
    ThresholdScoreField,
    BooleanScoreField,
)
from riskcalc.request import ThreatIntelContextRequest
from riskcalc.constants import *


class ThreatIntelProfileContext(ProfileContext[ThreatIntelContextRequest]):
    NAMESPACE: ClassVar[str] = THREAT_INTEL_CTX_NAMESPACE

    epss: list[ThresholdScoreField] = Field(default_factory=list)
    kev: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    exploit_available: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
