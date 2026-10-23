from __future__ import annotations

from pydantic import Field
from typing import ClassVar

from riskcalc.profiling.context.base import ProfileContext
from riskcalc.profiling.fields import (
    BooleanScoreField,
    EnumScoreField,
)
from riskcalc.request import BusinessContextRequest
from riskcalc.constants import *


class BusinessProfileContext(ProfileContext[BusinessContextRequest]):
    NAMESPACE: ClassVar[str] = BUSINESS_CTX_NAMESPACE

    asset_criticality: EnumScoreField[AssetCriticality] = Field(
        default_factory=EnumScoreField[AssetCriticality]
    )
    business_impact: EnumScoreField[BusinessImpact] = Field(
        default_factory=EnumScoreField[BusinessImpact]
    )
    data_sensitivity: EnumScoreField[DataSensitivity] = Field(
        default_factory=EnumScoreField[DataSensitivity]
    )
    customer_facing: BooleanScoreField = Field(default_factory=BooleanScoreField)
    revenue_generating: BooleanScoreField = Field(default_factory=BooleanScoreField)
    regulatory_scope: BooleanScoreField = Field(default_factory=BooleanScoreField)
    safety_critical: BooleanScoreField = Field(default_factory=BooleanScoreField)
