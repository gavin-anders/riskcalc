from __future__ import annotations

from pydantic import Field
from typing import ClassVar

from riskcalc.profiling.context.base import ProfileContext
from riskcalc.profiling.fields import (
    BooleanDeltaField,
)
from riskcalc.request import ExposureContextRequest
from riskcalc.constants import *


class ExposureProfileContext(ProfileContext[ExposureContextRequest]):
    NAMESPACE: ClassVar[str] = EXPOSURE_CTX_NAMESPACE

    internet_access: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    reachable_from_public: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    reachable_from_user_networks: BooleanDeltaField = Field(
        default_factory=BooleanDeltaField
    )
    reachable_from_untrusted_networks: BooleanDeltaField = Field(
        default_factory=BooleanDeltaField
    )
    authentication_boundary_crossed: BooleanDeltaField = Field(
        default_factory=BooleanDeltaField
    )
