from __future__ import annotations

from typing import ClassVar
from pydantic import Field

from riskcalc.profiling.context.base import ProfileContext
from riskcalc.profiling.fields import BooleanDeltaField
from riskcalc.request import ControlContextRequest
from riskcalc.constants import *


class ControlProfileContext(ProfileContext[ControlContextRequest]):
    NAMESPACE: ClassVar[str] = CONTROL_CTX_NAMESPACE

    edr_present: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    waf_present: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    network_segmentation: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    mfa_enforced: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
    firewall: BooleanDeltaField = Field(default_factory=BooleanDeltaField)
