from __future__ import annotations

from pydantic import Field
from typing import ClassVar

from riskcalc.profiling.context.base import ProfileContext
from riskcalc.profiling.fields import EnumDeltaField, BooleanDeltaField
from riskcalc.request import EnvironmentContextRequest
from riskcalc.constants import *


class EnvironmentProfileContext(ProfileContext[EnvironmentContextRequest]):
    NAMESPACE: ClassVar[str] = ENVIRONMENT_CTX_NAMESPACE

    deployment_environment: EnumDeltaField[DeploymentEnvironment] = Field(
        default_factory=EnumDeltaField[DeploymentEnvironment]
    )
    privileged_network_location: BooleanDeltaField = Field(
        default_factory=BooleanDeltaField
    )
