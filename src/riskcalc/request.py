from __future__ import annotations

from typing import Tuple, ClassVar, get_args
from pydantic import BaseModel, Field, model_validator

from riskcalc.constants import *


#
# Nested vuln component
#
class CvssScore(BaseModel):
    version: int = Field(ge=2, le=4)
    score: float = Field(ge=0.1, le=10)
    vector: str | None = None


class VulnerabilityRequest(BaseModel):
    id: str | None = None
    title: str
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    capec_ids: list[str] = Field(default_factory=list)
    cvss: CvssScore


#
# Nested Contexts components
#
class ContextRequest(BaseModel):
    NAMESPACE: ClassVar[str] = "context"


class ThreatIntelContextRequest(ContextRequest):
    NAMESPACE: ClassVar[str] = THREAT_INTEL_CTX_NAMESPACE

    epss: float | None = Field(default=None, ge=0, le=1)
    kev: bool | None = None
    exploit_available: bool | None = None


class EnvironmentContextRequest(ContextRequest):
    NAMESPACE: ClassVar[str] = ENVIRONMENT_CTX_NAMESPACE

    deployment_environment: DeploymentEnvironment | None = None
    privileged_network_location: bool | None = None


class ControlContextRequest(ContextRequest):
    NAMESPACE: ClassVar[str] = CONTROL_CTX_NAMESPACE

    edr_present: bool | None = None
    waf_present: bool | None = None
    network_segmentation: bool | None = None
    mfa_enforced: bool | None = None
    firewall: bool | None = None


class BusinessContextRequest(ContextRequest):
    NAMESPACE: ClassVar[str] = BUSINESS_CTX_NAMESPACE

    asset_criticality: AssetCriticality | None = None
    business_impact: BusinessImpact | None = None
    data_sensitivity: DataSensitivity | None = None
    customer_facing: bool | None = None
    revenue_generating: bool | None = None
    regulatory_scope: bool | None = None
    safety_critical: bool | None = None


class RemediationContextRequest(ContextRequest):
    NAMESPACE: ClassVar[str] = REMEDIATION_CTX_NAMESPACE

    patch_available: bool | None = None
    workaround_available: bool | None = None
    remediation_complexity: RemediationComplexity | None = None


class ExposureContextRequest(ContextRequest):
    NAMESPACE: ClassVar[str] = EXPOSURE_CTX_NAMESPACE

    internet_access: bool | None = None
    reachable_from_public: bool | None = None
    reachable_from_user_networks: bool | None = None
    reachable_from_untrusted_networks: bool | None = None
    authentication_boundary_crossed: bool | None = None


#
# Contexts container
#
class ContextRequests(BaseModel):
    threat_intel: ThreatIntelContextRequest | None = None
    environment: EnvironmentContextRequest | None = None
    control: ControlContextRequest | None = None
    business: BusinessContextRequest | None = None
    remediation: RemediationContextRequest | None = None
    exposure: ExposureContextRequest | None = None

    @model_validator(mode="after")
    def validate_contexts(self) -> "ContextRequests":
        # check if all context fields are None
        if all(getattr(self, field) is None for field in type(self).model_fields):
            raise ValueError("At least one context must be provided")
        return self

    def context_values(self) -> list[Tuple[str, ContextRequest | None]]:
        def _context_namespace(annotation) -> str:
            cls = next(
                (a for a in get_args(annotation) if a is not type(None)), annotation
            )
            return cls.NAMESPACE

        return [
            (_context_namespace(field.annotation), getattr(self, name))
            for name, field in type(self).model_fields.items()
        ]


#
# Request container
#
class RiskRequest(BaseModel):
    vulnerability: VulnerabilityRequest
    contexts: ContextRequests
