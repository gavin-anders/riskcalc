from __future__ import annotations

from enum import StrEnum

#
# Vars
#
DEFAULT_SCORE: int = 0
DEFAULT_WEIGHT: int = 1
SCORE_UPPER_BOUND: int = 100
SCORE_LOWER_BOUND: int = 0
SCORE_DELTA_LOWER_BOUND: int = -100
SCORE_DELTA_UPPER_BOUND: int = 100

#
# Namespaces for context's
#
THREAT_INTEL_CTX_NAMESPACE: str = "threat_intel"
ENVIRONMENT_CTX_NAMESPACE: str = "environment"
CONTROL_CTX_NAMESPACE: str = "control"
BUSINESS_CTX_NAMESPACE: str = "business"
REMEDIATION_CTX_NAMESPACE: str = "remediation"
EXPOSURE_CTX_NAMESPACE: str = "exposure"


#
# Types
#
class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BusinessImpact(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataSensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class DeploymentEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRE_PRODUCTION = "pre_production"
    PRODUCTION = "production"
    DISASTER_RECOVERY = "disaster_recovery"
    UNKNOWN = "unknown"


class RemediationComplexity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskRating(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
