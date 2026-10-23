"""
vulnflow-riskcalc: evaluate vulnerability risk from vulnerability data plus
environmental and business context, under an explicit scoring profile.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from riskcalc.calculator import RiskCalculator
from riskcalc.request import RiskRequest
from riskcalc.risk import Risk, RiskContribution
from riskcalc.profiling import RiskProfile
from riskcalc.utils import (
    list_profiles,
    load_profile,
    yaml_to_profile,
    yaml_to_risk_request,
)

try:
    __version__ = version("vulnflow-riskcalc")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = [
    "__version__",
    "RiskCalculator",
    "RiskRequest",
    "RiskProfile",
    "Risk",
    "RiskContribution",
    "list_profiles",
    "load_profile",
    "yaml_to_profile",
    "yaml_to_risk_request",
]
