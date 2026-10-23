from __future__ import annotations


class RiskCalcException(Exception):
    """Base exception class for all risk calculation errors."""

    pass


class RiskProfileValidationException(RiskCalcException):
    """Exception raised when a risk profile fails validation."""

    pass


class RiskRuleEvaluationException(RiskCalcException):
    """Exception raised when a risk rule evaluation fails."""

    pass


class RiskRequestException(RiskCalcException):
    """Exception raised when a risk request fails validation or processing."""

    pass
