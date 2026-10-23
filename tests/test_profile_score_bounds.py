"""
Tests for the theoretical minimum/maximum raw score exposed by profile
fields, contexts and the full RiskProfile.

The unmatched / unmapped outcome of every field type is DEFAULT_SCORE (0),
so every bound is an envelope that also includes 0.
"""

from riskcalc.profiling.fields import (
    BooleanDeltaField,
    BooleanScoreField,
    EnumDeltaField,
    EnumScoreField,
    ThresholdScoreField,
)
from riskcalc.request import ThreatIntelContextRequest
from riskcalc.profiling.context.threat_intel import ThreatIntelProfileContext
from riskcalc.profiling.context.control import ControlProfileContext
from riskcalc.profiling.profile import (
    ProfileContexts,
    ProfileVulnerability,
    RiskProfile,
)
from riskcalc.profiling.context import (
    EnvironmentProfileContext,
    BusinessProfileContext,
    RemediationProfileContext,
    ExposureProfileContext,
)
from riskcalc.constants import RemediationComplexity
from riskcalc.utils import yaml_to_profile, yaml_to_risk_request
from riskcalc.calculator import RiskCalculator


#
# Field-level bounds
#
def test_boolean_delta_field_bounds():
    field = BooleanDeltaField(true=20, false=-20)
    assert field.minimum_score() == -20
    assert field.maximum_score() == 20


def test_boolean_score_field_bounds():
    field = BooleanScoreField(true=5, false=0)
    assert field.minimum_score() == 0
    assert field.maximum_score() == 5


def test_threshold_score_field_floor_is_zero_when_out_of_range():
    field = ThresholdScoreField(gte=0.9, score=15)
    assert field.minimum_score() == 0
    assert field.maximum_score() == 15


def test_enum_score_field_bounds_include_unmapped_fallback():
    field = EnumScoreField[RemediationComplexity](
        values={"low": 0, "medium": 3, "high": 7}
    )
    assert field.minimum_score() == 0
    assert field.maximum_score() == 7


def test_enum_score_field_all_positive_map_still_has_zero_floor():
    # An enum member the profile did not map evaluates to DEFAULT_SCORE (0),
    # so the floor stays 0 even though every mapped value is positive.
    field = EnumScoreField[RemediationComplexity](
        values={"low": 2, "medium": 3, "high": 7}
    )
    assert field.minimum_score() == 0
    assert field.maximum_score() == 7


def test_enum_delta_field_bounds_span_zero():
    field = EnumDeltaField[RemediationComplexity](
        values={"low": -4, "medium": 0, "high": 6}
    )
    assert field.minimum_score() == -4
    assert field.maximum_score() == 6


def test_empty_enum_field_collapses_to_zero():
    field = EnumScoreField[RemediationComplexity]()
    assert field.minimum_score() == 0
    assert field.maximum_score() == 0


#
# Context-level aggregation
#
def test_context_sums_field_bounds_and_treats_threshold_list_as_one_slot():
    ctx = ThreatIntelProfileContext(
        epss=[
            ThresholdScoreField(gte=0.9, score=15),
            ThresholdScoreField(gte=0.7, score=10),
        ],
        kev=BooleanDeltaField(true=20, false=-20),
        exploit_available=BooleanDeltaField(true=90, false=-50),
    )
    # epss: [0, 15]  kev: [-20, 20]  exploit_available: [-50, 90]
    assert ctx.minimum_score() == -70.0
    assert ctx.maximum_score() == 125.0


def test_empty_threshold_list_contributes_zero():
    ctx = ThreatIntelProfileContext(
        kev=BooleanDeltaField(true=10, false=-10),
    )
    assert ctx.minimum_score() == -10.0
    assert ctx.maximum_score() == 10.0


def test_default_context_has_zero_bounds():
    ctx = ControlProfileContext()
    assert ctx.minimum_score() == 0.0
    assert ctx.maximum_score() == 0.0


def test_namespace_computed_field_is_not_counted():
    # `namespace` is a computed_field, not a model field, so it must not
    # participate in the sum (and has no minimum_score()).
    ctx = ControlProfileContext(edr_present=BooleanDeltaField(true=-5, false=0))
    assert ctx.minimum_score() == -5.0
    assert ctx.maximum_score() == 0.0


#
# Whole-profile roll-up
#
def _profile(**contexts) -> RiskProfile:
    defaults = dict(
        threat_intel=ThreatIntelProfileContext(),
        environment=EnvironmentProfileContext(),
        control=ControlProfileContext(),
        business=BusinessProfileContext(),
        remediation=RemediationProfileContext(),
        exposure=ExposureProfileContext(),
    )
    defaults.update(contexts)
    return RiskProfile(
        name="test",
        version="1",
        vulnerability=ProfileVulnerability(cvss_weight=30),
        contexts=ProfileContexts(**defaults),
    )


def test_profile_bounds_combine_vulnerability_and_contexts():
    profile = _profile(
        threat_intel=ThreatIntelProfileContext(
            kev=BooleanDeltaField(true=20, false=-20),
        ),
    )
    # vulnerability: [0, 30]  threat_intel.kev: [-20, 20]  rest: 0
    assert profile.minimum_score() == -20.0
    assert profile.maximum_score() == 50.0


#
# Threshold-list evaluation: pick the highest band the value falls into.
#
def _epss_context() -> ThreatIntelProfileContext:
    return ThreatIntelProfileContext(
        epss=[
            ThresholdScoreField(gte=0.90, score=15),
            ThresholdScoreField(gte=0.70, score=10),
            ThresholdScoreField(gte=0.40, score=5),
        ]
    )


def test_threshold_list_returns_first_matching_band():
    ctx = _epss_context()
    scores = [
        ctx.evaluate(ThreatIntelContextRequest(epss=value))["epss"]
        for value in (0.95, 0.75, 0.50, 0.20)
    ]
    assert scores == [15, 10, 5, 0]


def test_threshold_list_band_order_is_independent_of_config_order():
    # Same bands, listed low-to-high; sorting inside the evaluator must still
    # select the highest matching band.
    ctx = ThreatIntelProfileContext(
        epss=[
            ThresholdScoreField(gte=0.40, score=5),
            ThresholdScoreField(gte=0.90, score=15),
            ThresholdScoreField(gte=0.70, score=10),
        ]
    )
    assert ctx.evaluate(ThreatIntelContextRequest(epss=0.75))["epss"] == 10


#
# YAML parses bare `true` / `false` mapping keys as Python bools; the boolean
# fields must still populate.
#
def test_boolean_field_accepts_bool_keys():
    field = BooleanDeltaField.model_validate({True: 20, False: -20})
    assert (field.true, field.false) == (20, -20)


def test_boolean_score_field_accepts_bool_keys():
    field = BooleanScoreField.model_validate({True: 5})
    assert (field.true, field.false) == (5, 0)


def test_boolean_field_still_accepts_string_keys():
    field = BooleanDeltaField.model_validate({"true": 1, "false": -1})
    assert (field.true, field.false) == (1, -1)


#
# Regression: the example profile used to raise AttributeError here.
#
def test_example_calculation_runs():
    request = yaml_to_risk_request("example/request.yaml")
    profile = yaml_to_profile("example/profile.yaml")

    risk = RiskCalculator(request, profile).calculate()

    assert profile.minimum_score() <= risk.raw_score <= profile.maximum_score()
    assert profile.score.minimum <= risk.score <= profile.score.maximum
