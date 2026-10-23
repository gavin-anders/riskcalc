"""
Package-level finalisation checks: public API surface and bundled profiles.
"""

import pytest

import riskcalc
from riskcalc.exceptions import RiskRequestException
from riskcalc.profiling import RiskProfile
from riskcalc.utils import list_profiles, load_profile

BUNDLED_NAMES = list_profiles()


def test_public_api_is_importable():
    for name in (
        "RiskCalculator",
        "RiskRequest",
        "RiskProfile",
        "Risk",
        "RiskContribution",
        "list_profiles",
        "load_profile",
        "yaml_to_profile",
        "yaml_to_risk_request",
    ):
        assert name in riskcalc.__all__
        assert getattr(riskcalc, name) is not None


def test_version_is_populated():
    assert riskcalc.__version__
    assert riskcalc.__version__ != "0.0.0+unknown"  # resolved from installed metadata


def test_bundled_profiles_are_discoverable():
    assert list_profiles() == [
        "critical-business",
        "default",
        "general",
        "internet-facing",
        "minimal",
        "threat-led",
    ]


@pytest.mark.parametrize("name", BUNDLED_NAMES)
def test_every_bundled_profile_validates(name):
    profile = load_profile(name)
    assert isinstance(profile, RiskProfile)
    assert profile.minimum_score() <= profile.maximum_score()


def test_load_profile_rejects_unknown_name():
    with pytest.raises(RiskRequestException) as exc:
        load_profile("no-such-profile")
    assert "no-such-profile" in str(exc.value)
    assert "Available:" in str(exc.value)
