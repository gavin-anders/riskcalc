from __future__ import annotations

import yaml
from importlib.resources import files
from pathlib import Path

from riskcalc.request import RiskRequest
from riskcalc.exceptions import RiskRequestException
from riskcalc.profiling import RiskProfile

BUNDLED_PROFILES = "riskcalc.profiles"


def yaml_to_risk_request(req_file: Path | str) -> RiskRequest:
    """
    Load a risk request definition from a YAML file.
    """
    if isinstance(req_file, str):
        req_file = Path(req_file)

    if not req_file.exists():
        raise RiskRequestException(f"Risk request file `{req_file}` does not exist")

    with req_file.open("r") as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)

    request = RiskRequest.model_validate(data)
    return request


def yaml_to_profile(profile_file: Path | str) -> RiskProfile:
    """
    Load a risk profile definition from a YAML file.
    """
    if isinstance(profile_file, str):
        profile_file = Path(profile_file)

    if not profile_file.exists():
        raise RiskRequestException(f"Risk profile file `{profile_file}` does not exist")

    with profile_file.open("r") as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)

    profile = RiskProfile.model_validate(data)
    return profile


def list_profiles() -> list[str]:
    """
    Return the sorted file stems of the risk profiles bundled with the package
    (the names accepted by load_profile).
    """
    return sorted(
        r.name.removesuffix(".yaml")
        for r in files(BUNDLED_PROFILES).iterdir()
        if r.name.endswith(".yaml")
    )


def load_profile(name: str) -> RiskProfile:
    """
    Load one of the risk profiles bundled with the package by its file stem
    (e.g. "default", "minimal", "internet-facing").
    """
    resource = files(BUNDLED_PROFILES).joinpath(f"{name}.yaml")

    if not resource.is_file():
        raise RiskRequestException(
            f"No bundled profile named {name!r}. "
            f"Available: {', '.join(list_profiles())}"
        )

    data = yaml.load(resource.read_text(), Loader=yaml.SafeLoader)
    return RiskProfile.model_validate(data)
