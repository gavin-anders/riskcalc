from __future__ import annotations

import json
from pathlib import Path

import click

from riskcalc.utils import (
    list_profiles,
    load_profile,
    yaml_to_profile,
    yaml_to_risk_request,
)
from riskcalc.calculator import RiskCalculator


##############################
#         Entrypoint         #
##############################
@click.group(help="Evaluate vulnerability risk from a request and a profile.")
def cli():
    """
    entrypoint for command line
    """
    pass


##############################
#       Calculate risk       #
##############################
@cli.command(help="Calculate risk for a request against a profile")
@click.option(
    "--request",
    "-r",
    "request_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the risk request YAML file",
)
@click.option(
    "--profile",
    "-p",
    "profile_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the risk profile YAML file",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit the result as JSON instead of the terminal report",
)
def calculate(request_file: Path, profile_file: Path, as_json: bool):
    """
    Load the request and profile, run the calculator and print the result.
    """
    try:
        request = yaml_to_risk_request(request_file)
        profile = yaml_to_profile(profile_file)
    except Exception as e:
        raise click.ClickException(str(e))

    risk = RiskCalculator(request, profile).calculate()

    if as_json:
        click.echo(risk.model_dump_json(indent=2))
    else:
        click.echo(risk.report)


##############################
#       List profiles        #
##############################
@cli.command(name="profiles", help="List the risk profiles bundled with the package")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit the list as JSON instead of a table",
)
def profiles(as_json: bool):
    """
    List the bundled profiles by the stem name accepted by load_profile(),
    along with each profile's declared name and version.
    """
    rows: list[dict[str, str | None]] = []
    for stem in list_profiles():
        try:
            profile = load_profile(stem)
            rows.append(
                {"profile": stem, "name": profile.name, "version": profile.version}
            )
        except Exception as e:
            rows.append(
                {"profile": stem, "name": None, "version": None, "error": str(e)}
            )

    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return

    width = max((len(row["profile"] or "") for row in rows), default=0)
    for row in rows:
        if row.get("error"):
            click.echo(f"{row['profile']:<{width}}  (failed to load: {row['error']})")
        else:
            click.echo(f"{row['profile']:<{width}}  {row['name']} (v{row['version']})")


def main():
    cli()
