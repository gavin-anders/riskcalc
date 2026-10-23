# riskcalc

Most teams triage known vulnerabilities with a raw CVSS number and zero context.
The score ignores their environment and external contextual contributors which might see
the risk of the vulnerability go from a low to high risk or a high risk vastly reduced
due to environmenal mitigating factors. Often these adjustments live in someone's head, and
the result can't be explained or easiy reproduced. `riskcalc` turns that into a small
calculation using a repeatable and simple to use algorithm - supply the vulnerability, 
the context you know, and get back a revised risk score out of 100 with every contribution
accounted for. Once the context has been established these can then be saved as profile for the
calculator to reuse. Once profiles are saved and shared as YAML, the calculator interface 
serves many use cases; an analyst at a terminal, a build step in CI, or a security tool
embedding the library as a dependency.

Its possible to evaluate the risk of a **known** vulnerability from three key inputs, 
which can be thought of as a simple calculation.

    vulnerability + (context * weights) = evaluated risk

- **vulnerability** - properties of the issue itself (CVSS, CVE/CWE ids)
- **context** - data points about where it exists and what is known about exploitation
  (threat intel, environment, controls, business impact, remediation, exposure, etc)
- **weight** - constant weighted values for the context, served and saved as "profiles"

## Use cases

- **Standalone terminal** - an analyst/consultant scores a known CVE by hand
  with `riskcalc calculate`, reads the explained report (every contribution and
  the context it could not evaluate), and compares policies by swapping
  `--profile`.

- **CI/CD** - run `riskcalc calculate --json`, parse `score` / `rating`, and
  fail the build above a threshold; keep `profile.yaml` in the repo so scoring
  changes go through review. 

- **Embedded as a library** - a vulnerability scanner platform or SOAR
  playbook imports `RiskCalculator` to score findings in bulk, building
  `RiskRequest` / `RiskProfile` from its own data and re-scoring the backlog
  upon request.

## Install

```bash
pip install riskcalc

OR

uv sync
```

Requires Python 3.11+.

`RiskRequest` and `RiskProfile` are plain Pydantic models making them easy to build 
directly or load from YAML with `yaml_to_risk_request` / `yaml_to_profile` /
`load_profile`.

## CLI

```bash
$ riskcalc
Usage: riskcalc [OPTIONS] COMMAND [ARGS]...

  Evaluate vulnerability risk from a request and a profile.

Options:
  --help  Show this message and exit.

Commands:
  calculate  Calculate risk for a request against a profile

$ riskcalc calculate --request example/request.yaml --profile example/profile.yaml
Evaluated at: 2026-10-23 10:21:10.650670
Raw score: 309.0
Score: 91.36029411764706
Rating: critical
Contributions:
  - vulnerability.cvss (7.0)
  - threat_intel.epss (15.0)
  - threat_intel.kev (20.0)
  - threat_intel.exploit_available (90.0)
  - environment.deployment_environment (0.0)
  - environment.privileged_network_location (8.0)
  - control.edr_present (-5.0)
  - control.waf_present (-5.0)
  - control.network_segmentation (-5.0)
  - control.mfa_enforced (-5.0)
  - control.firewall (-3.0)
  - business.asset_criticality (10.0)
  - business.business_impact (15.0)
  - business.data_sensitivity (7.0)
  - business.customer_facing (5.0)
  - business.revenue_generating (5.0)
  - business.regulatory_scope (5.0)
  - business.safety_critical (15.0)
  - remediation.patch_available (-3.0)
  - remediation.workaround_available (-2.0)
  - remediation.remediation_complexity (7.0)
  - exposure.internet_access (90.0)
  - exposure.reachable_from_public (15.0)
  - exposure.reachable_from_user_networks (5.0)
  - exposure.reachable_from_untrusted_networks (10.0)
  - exposure.authentication_boundary_crossed (8.0)
Missing context: 

```

## Library

```python
from riskcalc import RiskCalculator, load_profile, yaml_to_risk_request

request = yaml_to_risk_request("example/request.yaml")
profile = load_profile("default")          # a bundled profile, by name

risk = RiskCalculator(request, profile).calculate()

print(risk.score)             # normalised to the profile's output range
print(risk.rating)            # RiskRating enum: informational … critical
print(risk.raw_score)         # score before normalisation
for c in risk.contributions:  # what moved the score, and why
    print(f"{c.source:40} {c.value:+}  {c.reason}")
print(risk.missing_context)   # request context with no profile counterpart / no value
```

## Bundled profiles

Riskcalc comes with its own premade profiles. List them with `riskcalc profiles` or 
`riskcalc.list_profiles()`:

| name | intent |
| --- | --- |
| `default` | balanced general-purpose scoring |
| `minimal` | only a handful of high-signal facts |
| `general` | broad coverage, moderate weights |
| `internet-facing` | weights exposure and reachability heavily |
| `threat-led` | weights active-exploitation signals heavily |
| `critical-business` | weights asset criticality and business impact heavily |

## Context fields

The following table shows the range of fields that can be set for the context. The
 **default profile** column shows the contribution range each field can
add or subtract under the bundled `default` profile. Ranges are policy, not
fact: if your internal security policy dictates that any vuln that has an exploit available
should be of a high priority for remediation, the corresponding weights within the profile
can we tweaked to place a stronger weight towards the `true` value assocaited with the 
`exploit_available` field within your profile. Upon completion of the calculation the risk 
score is slightly higher due to this field's contribution.

Each context groups related fields of one kind. Every field is optional - supply what you
know; anything you leave out is reported back as missing context. The more context and 
fields you fill out the more accurate your score is at the end!

### `threat_intel` - what is known about exploitation

| field | meaning | default profile |
| --- | --- | --- |
| `epss` | EPSS probability (0-1) that the flaw will be exploited in the wild | `0 … +15` (tiered at 0.40 / 0.70 / 0.90) |
| `kev` | listed in CISA's Known Exploited Vulnerabilities catalogue | `−20 … +20` |
| `exploit_available` | a working exploit is publicly available | `−50 … +90` |

### `environment` - where the affected system runs

| field | meaning | default profile |
| --- | --- | --- |
| `deployment_environment` | lifecycle of the host: `development`, `test`, `staging`, `pre_production`, `production`, `disaster_recovery`, `unknown` | `0 … +10` |
| `privileged_network_location` | the system sits in a trusted or high-value network zone | `0 … +8` |

### `control` - mitigating controls in place around it

| field | meaning | default profile |
| --- | --- | --- |
| `edr_present` | endpoint detection and response is running on the host | `−5 … 0` |
| `waf_present` | a web application firewall protects the service | `−5 … 0` |
| `network_segmentation` | the system is isolated by network segmentation | `−5 … 0` |
| `mfa_enforced` | multi-factor authentication is required to reach it | `−5 … 0` |
| `firewall` | a host or network firewall restricts traffic to it | `−3 … 0` |

### `business` - what the asset is worth to the organisation

| field | meaning | default profile |
| --- | --- | --- |
| `asset_criticality` | importance of the affected asset: `low`, `medium`, `high`, `critical` | `0 … +15` |
| `business_impact` | severity of business consequences if exploited: `low`, `medium`, `high`, `critical` | `0 … +15` |
| `data_sensitivity` | sensitivity of data handled: `public`, `internal`, `confidential`, `restricted` | `0 … +12` |
| `customer_facing` | the system is used directly by customers | `0 … +5` |
| `revenue_generating` | the system directly supports revenue | `0 … +5` |
| `regulatory_scope` | the system falls under regulatory or compliance obligations | `0 … +5` |
| `safety_critical` | failure could cause physical harm | `0 … +15` |

### `remediation` - how hard the fix is

| field | meaning | default profile |
| --- | --- | --- |
| `patch_available` | an official fix or patch exists | `−3 … +3` |
| `workaround_available` | a mitigation or workaround exists short of patching | `−2 … +2` |
| `remediation_complexity` | effort and risk to remediate: `low`, `medium`, `high` | `0 … +7` |

### `exposure` - who can reach the vulnerable component

| field | meaning | default profile |
| --- | --- | --- |
| `internet_access` | the system can reach or be reached from the internet | `−90 … +90` |
| `reachable_from_public` | an attacker on the public internet can reach the component | `0 … +15` |
| `reachable_from_user_networks` | reachable from general internal user networks | `0 … +5` |
| `reachable_from_untrusted_networks` | reachable from untrusted or third-party networks | `0 … +10` |
| `authentication_boundary_crossed` | reaching it crosses an authentication boundary | `0 … +8` |


## Development

```bash
uv sync
uv run pytest
uv run black .
uv build
```

## License

Apache-2.0. See [LICENSE](LICENSE).
