from __future__ import annotations

from riskcalc.request import RiskRequest
from riskcalc.profiling import RiskProfile
from riskcalc.risk import Risk, RiskContribution


class RiskCalculator:
    """
    Calculates evaluated risk from a RiskRequest and RiskProfile.

    The calculator is responsible for:

    1. Calculating the initial vulnerability contribution.
    2. Evaluating supplied request contexts against the corresponding
       profile contexts.
    3. Collecting all score contributions.
    4. Tracking context that could not be evaluated.
    5. Producing the raw score.
    6. Normalising the raw score to the configured output range.
    7. Determining the final risk rating.
    """

    def __init__(
        self,
        request: RiskRequest,
        profile: RiskProfile,
    ):
        self.request = request
        self.profile = profile

        self.contributions: list[RiskContribution] = []
        self.missing_context: list[str] = []

    @property
    def raw_score(self) -> float:
        """
        Return the total raw score from all evaluated contributions.

        Contributions are the source of truth for the raw score.
        """
        return sum(contribution.value for contribution in self.contributions)

    def add_contribution(
        self,
        field: str,
        reason: str,
        score: float | int,
    ) -> None:
        """
        Add an evaluated score contribution.
        """
        self.contributions.append(
            RiskContribution(
                source=field,
                reason=reason,
                value=float(score),
            )
        )

    def _load_initial_score(self) -> None:
        """
        Calculate the initial vulnerability contribution.

        For V1 the base vulnerability score is derived from CVSS.

        Example:

            CVSS: 7.0
            configured weight: 30

            (7.0 / 10) * 30 = 21
        """
        value = self.profile.vulnerability.calculate_base_score(
            self.request.vulnerability.cvss.score
        )

        self.add_contribution(
            field="vulnerability.cvss",
            reason="Initial CVSS score contribution",
            score=value,
        )

    def _evaluate_contexts(self) -> None:
        """
        Evaluate each supplied request context against its corresponding
        profile context.
        """
        for ctx_name, request_ctx in self.request.contexts.context_values():

            if request_ctx is None:
                continue

            profile_ctx = self.profile.contexts.get_context(ctx_name)

            # A request may contain context which a profile does not use.
            # This does not make the risk calculation invalid.
            if profile_ctx is None:
                continue

            results = profile_ctx.evaluate(request_ctx)

            for field_name, score in results.items():

                # None means the field could not be evaluated.
                # Zero is a legitimate score contribution.
                if score is None:
                    self.missing_context.append(f"{ctx_name}.{field_name}")
                    continue

                self.add_contribution(
                    field=f"{ctx_name}.{field_name}",
                    reason=f"Contribution from context '{ctx_name}.{field_name}'",
                    score=score,
                )

    def _normalise_score(self, raw_score: float) -> float:
        """
        Normalise the raw score to the configured score range.

        The profile is responsible for exposing the theoretical minimum
        and maximum raw scores available from its configuration.

        The result is projected onto the configured output score range.
        """
        raw_min = self.profile.minimum_score()
        raw_max = self.profile.maximum_score()

        output_min = self.profile.score.minimum
        output_max = self.profile.score.maximum

        if raw_max == raw_min:
            return float(output_min)

        normalised = (raw_score - raw_min) / (raw_max - raw_min)

        score = output_min + normalised * (output_max - output_min)

        return max(
            output_min,
            min(output_max, score),
        )

    def calculate(self) -> Risk:
        """
        Perform the complete risk calculation.
        """
        # Make repeated calls deterministic.
        self.contributions.clear()
        self.missing_context.clear()

        self._load_initial_score()
        self._evaluate_contexts()

        raw_score = self.raw_score
        score = self._normalise_score(raw_score)

        rating = self.profile.rating_for(score)

        return Risk(
            raw_score=raw_score,
            score=score,
            rating=rating,
            contributions=list(self.contributions),
            missing_context=list(self.missing_context),
        )
