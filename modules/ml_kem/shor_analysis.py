"""Scientific applicability analysis of Shor's algorithm against ML-KEM."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ShorApplicability:
    """A structured explanation of whether Shor has a direct attack target."""

    target_problem: str
    uses_integer_factorization: bool
    uses_discrete_logarithms: bool
    direct_shor_attack_known: bool
    conclusion: str


def analyze_shor_applicability() -> ShorApplicability:
    """Describe why Shor's factoring/discrete-log tools do not directly fit ML-KEM."""

    return ShorApplicability(
        target_problem="Module Learning With Errors (Module-LWE)",
        uses_integer_factorization=False,
        uses_discrete_logarithms=False,
        direct_shor_attack_known=False,
        conclusion=(
            "Shor's algorithm has no known direct efficient attack on the "
            "Module-LWE problem underlying ML-KEM."
        ),
    )
