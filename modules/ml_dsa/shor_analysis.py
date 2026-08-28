"""Scientific applicability analysis of Shor's algorithm against ML-DSA."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ShorApplicability:
    """A structured explanation of whether Shor has a direct attack target."""

    target_problems: str
    uses_integer_factorization: bool
    uses_discrete_logarithms: bool
    direct_shor_attack_known: bool
    conclusion: str


def analyze_shor_applicability() -> ShorApplicability:
    """Describe why Shor's factoring/discrete-log tools do not directly fit ML-DSA."""

    return ShorApplicability(
        target_problems="module-lattice problems including Module-LWE and Module-SIS",
        uses_integer_factorization=False,
        uses_discrete_logarithms=False,
        direct_shor_attack_known=False,
        conclusion=(
            "Shor's algorithm has no known direct efficient attack on the "
            "module-lattice assumptions underlying ML-DSA."
        ),
    )
