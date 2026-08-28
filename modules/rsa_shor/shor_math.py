"""Classical demonstration of the mathematics in Shor's factoring workflow.

No quantum circuit, quantum simulator, or quantum hardware is used here. The
order-finding operation is deliberately implemented as a classical loop so a
small example can expose the attack's mathematical structure.
"""

from dataclasses import dataclass
from math import gcd
from typing import Iterable


@dataclass(frozen=True)
class OrderFindingResult:
    """A multiplicative order and the modular-power sequence used to find it."""

    order: int
    sequence: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class FailedAttempt:
    """An unsuitable base and the reason it could not recover factors."""

    base: int
    reason: str


@dataclass(frozen=True)
class ShorAttackResult:
    """Values independently reconstructed from attacker-visible information."""

    base: int
    order: int
    order_sequence: tuple[tuple[int, int], ...]
    half_power: int
    factor1: int
    factor2: int
    recovered_phi: int
    recovered_d: int
    recovered_plaintext: int
    failed_attempts: tuple[FailedAttempt, ...]


def find_multiplicative_order(a: int, n: int) -> OrderFindingResult:
    """Find the smallest positive ``r`` for which ``a**r == 1 (mod n)``.

    This exhaustive loop is educational and practical only for tiny integers.
    Actual Shor order finding obtains its speedup from a quantum subroutine.
    """

    if n <= 2:
        raise ValueError("N must be greater than 2")
    if not 1 < a < n:
        raise ValueError("a must satisfy 1 < a < N")
    if gcd(a, n) != 1:
        raise ValueError("a must be coprime with N")

    sequence: list[tuple[int, int]] = []
    # Euler's theorem guarantees an order no larger than phi(n), hence < n.
    for exponent in range(1, n):
        residue = pow(a, exponent, n)
        sequence.append((exponent, residue))
        if residue == 1:
            return OrderFindingResult(exponent, tuple(sequence))

    raise RuntimeError("multiplicative order was not found")


def recover_factors_from_order(a: int, order: int, n: int) -> tuple[int, int, int]:
    """Recover non-trivial factors using an even multiplicative order.

    Returns:
        ``(factor1, factor2, half_power)``, where ``half_power`` is
        ``a**(order/2) mod n``.
    """

    if gcd(a, n) != 1:
        raise ValueError("a must be coprime with N")
    if order % 2 != 0:
        raise ValueError("the recovered order r must be even")

    half_power = pow(a, order // 2, n)
    if half_power == n - 1:
        raise ValueError("a^(r/2) is congruent to -1 modulo N")

    factor1 = gcd(half_power - 1, n)
    factor2 = gcd(half_power + 1, n)
    if factor1 in (1, n) or factor2 in (1, n):
        raise ValueError("the GCD calculations produced trivial factors")
    if factor1 * factor2 != n:
        raise ValueError("the recovered values do not form a factorization of N")

    return factor1, factor2, half_power


def run_shor_math_attack(
    n: int,
    e: int,
    ciphertext: int,
    candidate_bases: Iterable[int],
) -> ShorAttackResult:
    """Reconstruct an RSA private key using only attacker-visible inputs.

    The function receives only ``n``, ``e``, the intercepted ciphertext, and
    candidate bases. It never receives or reads the legitimate values ``p``,
    ``q``, or ``d``. Unsuitable bases are recorded and the next base is tried.
    """

    if n <= 2:
        raise ValueError("N must be greater than 2")
    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < N")

    failures: list[FailedAttempt] = []
    for a in candidate_bases:
        if not 1 < a < n:
            failures.append(FailedAttempt(a, "a must satisfy 1 < a < N"))
            continue
        if gcd(a, n) != 1:
            failures.append(FailedAttempt(a, "gcd(a, N) is not 1"))
            continue

        order_result = find_multiplicative_order(a, n)
        try:
            factor1, factor2, half_power = recover_factors_from_order(
                a, order_result.order, n
            )
        except ValueError as error:
            failures.append(FailedAttempt(a, str(error)))
            continue

        recovered_phi = (factor1 - 1) * (factor2 - 1)
        if gcd(e, recovered_phi) != 1:
            failures.append(FailedAttempt(a, "e is not coprime with recovered phi(N)"))
            continue

        recovered_d = pow(e, -1, recovered_phi)
        recovered_plaintext = pow(ciphertext, recovered_d, n)
        return ShorAttackResult(
            base=a,
            order=order_result.order,
            order_sequence=order_result.sequence,
            half_power=half_power,
            factor1=factor1,
            factor2=factor2,
            recovered_phi=recovered_phi,
            recovered_d=recovered_d,
            recovered_plaintext=recovered_plaintext,
            failed_attempts=tuple(failures),
        )

    raise ValueError("none of the supplied bases recovered non-trivial factors")
