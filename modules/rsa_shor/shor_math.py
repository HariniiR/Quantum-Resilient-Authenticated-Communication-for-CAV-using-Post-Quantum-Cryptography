"""Classical demonstration of the mathematics used in Shor's attack."""

from math import gcd
from typing import Dict, List, Tuple


def find_order(a: int, n: int) -> Tuple[int, List[Tuple[int, int]]]:
    """Find the smallest r for which a^r is 1 modulo N."""

    if not 1 < a < n:
        raise ValueError("a must satisfy 1 < a < N")
    if gcd(a, n) != 1:
        raise ValueError("a must be coprime with N")

    steps = []
    value = 1

    for r in range(1, n):
        value = (value * a) % n
        steps.append((r, value))

        if value == 1:
            return r, steps

    raise ValueError("order could not be found")


def recover_factors(a: int, r: int, n: int) -> Tuple[int, int, int]:
    """Use an even order to recover two non-trivial factors of N."""

    if gcd(a, n) != 1:
        raise ValueError("a must be coprime with N")
    if r % 2 != 0:
        raise ValueError("the order r must be even")

    half_power = pow(a, r // 2, n)
    if half_power == n - 1:
        raise ValueError("a^(r/2) is -1 modulo N")

    factor1 = gcd(half_power - 1, n)
    factor2 = gcd(half_power + 1, n)

    if factor1 in (1, n) or factor2 in (1, n):
        raise ValueError("this value of a gives trivial factors")
    if factor1 * factor2 != n:
        raise ValueError("the recovered values do not factor N")

    return factor1, factor2, half_power


def attack_rsa(n: int, e: int, ciphertext: int, a: int) -> Dict[str, object]:
    """Recover the RSA private key using only attacker-known values."""

    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < N")

    order, steps = find_order(a, n)
    factor1, factor2, half_power = recover_factors(a, order, n)

    recovered_phi = (factor1 - 1) * (factor2 - 1)
    if gcd(e, recovered_phi) != 1:
        raise ValueError("e is not coprime with the recovered phi(N)")

    recovered_d = pow(e, -1, recovered_phi)
    recovered_message = pow(ciphertext, recovered_d, n)

    return {
        "a": a,
        "order": order,
        "steps": steps,
        "half_power": half_power,
        "factor1": factor1,
        "factor2": factor2,
        "phi": recovered_phi,
        "d": recovered_d,
        "message": recovered_message,
    }
