"""Small RSA functions for the classroom demonstration."""

from math import gcd, isqrt
from typing import Tuple


def is_prime(number: int) -> bool:
    """Check whether a number is prime."""

    if number < 2:
        return False

    for divisor in range(2, isqrt(number) + 1):
        if number % divisor == 0:
            return False
    return True

def generate_keys(p: int, q: int, e: int) -> Tuple[int, int, int]:
    """Return N, phi(N), and the private exponent d."""

    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must both be prime")
    if p == q:
        raise ValueError("p and q must be different primes")

    n = p * q
    phi = (p - 1) * (q - 1)

    if not 1 < e < phi:
        raise ValueError("e must satisfy 1 < e < phi(N)")
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi(N)")

    d = pow(e, -1, phi)
    return n, phi, d


def encrypt(message: int, n: int, e: int) -> int:
    """Encrypt an integer using the public key (N, e)."""

    if not 0 <= message < n:
        raise ValueError("message must satisfy 0 <= message < N")
    return pow(message, e, n)


def decrypt(ciphertext: int, n: int, d: int) -> int:
    """Decrypt an integer using the private exponent d."""

    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < N")
    return pow(ciphertext, d, n)
