"""Small, educational RSA primitives used by the demonstration.

This module intentionally operates on tiny integers. It illustrates RSA's
mathematics; it is not suitable for real cryptographic use.
"""

from dataclasses import dataclass
from math import gcd, isqrt


@dataclass(frozen=True)
class RSAKeyPair:
    """The values produced during educational RSA key generation."""

    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int

    @property
    def public_key(self) -> tuple[int, int]:
        """Return the public key as ``(n, e)``."""

        return self.n, self.e


def _is_prime(value: int) -> bool:
    """Return whether *value* is prime using trial division."""

    if value < 2:
        return False
    if value == 2:
        return True
    if value % 2 == 0:
        return False
    return all(value % divisor for divisor in range(3, isqrt(value) + 1, 2))


def generate_keypair(p: int, q: int, e: int) -> RSAKeyPair:
    """Generate an educational RSA key pair from two primes and exponent ``e``.

    Raises:
        ValueError: If the supplied values cannot form a valid RSA key pair.
    """

    if not _is_prime(p) or not _is_prime(q):
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
    return RSAKeyPair(p=p, q=q, n=n, phi=phi, e=e, d=d)


def encrypt(message: int, public_key: tuple[int, int]) -> int:
    """Encrypt an integer message with the public key ``(n, e)``."""

    n, e = public_key
    if not 0 <= message < n:
        raise ValueError("message must satisfy 0 <= message < N")
    return pow(message, e, n)


def decrypt(ciphertext: int, n: int, d: int) -> int:
    """Decrypt an integer ciphertext with modulus ``n`` and private exponent ``d``."""

    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < N")
    return pow(ciphertext, d, n)
