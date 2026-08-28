"""Educational elliptic-curve arithmetic and toy EC ElGamal encryption.

The implementation uses tiny prime fields and is intentionally transparent.
It is not constant-time and must not be used to protect real information.
"""

from dataclasses import dataclass
from math import gcd, isqrt
from typing import Optional, Tuple


Point = Optional[Tuple[int, int]]
INFINITY: Point = None


def is_prime(value: int) -> bool:
    """Return whether ``value`` is prime using trial division."""

    if value < 2:
        return False
    if value == 2:
        return True
    if value % 2 == 0:
        return False
    return all(value % divisor for divisor in range(3, isqrt(value) + 1, 2))


@dataclass(frozen=True)
class Curve:
    """A short-Weierstrass curve ``y^2 = x^3 + ax + b (mod p)``."""

    p: int
    a: int
    b: int

    def __post_init__(self) -> None:
        if self.p <= 3 or not is_prime(self.p):
            raise ValueError("field modulus p must be a prime greater than 3")
        if (4 * self.a**3 + 27 * self.b**2) % self.p == 0:
            raise ValueError("curve discriminant must be non-zero modulo p")

    def contains(self, point: Point) -> bool:
        """Return whether a point lies on this curve."""

        if point is INFINITY:
            return True
        x, y = point
        if not 0 <= x < self.p or not 0 <= y < self.p:
            return False
        return (y * y - (x**3 + self.a * x + self.b)) % self.p == 0


@dataclass(frozen=True)
class ECCKeyPair:
    """An educational ECC private scalar and public point."""

    curve: Curve
    generator: Point
    generator_order: int
    private_scalar: int
    public_point: Point


@dataclass(frozen=True)
class ECCCiphertext:
    """The two public points in a toy elliptic-curve ElGamal ciphertext."""

    c1: Point
    c2: Point


@dataclass(frozen=True)
class ECCEncryptionResult:
    """Legitimate-side values produced while encrypting a message point."""

    message_scalar: int
    message_point: Point
    ephemeral_scalar: int
    shared_point: Point
    ciphertext: ECCCiphertext


def format_point(point: Point) -> str:
    """Return a compact, console-friendly representation of a curve point."""

    return "O (point at infinity)" if point is INFINITY else f"({point[0]}, {point[1]})"


def negate_point(curve: Curve, point: Point) -> Point:
    """Return the additive inverse of ``point``."""

    if not curve.contains(point):
        raise ValueError("point is not on the curve")
    if point is INFINITY:
        return INFINITY
    return point[0], (-point[1]) % curve.p


def add_points(curve: Curve, left: Point, right: Point) -> Point:
    """Add two points using the elliptic-curve group law."""

    if not curve.contains(left) or not curve.contains(right):
        raise ValueError("both points must lie on the curve")
    if left is INFINITY:
        return right
    if right is INFINITY:
        return left

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return INFINITY

    if left == right:
        slope = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, curve.p)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, curve.p)
    slope %= curve.p

    x3 = (slope * slope - x1 - x2) % curve.p
    y3 = (slope * (x1 - x3) - y1) % curve.p
    result = x3, y3
    if not curve.contains(result):
        raise RuntimeError("point addition produced a point outside the curve")
    return result


def scalar_multiply(curve: Curve, scalar: int, point: Point) -> Point:
    """Compute ``scalar * point`` with double-and-add."""

    if not curve.contains(point):
        raise ValueError("point is not on the curve")
    if scalar < 0:
        return scalar_multiply(curve, -scalar, negate_point(curve, point))

    result = INFINITY
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = add_points(curve, result, addend)
        addend = add_points(curve, addend, addend)
        remaining >>= 1
    return result


def point_order(curve: Curve, point: Point) -> int:
    """Find a point's order with a classical loop suitable for tiny curves."""

    if point is INFINITY or not curve.contains(point):
        raise ValueError("generator must be a finite point on the curve")

    # Hasse's theorem bounds the number of points, and therefore point order.
    upper_bound = curve.p + 1 + 2 * isqrt(curve.p) + 2
    running = INFINITY
    for order in range(1, upper_bound + 1):
        running = add_points(curve, running, point)
        if running is INFINITY:
            return order
    raise RuntimeError("point order was not found inside the Hasse bound")


def generate_keypair(curve: Curve, generator: Point, private_scalar: int) -> ECCKeyPair:
    """Generate an educational ECC key pair from a public generator point."""

    order = point_order(curve, generator)
    if order < 5:
        raise ValueError("generator order is too small for this demonstration")
    if not 1 <= private_scalar < order:
        raise ValueError(f"private scalar d must satisfy 1 <= d < {order}")
    if gcd(private_scalar, order) != 1:
        raise ValueError("private scalar d must be coprime with the generator order")

    public_point = scalar_multiply(curve, private_scalar, generator)
    return ECCKeyPair(curve, generator, order, private_scalar, public_point)


def encrypt_message(
    keypair: ECCKeyPair,
    message_scalar: int,
    ephemeral_scalar: int,
) -> ECCEncryptionResult:
    """Encrypt a toy scalar-encoded message using EC ElGamal point operations."""

    order = keypair.generator_order
    if not 1 <= message_scalar < order:
        raise ValueError(f"message scalar m must satisfy 1 <= m < {order}")
    if not 1 <= ephemeral_scalar < order:
        raise ValueError(f"ephemeral scalar k must satisfy 1 <= k < {order}")
    if gcd(ephemeral_scalar, order) != 1:
        raise ValueError("ephemeral scalar k must be coprime with the generator order")

    message_point = scalar_multiply(keypair.curve, message_scalar, keypair.generator)
    c1 = scalar_multiply(keypair.curve, ephemeral_scalar, keypair.generator)
    shared_point = scalar_multiply(
        keypair.curve, ephemeral_scalar, keypair.public_point
    )
    c2 = add_points(keypair.curve, message_point, shared_point)
    return ECCEncryptionResult(
        message_scalar,
        message_point,
        ephemeral_scalar,
        shared_point,
        ECCCiphertext(c1, c2),
    )


def decrypt_point(curve: Curve, ciphertext: ECCCiphertext, private_scalar: int) -> Point:
    """Decrypt an EC ElGamal ciphertext to its original message point."""

    shared_point = scalar_multiply(curve, private_scalar, ciphertext.c1)
    return add_points(curve, ciphertext.c2, negate_point(curve, shared_point))


def decode_message_scalar(curve: Curve, generator: Point, order: int, point: Point) -> int:
    """Decode the toy ``m * G`` mapping with a tiny classical lookup loop."""

    for scalar in range(1, order):
        if scalar_multiply(curve, scalar, generator) == point:
            return scalar
    raise ValueError("message point is not in the generator subgroup")
