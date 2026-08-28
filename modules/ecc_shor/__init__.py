"""ECC and Shor discrete-logarithm workflow demonstration."""

from .demo import run_demo
from .ecc import (
    Curve,
    ECCCiphertext,
    ECCKeyPair,
    Point,
    decrypt_point,
    encrypt_message,
    generate_keypair,
    point_order,
    scalar_multiply,
)
from .shor_math import ECCShorAttackResult, run_ecc_shor_math_attack

__all__ = [
    "Curve",
    "ECCCiphertext",
    "ECCKeyPair",
    "ECCShorAttackResult",
    "Point",
    "decrypt_point",
    "encrypt_message",
    "generate_keypair",
    "point_order",
    "run_demo",
    "run_ecc_shor_math_attack",
    "scalar_multiply",
]
