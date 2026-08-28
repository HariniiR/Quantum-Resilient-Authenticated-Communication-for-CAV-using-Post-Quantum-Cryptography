"""Regression tests for Module 2's ECC and Shor mathematics."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.ecc_shor.demo import run_demo
from modules.ecc_shor.ecc import (
    Curve,
    ECCCiphertext,
    add_points,
    decrypt_point,
    encrypt_message,
    generate_keypair,
    point_order,
    scalar_multiply,
)
from modules.ecc_shor.shor_math import run_ecc_shor_math_attack


class ECCArithmeticTests(unittest.TestCase):
    """Verify arithmetic on the documented toy curve."""

    def setUp(self) -> None:
        self.curve = Curve(17, 2, 2)
        self.generator = (5, 1)

    def test_generator_and_known_multiples(self) -> None:
        self.assertTrue(self.curve.contains(self.generator))
        self.assertEqual(point_order(self.curve, self.generator), 19)
        self.assertEqual(scalar_multiply(self.curve, 2, self.generator), (6, 3))
        self.assertEqual(scalar_multiply(self.curve, 7, self.generator), (0, 6))
        self.assertIsNone(scalar_multiply(self.curve, 19, self.generator))

    def test_point_plus_inverse_is_infinity(self) -> None:
        self.assertIsNone(add_points(self.curve, (5, 1), (5, 16)))

    def test_singular_curve_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "discriminant"):
            Curve(17, 0, 0)

    def test_off_curve_generator_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite point"):
            point_order(self.curve, (1, 1))


class ECCEncryptionAndAttackTests(unittest.TestCase):
    """Verify legitimate encryption and independent attacker recovery."""

    def setUp(self) -> None:
        self.curve = Curve(17, 2, 2)
        self.generator = (5, 1)
        self.key = generate_keypair(self.curve, self.generator, 7)

    def test_toy_ec_elgamal_round_trip(self) -> None:
        encryption = encrypt_message(self.key, 4, 3)

        self.assertEqual(self.key.public_point, (0, 6))
        self.assertEqual(
            encryption.ciphertext,
            ECCCiphertext(c1=(10, 6), c2=(16, 13)),
        )
        self.assertEqual(
            decrypt_point(self.curve, encryption.ciphertext, self.key.private_scalar),
            encryption.message_point,
        )

    def test_attack_recovers_private_scalar_and_message(self) -> None:
        encryption = encrypt_message(self.key, 4, 3)

        attack = run_ecc_shor_math_attack(
            self.curve,
            self.generator,
            self.key.generator_order,
            self.key.public_point,
            encryption.ciphertext,
        )

        self.assertEqual(attack.recovered_private_scalar, 7)
        self.assertEqual(attack.recovered_message_point, (3, 1))
        self.assertEqual(attack.recovered_message_scalar, 4)

    def test_private_scalar_range_is_validated(self) -> None:
        with self.assertRaisesRegex(ValueError, "private scalar"):
            generate_keypair(self.curve, self.generator, 19)


class InteractiveECCDemoTests(unittest.TestCase):
    """Verify the ECC console demo consumes user-supplied values."""

    def test_complete_interactive_ecc_flow(self) -> None:
        output = StringIO()
        inputs = ("17", "2", "2", "5", "1", "7", "4", "3")
        with patch("builtins.input", side_effect=inputs):
            with redirect_stdout(output):
                run_demo()

        presentation = output.getvalue()
        self.assertIn("Public point Q = dG", presentation)
        self.assertIn("Recovered private scalar: d = 7", presentation)
        self.assertIn("Recovered message scalar: m = 4", presentation)
        self.assertIn("ECC PRIVATE KEY COMPROMISED", presentation)


if __name__ == "__main__":
    unittest.main()
