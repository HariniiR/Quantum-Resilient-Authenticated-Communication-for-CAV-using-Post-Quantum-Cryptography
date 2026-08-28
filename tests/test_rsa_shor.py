"""Regression tests for Module 1's RSA and factoring mathematics."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.rsa_shor.demo import run_demo
from modules.rsa_shor.rsa import decrypt, encrypt, generate_keypair
from modules.rsa_shor.shor_math import (
    find_multiplicative_order,
    recover_factors_from_order,
    run_shor_math_attack,
)


class RSATests(unittest.TestCase):
    """Verify key generation, encryption, and input validation."""

    def test_toy_rsa_round_trip(self) -> None:
        key = generate_keypair(3, 5, 3)

        ciphertext = encrypt(2, key.public_key)

        self.assertEqual(ciphertext, 8)
        self.assertEqual(decrypt(ciphertext, key.n, key.d), 2)

    def test_equal_primes_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "different primes"):
            generate_keypair(3, 3, 3)

    def test_non_coprime_public_exponent_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "coprime"):
            generate_keypair(3, 5, 2)


class ShorMathTests(unittest.TestCase):
    """Verify order finding, factor recovery, retrying, and reconstruction."""

    def test_order_sequence_for_two_modulo_fifteen(self) -> None:
        result = find_multiplicative_order(2, 15)

        self.assertEqual(result.order, 4)
        self.assertEqual(result.sequence, ((1, 2), (2, 4), (3, 8), (4, 1)))

    def test_non_coprime_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "coprime"):
            find_multiplicative_order(3, 15)

    def test_odd_order_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "even"):
            recover_factors_from_order(4, 3, 21)

    def test_negative_one_half_power_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "-1"):
            recover_factors_from_order(14, 2, 15)

    def test_trivial_factors_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "trivial"):
            recover_factors_from_order(2, 2, 15)

    def test_attack_retries_and_reconstructs_private_values(self) -> None:
        result = run_shor_math_attack(15, 3, 8, (3, 14, 2))

        self.assertEqual(tuple(item.base for item in result.failed_attempts), (3, 14))
        self.assertEqual((result.factor1, result.factor2), (3, 5))
        self.assertEqual(result.recovered_phi, 8)
        self.assertEqual(result.recovered_d, 3)
        self.assertEqual(result.recovered_plaintext, 2)


class InteractiveDemoTests(unittest.TestCase):
    """Verify that the console demo uses user-supplied values end to end."""

    def test_demo_accepts_non_default_user_inputs(self) -> None:
        output = StringIO()
        # p=5, q=7, e=5, m=2, and a=2 form a second valid demonstration.
        with patch("builtins.input", side_effect=("5", "7", "5", "2", "2")):
            with redirect_stdout(output):
                run_demo()

        presentation = output.getvalue()
        self.assertIn("N = p * q = 5 * 7 = 35", presentation)
        self.assertIn("ATTACK SUCCESSFUL", presentation)
        self.assertIn("Recovered plaintext: 2", presentation)


if __name__ == "__main__":
    unittest.main()
