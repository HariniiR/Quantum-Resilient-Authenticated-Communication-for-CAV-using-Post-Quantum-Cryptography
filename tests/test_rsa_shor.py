"""Tests for the RSA demonstration."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.rsa_shor.demo import run_demo
from modules.rsa_shor.rsa import decrypt, encrypt, generate_keys
from modules.rsa_shor.shor_math import attack_rsa, find_order, recover_factors


class RSATests(unittest.TestCase):

    def test_encrypt_and_decrypt(self):
        n, phi, d = generate_keys(3, 5, 3)
        ciphertext = encrypt(2, n, 3)

        self.assertEqual(phi, 8)
        self.assertEqual(ciphertext, 8)
        self.assertEqual(decrypt(ciphertext, n, d), 2)

    def test_invalid_keys(self):
        with self.assertRaises(ValueError):
            generate_keys(3, 3, 3)
        with self.assertRaises(ValueError):
            generate_keys(3, 5, 2)


class ShorTests(unittest.TestCase):

    def test_order_finding(self):
        order, steps = find_order(2, 15)

        self.assertEqual(order, 4)
        self.assertEqual(steps, [(1, 2), (2, 4), (3, 8), (4, 1)])

    def test_factor_recovery(self):
        factor1, factor2, half_power = recover_factors(2, 4, 15)

        self.assertEqual((factor1, factor2), (3, 5))
        self.assertEqual(half_power, 4)

    def test_complete_attack(self):
        result = attack_rsa(15, 3, 8, 2)

        self.assertEqual((result["factor1"], result["factor2"]), (3, 5))
        self.assertEqual(result["d"], 3)
        self.assertEqual(result["message"], 2)

    def test_bad_a_is_rejected(self):
        with self.assertRaises(ValueError):
            attack_rsa(15, 3, 8, 3)
        with self.assertRaises(ValueError):
            attack_rsa(15, 3, 8, 14)


class DemoTests(unittest.TestCase):

    def test_interactive_demo(self):
        output = StringIO()
        inputs = ("5", "7", "5", "2", "2")

        with patch("builtins.input", side_effect=inputs):
            with redirect_stdout(output):
                run_demo()

        text = output.getvalue()
        self.assertIn("N = p * q = 5 * 7 = 35", text)
        self.assertIn("ATTACK SUCCESSFUL", text)
        self.assertIn("Plaintext recovered   : 2", text)


if __name__ == "__main__":
    unittest.main()
