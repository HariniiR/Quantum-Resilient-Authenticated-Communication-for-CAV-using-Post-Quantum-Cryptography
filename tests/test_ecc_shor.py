"""Tests for the ECC demonstration."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.ecc_shor.demo import run_demo
from modules.ecc_shor.ecc import (add_points, create_keypair, decrypt,
                                  encrypt, make_curve, multiply, point_order)
from modules.ecc_shor.shor_math import attack_ecc


class ECCTests(unittest.TestCase):

    def setUp(self):
        self.curve = make_curve(17, 2, 2)
        self.generator = (5, 1)

    def test_point_math(self):
        self.assertEqual(multiply(self.curve, 2, self.generator), (6, 3))
        self.assertEqual(multiply(self.curve, 7, self.generator), (0, 6))
        self.assertEqual(point_order(self.curve, self.generator), 19)
        self.assertIsNone(add_points(self.curve, (5, 1), (5, 16)))

    def test_encrypt_and_decrypt(self):
        order, public_key = create_keypair(self.curve, self.generator, 7)
        encrypted = encrypt(self.curve, self.generator, public_key, order, 4, 3)

        self.assertEqual(public_key, (0, 6))
        self.assertEqual((encrypted["c1"], encrypted["c2"]),
                         ((10, 6), (16, 13)))
        self.assertEqual(decrypt(self.curve, encrypted["c1"],
                                 encrypted["c2"], 7), (3, 1))

    def test_complete_attack(self):
        order, public_key = create_keypair(self.curve, self.generator, 7)
        encrypted = encrypt(self.curve, self.generator, public_key, order, 4, 3)
        result = attack_ecc(self.curve, self.generator, public_key, order,
                            encrypted["c1"], encrypted["c2"])

        self.assertEqual(result["d"], 7)
        self.assertEqual(result["message"], 4)

    def test_interactive_demo(self):
        output = StringIO()
        inputs = ("17", "2", "2", "5", "1", "7", "4", "3")

        with patch("builtins.input", side_effect=inputs):
            with redirect_stdout(output):
                run_demo()

        text = output.getvalue()
        self.assertIn("Recovered private key d = 7", text)
        self.assertIn("Recovered message m = 4", text)
        self.assertIn("ATTACK SUCCESSFUL", text)


if __name__ == "__main__":
    unittest.main()
