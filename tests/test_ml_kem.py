"""Tests for the ML-KEM demonstration."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.ml_kem.demo import run_demo
from modules.ml_kem.ml_kem import run_ml_kem, shor_has_direct_attack


class MLKEMTests(unittest.TestCase):

    def test_all_versions(self):
        expected_sizes = {
            "1": (800, 1632, 768),
            "2": (1184, 2400, 1088),
            "3": (1568, 3168, 1568),
        }

        for choice, sizes in expected_sizes.items():
            result = run_ml_kem(choice)
            actual = (len(result["public_key"]), len(result["private_key"]),
                      len(result["ciphertext"]))

            self.assertEqual(actual, sizes)
            self.assertEqual(result["sender_secret"], result["receiver_secret"])

    def test_shor_result(self):
        self.assertFalse(shor_has_direct_attack())

    def test_interactive_demo(self):
        output = StringIO()

        with patch("builtins.input", side_effect=("1",)):
            with redirect_stdout(output):
                run_demo()

        text = output.getvalue()
        self.assertIn("Secrets match   = True", text)
        self.assertIn("Known direct Shor attack = False", text)
        self.assertIn("MODULE 3 SUCCESSFUL", text)


if __name__ == "__main__":
    unittest.main()
