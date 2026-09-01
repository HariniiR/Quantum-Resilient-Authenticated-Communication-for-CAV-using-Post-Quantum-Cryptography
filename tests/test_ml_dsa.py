"""Tests for the ML-DSA demonstration."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.ml_dsa.demo import run_demo
from modules.ml_dsa.ml_dsa import run_ml_dsa, shor_has_direct_attack


class MLDSATests(unittest.TestCase):

    def test_all_versions(self):
        expected_sizes = {
            "1": (1312, 2560, 2420),
            "2": (1952, 4032, 3309),
            "3": (2592, 4896, 4627),
        }

        for choice, sizes in expected_sizes.items():
            result = run_ml_dsa(choice, b"Test message", b"college-demo")
            actual = (len(result["public_key"]), len(result["private_key"]),
                      len(result["signature"]))

            self.assertEqual(actual, sizes)
            self.assertTrue(result["valid"])
            self.assertFalse(result["tampered_valid"])

    def test_shor_result(self):
        self.assertFalse(shor_has_direct_attack())

    def test_interactive_demo(self):
        output = StringIO()
        inputs = ("1", "Panel message", "college")

        with patch("builtins.input", side_effect=inputs):
            with redirect_stdout(output):
                run_demo()

        text = output.getvalue()
        self.assertIn("Original message valid = True", text)
        self.assertIn("Changed message valid  = False", text)
        self.assertIn("MODULE 4 SUCCESSFUL", text)


if __name__ == "__main__":
    unittest.main()
