"""Regression tests for Module 4's standardized ML-DSA operations."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.ml_dsa.backend import load_backend
from modules.ml_dsa.demo import run_demo
from modules.ml_dsa.shor_analysis import analyze_shor_applicability


class MLDSABackendTests(unittest.TestCase):
    """Verify every supported ML-DSA parameter set end to end."""

    EXPECTED_SIZES = {
        "1": (1312, 2560, 2420),
        "2": (1952, 4032, 3309),
        "3": (2592, 4896, 4627),
    }

    def test_all_parameter_sets_sign_and_verify(self) -> None:
        message = b"ML-DSA regression message"
        context = b"college-demo"
        for selection, expected in self.EXPECTED_SIZES.items():
            with self.subTest(selection=selection):
                backend = load_backend(selection)
                public_key, secret_key = backend.keygen()
                signature = backend.sign(secret_key, message, context)

                self.assertEqual(
                    (len(public_key), len(secret_key), len(signature)), expected
                )
                self.assertTrue(
                    backend.verify(public_key, message, signature, context)
                )
                self.assertFalse(
                    backend.verify(public_key, message + b"!", signature, context)
                )

    def test_shor_analysis_does_not_fabricate_an_attack(self) -> None:
        analysis = analyze_shor_applicability()

        self.assertFalse(analysis.uses_integer_factorization)
        self.assertFalse(analysis.uses_discrete_logarithms)
        self.assertFalse(analysis.direct_shor_attack_known)


class InteractiveMLDSADemoTests(unittest.TestCase):
    """Verify the complete Module 4 console presentation."""

    def test_ml_dsa_44_demo(self) -> None:
        output = StringIO()
        inputs = ("1", "Panel demonstration", "college-panel")
        with patch("builtins.input", side_effect=inputs):
            with redirect_stdout(output):
                run_demo()

        presentation = output.getvalue()
        self.assertIn("Original message verifies: True", presentation)
        self.assertIn("Modified message verifies with same signature: False", presentation)
        self.assertIn("ML-DSA-44 key generation/sign/verify: SUCCESSFUL", presentation)
        self.assertIn("NO KNOWN DIRECTLY APPLICABLE ATTACK", presentation)


if __name__ == "__main__":
    unittest.main()
