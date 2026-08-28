"""Regression tests for Module 3's standardized ML-KEM operations."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from modules.ml_kem.backend import load_backend
from modules.ml_kem.demo import run_demo
from modules.ml_kem.shor_analysis import analyze_shor_applicability


class MLKEMBackendTests(unittest.TestCase):
    """Verify every supported ML-KEM parameter set end to end."""

    EXPECTED_SIZES = {
        "1": (800, 1632, 768, 32),
        "2": (1184, 2400, 1088, 32),
        "3": (1568, 3168, 1568, 32),
    }

    def test_all_parameter_sets_encapsulate_and_decapsulate(self) -> None:
        for selection, expected in self.EXPECTED_SIZES.items():
            with self.subTest(selection=selection):
                backend = load_backend(selection)
                public_key, secret_key = backend.keygen()
                ciphertext, sender_secret = backend.encaps(public_key)
                receiver_secret = backend.decaps(secret_key, ciphertext)

                self.assertEqual(
                    (
                        len(public_key),
                        len(secret_key),
                        len(ciphertext),
                        len(sender_secret),
                    ),
                    expected,
                )
                self.assertEqual(sender_secret, receiver_secret)

    def test_shor_analysis_does_not_fabricate_an_attack(self) -> None:
        analysis = analyze_shor_applicability()

        self.assertFalse(analysis.uses_integer_factorization)
        self.assertFalse(analysis.uses_discrete_logarithms)
        self.assertFalse(analysis.direct_shor_attack_known)


class InteractiveMLKEMDemoTests(unittest.TestCase):
    """Verify the complete Module 3 console presentation."""

    def test_ml_kem_512_demo(self) -> None:
        output = StringIO()
        with patch("builtins.input", side_effect=("1",)):
            with redirect_stdout(output):
                run_demo()

        presentation = output.getvalue()
        self.assertIn("Shared secrets match: True", presentation)
        self.assertIn("ML-KEM-512 encapsulation/decapsulation: SUCCESSFUL", presentation)
        self.assertIn("NO KNOWN DIRECTLY APPLICABLE ATTACK", presentation)


if __name__ == "__main__":
    unittest.main()
