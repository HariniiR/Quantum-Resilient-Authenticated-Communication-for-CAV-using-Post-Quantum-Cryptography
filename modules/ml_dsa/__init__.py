"""ML-DSA demonstration module."""

from .demo import run_demo
from .ml_dsa import get_algorithm, run_ml_dsa, shor_has_direct_attack, verify

__all__ = ["get_algorithm", "run_demo", "run_ml_dsa",
           "shor_has_direct_attack", "verify"]
