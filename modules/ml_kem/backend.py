"""Typed adapter for standardized ML-KEM implementations from ``pqcrypto``."""

from dataclasses import dataclass
from importlib import import_module
from types import ModuleType
from typing import Dict, Tuple


PARAMETER_SETS: Dict[str, str] = {
    "1": "ml_kem_512",
    "2": "ml_kem_768",
    "3": "ml_kem_1024",
}


class PQCBackendUnavailable(RuntimeError):
    """Raised when the required standardized PQC backend is not installed."""


@dataclass(frozen=True)
class MLKEMBackend:
    """A selected ML-KEM parameter set and its implementation module."""

    algorithm: str
    module: ModuleType

    @property
    def display_name(self) -> str:
        """Return the standardized hyphenated algorithm name."""

        return self.algorithm.upper().replace("_", "-")

    @property
    def public_key_size(self) -> int:
        return int(self.module.PUBLIC_KEY_SIZE)

    @property
    def secret_key_size(self) -> int:
        return int(self.module.SECRET_KEY_SIZE)

    @property
    def ciphertext_size(self) -> int:
        return int(self.module.CIPHERTEXT_SIZE)

    @property
    def shared_secret_size(self) -> int:
        return int(self.module.SHARED_SECRET_SIZE)

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a real ML-KEM encapsulation/decapsulation key pair."""

        return self.module.keygen()

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a fresh shared secret with an encapsulation key."""

        return self.module.encaps(public_key)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a ciphertext with the private decapsulation key."""

        return self.module.decaps(secret_key, ciphertext)


def load_backend(selection: str) -> MLKEMBackend:
    """Load one selected ML-KEM parameter set without breaking other modules."""

    try:
        algorithm = PARAMETER_SETS[selection]
    except KeyError as error:
        raise ValueError("unknown ML-KEM parameter selection") from error

    try:
        module = import_module(f"pqcrypto.kem.{algorithm}")
    except (ImportError, OSError) as error:
        raise PQCBackendUnavailable(
            "pqcrypto 1.0.0 is required; run: python -m pip install -r requirements.txt"
        ) from error
    return MLKEMBackend(algorithm, module)
