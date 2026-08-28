"""Typed adapter for standardized ML-DSA implementations from ``pqcrypto``."""

from dataclasses import dataclass
from importlib import import_module
from types import ModuleType
from typing import Dict, Tuple


PARAMETER_SETS: Dict[str, str] = {
    "1": "ml_dsa_44",
    "2": "ml_dsa_65",
    "3": "ml_dsa_87",
}


class PQCBackendUnavailable(RuntimeError):
    """Raised when the required standardized PQC backend is not installed."""


@dataclass(frozen=True)
class MLDSABackend:
    """A selected ML-DSA parameter set and its implementation module."""

    algorithm: str
    module: ModuleType

    @property
    def display_name(self) -> str:
        return self.algorithm.upper().replace("_", "-")

    @property
    def public_key_size(self) -> int:
        return int(self.module.PUBLIC_KEY_SIZE)

    @property
    def secret_key_size(self) -> int:
        return int(self.module.SECRET_KEY_SIZE)

    @property
    def signature_size(self) -> int:
        return int(self.module.SIGNATURE_SIZE)

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a real ML-DSA verification/signing key pair."""

        return self.module.keygen()

    def sign(self, secret_key: bytes, message: bytes, context: bytes) -> bytes:
        """Sign a message with an optional FIPS 204 context string."""

        return self.module.sign(secret_key, message, context)

    def verify(
        self, public_key: bytes, message: bytes, signature: bytes, context: bytes
    ) -> bool:
        """Return whether an ML-DSA signature verifies."""

        try:
            self.module.verify(public_key, message, signature, context)
            return True
        except Exception as error:
            try:
                from pqcrypto import InvalidSignatureError
            except ImportError:
                raise error
            if isinstance(error, InvalidSignatureError):
                return False
            raise


def load_backend(selection: str) -> MLDSABackend:
    """Load one selected ML-DSA parameter set without breaking other modules."""

    try:
        algorithm = PARAMETER_SETS[selection]
    except KeyError as error:
        raise ValueError("unknown ML-DSA parameter selection") from error

    try:
        module = import_module(f"pqcrypto.sign.{algorithm}")
    except (ImportError, OSError) as error:
        raise PQCBackendUnavailable(
            "pqcrypto 1.0.0 is required; run: python -m pip install -r requirements.txt"
        ) from error
    return MLDSABackend(algorithm, module)
