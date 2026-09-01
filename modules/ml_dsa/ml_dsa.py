"""Simple wrapper around the standardized ML-DSA library."""

from typing import Dict


def get_algorithm(choice: str):
    """Return the name and library module selected by the user."""

    try:
        from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87
    except ImportError as error:
        raise RuntimeError(
            "Install dependencies with: python -m pip install -r requirements.txt"
        ) from error

    algorithms = {
        "1": ("ML-DSA-44", ml_dsa_44),
        "2": ("ML-DSA-65", ml_dsa_65),
        "3": ("ML-DSA-87", ml_dsa_87),
    }

    if choice not in algorithms:
        raise ValueError("choose 1, 2, or 3")
    return algorithms[choice]


def verify(algorithm, public_key: bytes, message: bytes,
           signature: bytes, context: bytes) -> bool:
    """Return True when the signature is valid."""

    from pqcrypto import InvalidSignatureError

    try:
        algorithm.verify(public_key, message, signature, context)
        return True
    except InvalidSignatureError:
        return False


def run_ml_dsa(choice: str, message: bytes, context: bytes) -> Dict[str, object]:
    """Generate keys, sign a message, and verify the signature."""

    name, algorithm = get_algorithm(choice)

    public_key, private_key = algorithm.keygen()
    signature = algorithm.sign(private_key, message, context)
    valid = verify(algorithm, public_key, message, signature, context)
    tampered_valid = verify(
        algorithm, public_key, message + b" [changed]", signature, context
    )

    return {
        "name": name,
        "public_key": public_key,
        "private_key": private_key,
        "signature": signature,
        "valid": valid,
        "tampered_valid": tampered_valid,
    }


def shor_has_direct_attack() -> bool:
    """Shor has no known direct attack on ML-DSA's lattice problems."""

    return False
