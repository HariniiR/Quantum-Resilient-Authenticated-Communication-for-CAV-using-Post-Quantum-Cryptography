"""Simple wrapper around the standardized ML-KEM library."""

from typing import Dict, Tuple


def get_algorithm(choice: str):
    """Return the name and library module selected by the user."""

    try:
        from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
    except ImportError as error:
        raise RuntimeError(
            "Install dependencies with: python -m pip install -r requirements.txt"
        ) from error

    algorithms = {
        "1": ("ML-KEM-512", ml_kem_512),
        "2": ("ML-KEM-768", ml_kem_768),
        "3": ("ML-KEM-1024", ml_kem_1024),
    }

    if choice not in algorithms:
        raise ValueError("choose 1, 2, or 3")
    return algorithms[choice]


def run_ml_kem(choice: str) -> Dict[str, object]:
    """Generate keys, encapsulate, and decapsulate a shared secret."""

    name, algorithm = get_algorithm(choice)

    public_key, private_key = algorithm.keygen()
    ciphertext, sender_secret = algorithm.encaps(public_key)
    receiver_secret = algorithm.decaps(private_key, ciphertext)

    return {
        "name": name,
        "public_key": public_key,
        "private_key": private_key,
        "ciphertext": ciphertext,
        "sender_secret": sender_secret,
        "receiver_secret": receiver_secret,
    }


def shor_has_direct_attack() -> bool:
    """Shor has no known direct attack on Module-LWE."""

    return False
