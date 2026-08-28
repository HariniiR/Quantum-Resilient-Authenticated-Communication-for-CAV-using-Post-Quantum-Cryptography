"""Console presentation for Module 3: ML-KEM vs Shor's algorithm."""

from hashlib import sha256

from .backend import PARAMETER_SETS, PQCBackendUnavailable, MLKEMBackend, load_backend
from .shor_analysis import analyze_shor_applicability


WIDTH = 60


def _section(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(title)
    print("=" * WIDTH)


def _fingerprint(data: bytes) -> str:
    """Return a short non-secret identifier instead of dumping binary values."""

    return sha256(data).hexdigest()[:16] + "..."


def _read_backend() -> MLKEMBackend:
    """Prompt for an ML-KEM parameter set and load its backend."""

    while True:
        print("Choose a standardized parameter set:")
        print("  1. ML-KEM-512")
        print("  2. ML-KEM-768")
        print("  3. ML-KEM-1024")
        selection = input("Enter 1, 2, or 3: ").strip()
        if selection not in PARAMETER_SETS:
            print("Invalid selection. Please enter 1, 2, or 3.\n")
            continue
        return load_backend(selection)


def run_demo() -> None:
    """Run real ML-KEM operations and explain Shor's lack of a direct attack."""

    _section("ML-KEM VS SHOR'S ALGORITHM - MODULE 3")
    print("This module performs standardized ML-KEM key generation,")
    print("encapsulation, and decapsulation using the pqcrypto backend.")
    print("It does not implement or simulate a quantum circuit.")

    _section("[1] WHAT ML-KEM DOES")
    print("ML-KEM is a key-encapsulation mechanism, not direct message encryption.")
    print("It allows two parties to establish the same 32-byte shared secret:")
    print("  (encapsulation key, decapsulation key) = KeyGen()")
    print("  (ciphertext, sender secret) = Encaps(encapsulation key)")
    print("  receiver secret = Decaps(decapsulation key, ciphertext)")
    print()
    print("The shared secret can then be used with symmetric encryption in a")
    print("complete protocol; symmetric message encryption is outside this demo.")

    _section("[2] SECURITY FOUNDATION")
    print("ML-KEM is based on module-lattice mathematics, principally Module-LWE.")
    print("Its public equations include carefully sampled error/noise, so recovering")
    print("the short secret is not an integer-factorization or discrete-log problem.")
    print("The public modulus q = 3329 is not a secret RSA-style product; factoring")
    print("that public constant does not reveal the ML-KEM decapsulation key.")

    _section("[3] PARAMETER SELECTION")
    try:
        backend = _read_backend()
    except PQCBackendUnavailable as error:
        print(f"Backend unavailable: {error}")
        return
    print(f"Selected: {backend.display_name}")

    _section("[4] STANDARDIZED KEY GENERATION")
    public_key, secret_key = backend.keygen()
    print(f"Encapsulation key (public) size: {len(public_key)} bytes")
    print(f"Decapsulation key (private) size: {len(secret_key)} bytes")
    print(f"Public-key fingerprint: {_fingerprint(public_key)}")
    print("The private decapsulation key is retained by the receiver and not shown.")

    _section("[5] SENDER ENCAPSULATION")
    ciphertext, sender_secret = backend.encaps(public_key)
    print("The sender uses only the public encapsulation key.")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Ciphertext fingerprint: {_fingerprint(ciphertext)}")
    print(f"Sender shared-secret fingerprint: {_fingerprint(sender_secret)}")

    _section("[6] RECEIVER DECAPSULATION")
    receiver_secret = backend.decaps(secret_key, ciphertext)
    secrets_match = sender_secret == receiver_secret
    print("The receiver uses the private decapsulation key and ciphertext.")
    print(f"Receiver shared-secret fingerprint: {_fingerprint(receiver_secret)}")
    print(f"Shared secrets match: {secrets_match}")
    if not secrets_match:
        raise RuntimeError("ML-KEM encapsulation and decapsulation did not agree")

    _section("[7] INFORMATION BOUNDARY")
    print("RECEIVER KEEPS SECRET:")
    print(f"  Decapsulation key ({len(secret_key)} bytes)")
    print(f"  Shared secret ({len(receiver_secret)} bytes)")
    print()
    print("ATTACKER MAY KNOW:")
    print(f"  {backend.display_name} algorithm and public parameters")
    print(f"  Encapsulation key ({len(public_key)} bytes)")
    print(f"  Intercepted ciphertext ({len(ciphertext)} bytes)")
    print()
    print("The attacker does not receive the decapsulation key or shared secret.")

    _section("[8] SHOR APPLICABILITY CHECK")
    analysis = analyze_shor_applicability()
    print(f"Underlying target: {analysis.target_problem}")
    print(f"Depends on integer factorization: {analysis.uses_integer_factorization}")
    print(f"Depends on discrete logarithms: {analysis.uses_discrete_logarithms}")
    print(f"Known direct Shor attack: {analysis.direct_shor_attack_known}")
    print()
    print("Shor efficiently addresses factoring and discrete logarithms. ML-KEM")
    print("does not expose either of those structures as its security problem.")
    print("Shor's algorithm has no known direct efficient attack on the")
    print("Module-LWE problem underlying ML-KEM.")
    print()
    print("This is not a proof of immunity to every possible future quantum attack;")
    print("it states that Shor's known method does not directly solve Module-LWE.")

    _section("MODULE 3 RESULT")
    print(f"{backend.display_name} encapsulation/decapsulation: SUCCESSFUL")
    print("SHOR RESULT: NO KNOWN DIRECTLY APPLICABLE ATTACK")

    _section("[9] FINAL CONCLUSION")
    print("Unlike RSA and ECC, ML-KEM was designed around module-lattice problems")
    print("rather than factorization or discrete logarithms. Shor's algorithm does")
    print("not provide a known efficient method for recovering an ML-KEM private")
    print("key. This module used real ML-KEM operations and made no quantum-")
    print("security claim beyond the absence of a known direct Shor attack.")
