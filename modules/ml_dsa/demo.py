"""Console presentation for Module 4: ML-DSA vs Shor's algorithm."""

from hashlib import sha256

from .backend import PARAMETER_SETS, MLDSABackend, PQCBackendUnavailable, load_backend
from .shor_analysis import analyze_shor_applicability


WIDTH = 60


def _section(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(title)
    print("=" * WIDTH)


def _fingerprint(data: bytes) -> str:
    """Return a short identifier instead of dumping large binary objects."""

    return sha256(data).hexdigest()[:16] + "..."


def _read_backend() -> MLDSABackend:
    """Prompt for an ML-DSA parameter set and load its backend."""

    while True:
        print("Choose a standardized parameter set:")
        print("  1. ML-DSA-44")
        print("  2. ML-DSA-65")
        print("  3. ML-DSA-87")
        selection = input("Enter 1, 2, or 3: ").strip()
        if selection not in PARAMETER_SETS:
            print("Invalid selection. Please enter 1, 2, or 3.\n")
            continue
        return load_backend(selection)


def _read_message() -> bytes:
    """Prompt for a non-empty UTF-8 message."""

    while True:
        message = input("Enter the message to sign: ")
        if message:
            return message.encode("utf-8")
        print("The message must not be empty.")


def _read_context() -> bytes:
    """Prompt for a FIPS 204 context of at most 255 bytes."""

    while True:
        context = input("Enter optional signing context (press Enter for none): ").encode(
            "utf-8"
        )
        if len(context) <= 255:
            return context
        print("The UTF-8 context must be at most 255 bytes.")


def run_demo() -> None:
    """Run real ML-DSA operations and explain Shor's lack of a direct attack."""

    _section("ML-DSA VS SHOR'S ALGORITHM - MODULE 4")
    print("This module performs standardized ML-DSA key generation, signing,")
    print("and verification using the pqcrypto backend.")
    print("It does not implement or simulate a quantum circuit.")

    _section("[1] WHAT ML-DSA DOES")
    print("ML-DSA is a digital-signature algorithm.")
    print("The signer keeps a private signing key and publishes a verification key.")
    print("A valid signature authenticates a message and detects modification;")
    print("it does not encrypt or hide the message.")

    _section("[2] SECURITY FOUNDATION")
    print("ML-DSA is built from module-lattice problems, including assumptions")
    print("related to Module-LWE and Module-SIS, plus cryptographic hashing.")
    print("There is no RSA modulus to factor and no relation Q = dG whose")
    print("discrete logarithm reveals the signing key.")

    _section("[3] PARAMETER AND MESSAGE INPUT")
    try:
        backend = _read_backend()
    except PQCBackendUnavailable as error:
        print(f"Backend unavailable: {error}")
        return
    message = _read_message()
    context = _read_context()
    print(f"Selected: {backend.display_name}")
    print(f"Message length: {len(message)} bytes")
    print(f"Context length: {len(context)} bytes")

    _section("[4] STANDARDIZED KEY GENERATION")
    public_key, secret_key = backend.keygen()
    print(f"Verification key (public) size: {len(public_key)} bytes")
    print(f"Signing key (private) size: {len(secret_key)} bytes")
    print(f"Public-key fingerprint: {_fingerprint(public_key)}")
    print("The private signing key is retained by the signer and not shown.")

    _section("[5] MESSAGE SIGNING")
    signature = backend.sign(secret_key, message, context)
    print("The signer combines the private key, message, and context.")
    print(f"Signature size: {len(signature)} bytes")
    print(f"Message fingerprint: {_fingerprint(message)}")
    print(f"Signature fingerprint: {_fingerprint(signature)}")

    _section("[6] SIGNATURE VERIFICATION")
    valid = backend.verify(public_key, message, signature, context)
    tampered_message = message + b" [tampered]"
    tampered_valid = backend.verify(public_key, tampered_message, signature, context)
    print("Verifier uses only the public key, message, signature, and context.")
    print(f"Original message verifies: {valid}")
    print(f"Modified message verifies with same signature: {tampered_valid}")
    if not valid or tampered_valid:
        raise RuntimeError("ML-DSA verification behavior was unexpected")

    _section("[7] INFORMATION BOUNDARY")
    print("SIGNER KEEPS SECRET:")
    print(f"  Signing key ({len(secret_key)} bytes)")
    print()
    print("VERIFIER OR ATTACKER MAY KNOW:")
    print(f"  {backend.display_name} algorithm and public parameters")
    print(f"  Verification key ({len(public_key)} bytes)")
    print(f"  Message ({len(message)} bytes)")
    print(f"  Signature ({len(signature)} bytes)")
    print(f"  Context ({len(context)} bytes)")
    print()
    print("Public signatures do not reveal the private signing key through a")
    print("known factorization or discrete-logarithm relation.")

    _section("[8] SHOR APPLICABILITY CHECK")
    analysis = analyze_shor_applicability()
    print("Underlying targets: module-lattice problems including")
    print("  Module-LWE and Module-SIS")
    print(f"Depends on integer factorization: {analysis.uses_integer_factorization}")
    print(f"Depends on discrete logarithms: {analysis.uses_discrete_logarithms}")
    print(f"Known direct Shor attack: {analysis.direct_shor_attack_known}")
    print()
    print("Shor's algorithm has no known direct efficient attack on the")
    print("module-lattice assumptions underlying ML-DSA.")
    print("Therefore this module does not fabricate an attacker key-recovery step.")
    print("This is not a proof against every possible future quantum technique;")
    print("it is the scientifically limited conclusion about Shor's algorithm.")

    _section("MODULE 4 RESULT")
    print(f"{backend.display_name} key generation/sign/verify: SUCCESSFUL")
    print("TAMPERED MESSAGE REJECTION: SUCCESSFUL")
    print("SHOR RESULT: NO KNOWN DIRECTLY APPLICABLE ATTACK")

    _section("[9] FINAL CONCLUSION")
    print("Unlike RSA and ECC signatures, ML-DSA was designed around module-")
    print("lattice assumptions rather than factorization or discrete logarithms.")
    print("Shor's algorithm does not provide a known efficient signing-key")
    print("recovery or forgery method for ML-DSA. This module used real ML-DSA")
    print("operations and did not claim absolute immunity to future attacks.")
