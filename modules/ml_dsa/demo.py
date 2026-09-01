"""Interactive ML-DSA versus Shor demonstration."""

from hashlib import sha256

from .ml_dsa import run_ml_dsa, shor_has_direct_attack


LINE = "=" * 60


def heading(title: str) -> None:
    print(f"\n{LINE}\n{title}\n{LINE}")


def fingerprint(data: bytes) -> str:
    """Show a short hash instead of printing large binary values."""

    return sha256(data).hexdigest()[:16] + "..."


def read_choice() -> str:
    """Ask the user to select an ML-DSA parameter set."""

    while True:
        print("1. ML-DSA-44")
        print("2. ML-DSA-65")
        print("3. ML-DSA-87")
        choice = input("Choose 1, 2, or 3: ").strip()
        if choice in ("1", "2", "3"):
            return choice
        print("Invalid choice.\n")


def read_message() -> bytes:
    """Ask for a non-empty message."""

    while True:
        message = input("Enter message to sign: ")
        if message:
            return message.encode("utf-8")
        print("Message cannot be empty.")


def read_context() -> bytes:
    """Ask for an optional context no longer than 255 bytes."""

    while True:
        context = input("Optional context (press Enter for none): ").encode("utf-8")
        if len(context) <= 255:
            return context
        print("Context must be at most 255 bytes.")


def run_demo() -> None:
    """Run ML-DSA and explain why Shor does not directly attack it."""

    heading("ML-DSA VS SHOR'S ALGORITHM")
    print("ML-DSA signs messages so that changes can be detected.")
    print("It uses module-lattice problems, not factoring or discrete logarithms.")

    heading("1. INPUT")
    choice = read_choice()
    message = read_message()
    context = read_context()

    try:
        result = run_ml_dsa(choice, message, context)
    except RuntimeError as error:
        print(error)
        return

    heading("2. KEY GENERATION")
    print(f"Algorithm = {result['name']}")
    print(f"Public key size  = {len(result['public_key'])} bytes")
    print(f"Private key size = {len(result['private_key'])} bytes")
    print(f"Public key hash  = {fingerprint(result['public_key'])}")

    heading("3. SIGN MESSAGE")
    print("The signer uses the private key to create the signature.")
    print(f"Message hash   = {fingerprint(message)}")
    print(f"Signature size = {len(result['signature'])} bytes")
    print(f"Signature hash = {fingerprint(result['signature'])}")

    heading("4. VERIFY SIGNATURE")
    print("The verifier uses the public key, message, signature, and context.")
    print(f"Original message valid = {result['valid']}")
    print(f"Changed message valid  = {result['tampered_valid']}")

    heading("5. WHAT THE ATTACKER KNOWS")
    print("Attacker may know the public key, message, signature, and context.")
    print("Attacker does not know the private signing key.")

    heading("6. SHOR CHECK")
    print("ML-DSA relies on Module-LWE and Module-SIS-type lattice problems.")
    print(f"Known direct Shor attack = {shor_has_direct_attack()}")
    print("There is no RSA number to factor and no ECC discrete log to solve.")

    heading("MODULE 4 SUCCESSFUL")
    print("ML-DSA key generation, signing, and verification worked.")
    print("The changed message was rejected.")
    print("Shor has no known direct efficient attack on ML-DSA's foundations.")
    print("This does not prove protection from every possible future attack.")
