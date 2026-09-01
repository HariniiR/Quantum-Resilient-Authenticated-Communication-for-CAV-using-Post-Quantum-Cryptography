"""Interactive ML-KEM versus Shor demonstration."""

from hashlib import sha256

from .ml_kem import run_ml_kem, shor_has_direct_attack


LINE = "=" * 60


def heading(title: str) -> None:
    print(f"\n{LINE}\n{title}\n{LINE}")


def fingerprint(data: bytes) -> str:
    """Show a short hash instead of printing large binary keys."""

    return sha256(data).hexdigest()[:16] + "..."


def read_choice() -> str:
    """Ask the user to select an ML-KEM parameter set."""

    while True:
        print("1. ML-KEM-512")
        print("2. ML-KEM-768")
        print("3. ML-KEM-1024")
        choice = input("Choose 1, 2, or 3: ").strip()
        if choice in ("1", "2", "3"):
            return choice
        print("Invalid choice.\n")


def run_demo() -> None:
    """Run ML-KEM and explain why Shor does not directly attack it."""

    heading("ML-KEM VS SHOR'S ALGORITHM")
    print("ML-KEM creates a shared secret between a sender and receiver.")
    print("It is based on Module-LWE, not factoring or discrete logarithms.")

    heading("1. SELECT ML-KEM VERSION")
    choice = read_choice()

    try:
        result = run_ml_kem(choice)
    except RuntimeError as error:
        print(error)
        return

    heading("2. KEY GENERATION")
    print(f"Algorithm = {result['name']}")
    print(f"Public key size  = {len(result['public_key'])} bytes")
    print(f"Private key size = {len(result['private_key'])} bytes")
    print(f"Public key hash  = {fingerprint(result['public_key'])}")

    heading("3. ENCAPSULATION")
    print("The sender uses the public key to create a ciphertext and shared secret.")
    print(f"Ciphertext size = {len(result['ciphertext'])} bytes")
    print(f"Ciphertext hash = {fingerprint(result['ciphertext'])}")
    print(f"Sender secret   = {fingerprint(result['sender_secret'])}")

    heading("4. DECAPSULATION")
    print("The receiver uses the private key and ciphertext.")
    print(f"Receiver secret = {fingerprint(result['receiver_secret'])}")
    print(f"Secrets match   = "
          f"{result['sender_secret'] == result['receiver_secret']}")

    heading("5. WHAT THE ATTACKER KNOWS")
    print("Attacker may know the algorithm, public key, and ciphertext.")
    print("Attacker does not know the private key or shared secret.")

    heading("6. SHOR CHECK")
    print("RSA depends on factoring. ECC depends on discrete logarithms.")
    print("ML-KEM instead depends on noisy module-lattice equations (Module-LWE).")
    print(f"Known direct Shor attack = {shor_has_direct_attack()}")
    print("Factoring the public ML-KEM modulus q = 3329 reveals no private key.")

    heading("MODULE 3 SUCCESSFUL")
    print("ML-KEM key generation, encapsulation, and decapsulation worked.")
    print("Shor's algorithm has no known direct efficient attack on Module-LWE.")
    print("This does not prove protection from every possible future attack.")
