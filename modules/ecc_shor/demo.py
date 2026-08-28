"""Polished console presentation for Module 2: ECC vs Shor's algorithm."""

from .ecc import (
    Curve,
    ECCEncryptionResult,
    ECCKeyPair,
    Point,
    decrypt_point,
    encrypt_message,
    format_point,
    generate_keypair,
    point_order,
)
from .shor_math import run_ecc_shor_math_attack


WIDTH = 60
MAX_EDUCATIONAL_FIELD = 997


def _section(title: str) -> None:
    """Print a consistent section heading."""

    print()
    print("=" * WIDTH)
    print(title)
    print("=" * WIDTH)


def _read_integer(prompt: str) -> int:
    """Read an integer, retrying after invalid text."""

    while True:
        try:
            return int(input(prompt).strip())
        except ValueError:
            print("Invalid input: please enter a whole number.")


def _read_curve_and_generator() -> tuple[Curve, Point, int]:
    """Prompt until valid small public curve parameters are supplied."""

    while True:
        field_prime = _read_integer("Enter small field prime p (try 17): ")
        curve_a = _read_integer("Enter curve coefficient a (try 2): ")
        curve_b = _read_integer("Enter curve coefficient b (try 2): ")
        generator_x = _read_integer("Enter generator x-coordinate (try 5): ")
        generator_y = _read_integer("Enter generator y-coordinate (try 1): ")
        try:
            if field_prime > MAX_EDUCATIONAL_FIELD:
                raise ValueError(
                    f"field prime must be at most {MAX_EDUCATIONAL_FIELD} for this demo"
                )
            curve = Curve(field_prime, curve_a, curve_b)
            generator = generator_x, generator_y
            order = point_order(curve, generator)
            if order < 5:
                raise ValueError("generator order is too small for this demonstration")
            return curve, generator, order
        except ValueError as error:
            print(f"Invalid curve parameters: {error}.")
            print("Please enter the public curve parameters again.\n")


def _read_keypair(curve: Curve, generator: Point, order: int) -> ECCKeyPair:
    """Prompt until a valid private scalar is supplied."""

    while True:
        private_scalar = _read_integer(
            f"Enter receiver's private scalar d (1 <= d < {order}): "
        )
        try:
            return generate_keypair(curve, generator, private_scalar)
        except ValueError as error:
            print(f"Invalid private scalar: {error}.")


def _read_encryption(keypair: ECCKeyPair) -> ECCEncryptionResult:
    """Prompt until valid message and ephemeral scalars are supplied."""

    order = keypair.generator_order
    while True:
        message = _read_integer(f"Enter toy message scalar m (1 <= m < {order}): ")
        ephemeral = _read_integer(
            f"Enter sender's one-time scalar k (1 <= k < {order}): "
        )
        try:
            return encrypt_message(keypair, message, ephemeral)
        except ValueError as error:
            print(f"Invalid encryption input: {error}.")
            print("Please enter m and k again.\n")


def run_demo() -> None:
    """Run the complete educational ECC/Shor mathematical demonstration."""

    _section("ECC VS SHOR'S ALGORITHM - MODULE 2")
    print("Educational implementation of the mathematical workflow behind")
    print("Shor's elliptic-curve discrete-logarithm attack.")
    print()
    print("LIMITATION:")
    print("No quantum computer, quantum simulator, or quantum circuit is used.")
    print("The private scalar is recovered with a classical exhaustive loop on")
    print("a tiny curve. This is not a real quantum execution.")

    _section("[1] HOW ECC WORKS")
    print("ECC works with points on a curve over a finite field:")
    print("  y^2 = x^3 + ax + b (mod p)")
    print()
    print("A public generator point G and private scalar d produce:")
    print("  Q = dG")
    print("Q is public; d is secret.")
    print()
    print("ECC security relies on the elliptic-curve discrete logarithm problem:")
    print("given G and Q, recovering d from Q = dG is classically difficult")
    print("when secure real-world curves and key sizes are used.")

    _section("[2] ECC SECURITY MODEL")
    print("Real systems use standardized curves with large subgroup orders.")
    print("This program does not attack a production curve or claim that current")
    print("computers can break properly implemented real-world ECC.")
    print("It uses tiny user-supplied values only to expose the attack structure.")

    _section("[3] TOY CURVE AND KEY GENERATION")
    print("Enter small public curve parameters. A known working example is:")
    print("  p = 17, a = 2, b = 2, G = (5, 1)")
    print()
    curve, generator, order = _read_curve_and_generator()
    print()
    print(f"Curve: y^2 = x^3 + {curve.a}x + {curve.b} (mod {curve.p})")
    print(f"Generator G = {format_point(generator)}")
    print(f"Classically calculated order of G = {order}")
    print()
    legitimate_key = _read_keypair(curve, generator, order)
    print()
    print(f"Private scalar d = {legitimate_key.private_scalar}")
    print("Public point Q = dG")
    print(
        f"Q = {legitimate_key.private_scalar} * {format_point(generator)} "
        f"= {format_point(legitimate_key.public_point)}"
    )

    _section("[4] TOY EC ELGAMAL ENCRYPTION")
    print("For a transparent demonstration, integer m is encoded as point M = mG.")
    print("This simple encoding is educational and is not a production protocol.")
    print()
    encryption = _read_encryption(legitimate_key)
    print()
    print(f"Message scalar m = {encryption.message_scalar}")
    print(
        f"Message point M = mG = {encryption.message_scalar}G "
        f"= {format_point(encryption.message_point)}"
    )
    print(f"Sender's one-time scalar k = {encryption.ephemeral_scalar}")
    print(
        f"C1 = kG = {encryption.ephemeral_scalar}G "
        f"= {format_point(encryption.ciphertext.c1)}"
    )
    print(
        f"Shared point S = kQ = {format_point(encryption.shared_point)}"
    )
    print(f"C2 = M + kQ = {format_point(encryption.ciphertext.c2)}")
    print(
        "Ciphertext (C1, C2) = "
        f"({format_point(encryption.ciphertext.c1)}, "
        f"{format_point(encryption.ciphertext.c2)})"
    )

    _section("[5] LEGITIMATE RECEIVER DECRYPTION")
    legitimate_decrypted_point = decrypt_point(
        curve, encryption.ciphertext, legitimate_key.private_scalar
    )
    print("Receiver already knows private d and calculates:")
    print("  M = C2 - dC1")
    print(
        f"  M = {format_point(encryption.ciphertext.c2)} - "
        f"{legitimate_key.private_scalar}{format_point(encryption.ciphertext.c1)}"
    )
    print(f"Recovered message point = {format_point(legitimate_decrypted_point)}")

    _section("[6] INFORMATION BOUNDARY")
    print("LEGITIMATE PARTICIPANTS KNOW:")
    print(f"  Receiver private scalar d = {legitimate_key.private_scalar}")
    print(f"  Sender one-time scalar k = {encryption.ephemeral_scalar}")
    print(f"  Original message scalar m = {encryption.message_scalar}")
    print()
    print("ATTACKER KNOWS ONLY:")
    attacker_curve = curve
    attacker_generator = generator
    attacker_order = order
    attacker_public_point = legitimate_key.public_point
    attacker_ciphertext = encryption.ciphertext
    print(f"  Public curve: p={curve.p}, a={curve.a}, b={curve.b}")
    print(f"  Public generator G = {format_point(attacker_generator)}")
    print(f"  Public generator order n = {attacker_order}")
    print(f"  Public key Q = {format_point(attacker_public_point)}")
    print(
        "  Intercepted ciphertext (C1, C2) = "
        f"({format_point(attacker_ciphertext.c1)}, "
        f"{format_point(attacker_ciphertext.c2)})"
    )
    print()
    print("The attack routine receives none of d, k, or m.")

    _section("[7] SHOR'S ECC ATTACK APPROACH")
    print("The attacker needs the private scalar d in:")
    print("  Q = dG")
    print()
    print("This is the elliptic-curve discrete logarithm problem (ECDLP).")
    print("A sufficiently capable fault-tolerant quantum computer could use")
    print("Shor's algorithm to solve this problem efficiently.")
    print()
    print("Here, a classical loop tries 1G, 2G, 3G, ... only to demonstrate")
    print("what private value the quantum algorithm would recover.")

    # No legitimate private scalar, message, or ephemeral scalar is passed here.
    attack = run_ecc_shor_math_attack(
        attacker_curve,
        attacker_generator,
        attacker_order,
        attacker_public_point,
        attacker_ciphertext,
    )

    _section("[8] EDUCATIONAL CLASSICAL DISCRETE-LOG SEARCH")
    print("Classical exhaustive search on the tiny curve:")
    for step in attack.search_trace:
        marker = "  <-- matches public Q" if step.candidate_point == attacker_public_point else ""
        print(
            f"  {step.candidate}G = {format_point(step.candidate_point)}{marker}"
        )
    print()
    print(
        f"Recovered private scalar: d = {attack.recovered_private_scalar}"
    )
    print("The legitimate d was not passed to the attacker routine.")

    _section("[9] ATTACKER DECRYPTION")
    print("With recovered d, the attacker now performs the receiver's ordinary")
    print("decryption operation:")
    print("  recovered_M = C2 - recovered_d * C1")
    print(
        f"  recovered_M = {format_point(attacker_ciphertext.c2)} - "
        f"{attack.recovered_private_scalar}{format_point(attacker_ciphertext.c1)}"
    )
    print(
        f"Recovered message point = {format_point(attack.recovered_message_point)}"
    )
    print(f"Decoded toy message scalar = {attack.recovered_message_scalar}")
    message_matches = (
        attack.recovered_message_point == encryption.message_point
        and attack.recovered_message_scalar == encryption.message_scalar
    )
    print(f"Recovered message matches original: {message_matches}")
    if not message_matches:
        raise RuntimeError("the ECC attacker failed to recover the original message")

    _section("ATTACK SUCCESSFUL")
    print(f"ECC private scalar recovered: d = {attack.recovered_private_scalar}")
    print(
        "Intercepted ciphertext: "
        f"({format_point(attacker_ciphertext.c1)}, "
        f"{format_point(attacker_ciphertext.c2)})"
    )
    print(f"Recovered message scalar: m = {attack.recovered_message_scalar}")
    print()
    print("RESULT:")
    print("ECC PRIVATE KEY COMPROMISED")

    _section("[10] FINAL CONCLUSION")
    print("ECC remains secure against practical classical ECDLP attacks when")
    print("approved curves and key sizes are used, but its discrete-logarithm")
    print("assumption is vulnerable to Shor's algorithm on a sufficiently capable")
    print("fault-tolerant quantum computer. This module demonstrates the attack")
    print("mechanism with a tiny curve and a classical exhaustive search.")
