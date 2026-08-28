"""Polished console presentation for Module 1: RSA vs Shor's algorithm."""

from math import gcd
from typing import Iterator

from .rsa import RSAKeyPair, encrypt, generate_keypair
from .shor_math import run_shor_math_attack


WIDTH = 60


def _section(title: str) -> None:
    """Print a consistent section heading."""

    print()
    print("=" * WIDTH)
    print(title)
    print("=" * WIDTH)


def _read_integer(prompt: str) -> int:
    """Read an integer from the user, retrying after invalid text."""

    while True:
        try:
            return int(input(prompt).strip())
        except ValueError:
            print("Invalid input: please enter a whole number.")


def _read_keypair() -> RSAKeyPair:
    """Prompt until the user supplies valid educational RSA parameters."""

    while True:
        p = _read_integer("Enter prime p: ")
        q = _read_integer("Enter a different prime q: ")
        e = _read_integer("Enter public exponent e: ")
        try:
            return generate_keypair(p, q, e)
        except ValueError as error:
            print(f"Invalid RSA parameters: {error}.")
            print("Please enter p, q, and e again.\n")


def _read_plaintext(n: int) -> int:
    """Prompt for an integer plaintext in RSA's valid numeric range."""

    while True:
        message = _read_integer(f"Enter plaintext m (0 <= m < {n}): ")
        if 0 <= message < n:
            return message
        print(f"Invalid plaintext: m must satisfy 0 <= m < {n}.")


def _candidate_bases(n: int) -> Iterator[int]:
    """Yield user-selected Shor bases, prompting again after a failed attempt."""

    attempt = 1
    while True:
        if attempt > 1:
            print("The previous base was unsuitable. Please try another base.")
        yield _read_integer(f"Enter candidate base a (1 < a < {n}): ")
        attempt += 1


def run_demo() -> None:
    """Run the complete educational RSA/Shor mathematical demonstration."""

    _section("RSA VS SHOR'S ALGORITHM - MODULE 1")
    print("Educational implementation of the mathematical workflow behind")
    print("Shor's factoring algorithm.")
    print()
    print("LIMITATION:")
    print("No quantum computer, quantum simulator, or quantum circuit is used.")
    print("The order-finding step is computed classically to demonstrate the")
    print("attack mathematics; this is not a real quantum execution.")

    _section("[1] HOW RSA WORKS")
    print("RSA relies on the difficulty of factoring a large number N into its")
    print("secret prime factors p and q.")
    print()
    print("Key generation:")
    print("  N      = p * q")
    print("  phi(N) = (p - 1)(q - 1)")
    print("  gcd(e, phi(N)) = 1")
    print("  d      = e^(-1) mod phi(N)")
    print()
    print("Encryption: c = m^e mod N")
    print("Decryption: m = c^d mod N")

    _section("[2] RSA SECURITY MODEL")
    print("Real-world example: RSA-2048")
    print("Public modulus size: 2048 bits")
    print()
    print("RSA security depends on the difficulty of recovering p and q from:")
    print("  N = p * q")
    print()
    print("Using known classical algorithms, factoring a properly generated")
    print("RSA-2048 modulus is computationally infeasible in practice.")
    print("This program does NOT attempt to factor RSA-2048 or claim it is broken.")
    print("A tiny RSA instance is used only to show the attack mechanism.")

    _section("[3] TOY RSA KEY GENERATION")
    print("Enter small values for this educational demonstration.")
    print("The program validates that p and q are different primes and that")
    print("e is coprime with phi(N).")
    print()
    # These values remain on the legitimate-system side of the demonstration.
    legitimate_key = _read_keypair()
    print()
    print(f"Choose p = {legitimate_key.p}")
    print(f"Choose q = {legitimate_key.q}")
    print(f"N = p * q = {legitimate_key.p} * {legitimate_key.q} = {legitimate_key.n}")
    print(
        "phi(N) = (p - 1)(q - 1) = "
        f"({legitimate_key.p} - 1)({legitimate_key.q} - 1) = {legitimate_key.phi}"
    )
    print(f"Choose e = {legitimate_key.e}")
    print(f"gcd(e, phi(N)) = gcd({legitimate_key.e}, {legitimate_key.phi}) = 1")
    print(
        f"d = e^(-1) mod phi(N) = {legitimate_key.e}^(-1) "
        f"mod {legitimate_key.phi} = {legitimate_key.d}"
    )
    print(f"Public key:  (N, e) = {legitimate_key.public_key}")
    print(f"Private key: d = {legitimate_key.d}")

    print()
    original_plaintext = _read_plaintext(legitimate_key.n)
    intercepted_ciphertext = encrypt(original_plaintext, legitimate_key.public_key)

    _section("[4] RSA ENCRYPTION")
    print(f"Plaintext m = {original_plaintext}")
    print(
        f"c = m^e mod N = {original_plaintext}^{legitimate_key.e} "
        f"mod {legitimate_key.n} = {intercepted_ciphertext}"
    )

    _section("[5] INFORMATION BOUNDARY")
    print("LEGITIMATE SYSTEM KNOWS:")
    print(f"  p = {legitimate_key.p}")
    print(f"  q = {legitimate_key.q}")
    print(f"  d = {legitimate_key.d}")
    print()
    print("ATTACKER KNOWS ONLY:")
    attacker_n = legitimate_key.n
    attacker_e = legitimate_key.e
    attacker_ciphertext = intercepted_ciphertext
    print(f"  Public modulus N = {attacker_n}")
    print(f"  Public exponent e = {attacker_e}")
    print(f"  Intercepted ciphertext = {attacker_ciphertext}")
    print()
    print("The attack routine receives only these public/intercepted values.")

    _section("[6] SHOR MATHEMATICAL ATTACK APPROACH")
    print("Shor's algorithm converts integer factorization into an order-finding")
    print("problem.")
    print()
    print("The order r is the smallest positive integer for which:")
    print("  a^r is congruent to 1 (mod N)")
    print()
    print("In real Shor's algorithm, quantum period/order finding provides the")
    print("speedup. This demonstration computes the order classically because no")
    print("quantum simulator or quantum hardware is being used.")

    _section("[7] SELECT A BASE")
    print("Choose a candidate base. If it is unsuitable for factor recovery,")
    print("the program will ask for another one.")
    print()
    # Crucially, no p, q, phi, or d is passed to the attacker-side function.
    attack = run_shor_math_attack(
        n=attacker_n,
        e=attacker_e,
        ciphertext=attacker_ciphertext,
        candidate_bases=_candidate_bases(attacker_n),
    )
    print()
    for failure in attack.failed_attempts:
        print(f"Base a = {failure.base} was unsuitable: {failure.reason}")
    print(f"Select a = {attack.base}")
    print(
        f"Verify gcd(a, N) = gcd({attack.base}, {attacker_n}) "
        f"= {gcd(attack.base, attacker_n)}"
    )
    print("Therefore a and N are coprime, so order finding can proceed.")

    _section("[8] CLASSICAL ORDER FINDING")
    print("Educational classical loop (the quantum speedup is not simulated):")
    for exponent, residue in attack.order_sequence:
        print(f"  {attack.base}^{exponent} mod {attacker_n} = {residue}")
    print()
    print(f"The first exponent producing 1 is r = {attack.order}.")
    print(f"r is even: {attack.order} mod 2 = {attack.order % 2}")

    _section("[9] FACTOR RECOVERY WITH GCD")
    print("Once the order is known, classical GCD calculations can reveal the")
    print("factors of N.")
    print()
    print(f"a^(r/2) = {attack.base}^({attack.order}/2) = {attack.half_power}")
    print(
        f"factor1 = gcd({attack.half_power} - 1, {attacker_n}) "
        f"= {attack.factor1}"
    )
    print(
        f"factor2 = gcd({attack.half_power} + 1, {attacker_n}) "
        f"= {attack.factor2}"
    )
    print(f"Recovered factorization: {attacker_n} = {attack.factor1} * {attack.factor2}")

    _section("[10] PRIVATE KEY RECONSTRUCTION")
    print("Once p and q are recovered, phi(N) and the RSA private exponent d")
    print("can be reconstructed.")
    print()
    print(
        "recovered_phi = (factor1 - 1)(factor2 - 1) = "
        f"({attack.factor1} - 1)({attack.factor2} - 1) = {attack.recovered_phi}"
    )
    print(
        f"recovered_d = e^(-1) mod recovered_phi = {attacker_e}^(-1) "
        f"mod {attack.recovered_phi} = {attack.recovered_d}"
    )
    print("This value was reconstructed independently; the original private d")
    print("was not supplied to the attack routine.")

    _section("[11] ATTACKER DECRYPTION AND COMPARISON")
    print(
        "recovered_plaintext = ciphertext^recovered_d mod N = "
        f"{attacker_ciphertext}^{attack.recovered_d} mod {attacker_n} "
        f"= {attack.recovered_plaintext}"
    )
    print(f"Original plaintext:  {original_plaintext}")
    print(f"Recovered plaintext: {attack.recovered_plaintext}")
    messages_match = attack.recovered_plaintext == original_plaintext
    print(f"Messages match: {messages_match}")

    if not messages_match:
        raise RuntimeError("the attacker failed to recover the original plaintext")

    _section("ATTACK SUCCESSFUL")
    print("RSA factors recovered:")
    print(f"p = {attack.factor1}")
    print(f"q = {attack.factor2}")
    print()
    print("RSA private exponent recovered:")
    print(f"d = {attack.recovered_d}")
    print()
    print("Intercepted ciphertext:")
    print(attacker_ciphertext)
    print()
    print("Recovered plaintext:")
    print(attack.recovered_plaintext)
    print()
    print("RESULT:")
    print("RSA PRIVATE KEY COMPROMISED")

    _section("[12] FINAL CONCLUSION")
    print("RSA remains secure against practical classical factorization when")
    print("appropriate key sizes are used, but its underlying integer-")
    print("factorization assumption is vulnerable to Shor's algorithm on a")
    print("sufficiently capable fault-tolerant quantum computer. This module")
    print("demonstrates that attack mechanism using a small RSA instance.")
