"""Interactive RSA versus Shor demonstration."""

from math import gcd
from typing import Tuple

from .rsa import encrypt, generate_keys
from .shor_math import attack_rsa


LINE = "=" * 60


def heading(title: str) -> None:
    """Print a simple section heading."""

    print(f"\n{LINE}\n{title}\n{LINE}")


def read_number(prompt: str) -> int:
    """Read a whole number from the user."""

    while True:
        try:
            return int(input(prompt))
        except ValueError:
            print("Please enter a whole number.")


def read_rsa_values() -> Tuple[int, int, int, int, int, int]:
    """Ask for valid RSA values."""

    while True:
        p = read_number("Enter prime p: ")
        q = read_number("Enter a different prime q: ")
        e = read_number("Enter public exponent e: ")

        try:
            n, phi, d = generate_keys(p, q, e)
            return p, q, e, n, phi, d
        except ValueError as error:
            print(f"Invalid input: {error}. Try again.\n")


def read_message(n: int) -> int:
    """Ask for a plaintext in the valid RSA range."""

    while True:
        message = read_number(f"Enter plaintext m (0 <= m < {n}): ")
        if 0 <= message < n:
            return message
        print("The plaintext must be between 0 and N - 1.")


def run_demo() -> None:
    """Run the complete RSA attack demonstration."""

    heading("RSA VS SHOR'S ALGORITHM")
    print("This is an educational demonstration of Shor's mathematics.")
    print("The order is found with a normal Python loop.")
    print("No quantum computer or quantum simulator is used.")

    heading("1. RSA KEY GENERATION")
    print("RSA uses two secret prime numbers p and q.")
    print("Small numbers are required for this classroom demonstration.\n")

    p, q, e, n, phi, d = read_rsa_values()

    print(f"\nN = p * q = {p} * {q} = {n}")
    print(f"phi(N) = (p - 1)(q - 1) = {phi}")
    print(f"d = e^(-1) mod phi(N) = {d}")
    print(f"Public key  = ({n}, {e})")
    print(f"Private key = {d}")

    heading("2. ENCRYPT A MESSAGE")
    message = read_message(n)
    ciphertext = encrypt(message, n, e)
    print("\nc = m^e mod N")
    print(f"c = {message}^{e} mod {n} = {ciphertext}")

    heading("3. WHAT EACH SIDE KNOWS")
    print("Legitimate receiver knows:")
    print(f"  p = {p}, q = {q}, d = {d}")
    print("\nAttacker knows only:")
    print(f"  N = {n}, e = {e}, ciphertext = {ciphertext}")
    print("The attack function is given only these public values and a chosen a.")

    heading("4. SHOR'S FACTORING WORKFLOW")
    print("Shor changes factoring into an order-finding problem.")
    print("The order r is the first positive number where a^r = 1 (mod N).")
    print("A real Shor attack would find r using a quantum subroutine.")
    print("Here we find r classically so that the mathematics can be shown.\n")

    while True:
        a = read_number(f"Choose a value a (1 < a < {n}): ")
        try:
            result = attack_rsa(n, e, ciphertext, a)
            break
        except ValueError as error:
            print(f"This a cannot be used: {error}. Try another.\n")

    print(f"\ngcd({a}, {n}) = {gcd(a, n)}")
    print("\nClassical order search:")
    for exponent, value in result["steps"]:
        print(f"  {a}^{exponent} mod {n} = {value}")
    print(f"Therefore r = {result['order']}")

    heading("5. RECOVER THE FACTORS")
    print(
        f"a^(r/2) mod N = {a}^({result['order']}/2) mod {n} "
        f"= {result['half_power']}"
    )
    print(f"gcd({result['half_power']} - 1, {n}) = {result['factor1']}")
    print(f"gcd({result['half_power']} + 1, {n}) = {result['factor2']}")
    print(f"Recovered factors: {result['factor1']} and {result['factor2']}")

    heading("6. RECOVER THE PRIVATE KEY")
    print(
        "recovered phi(N) = "
        f"({result['factor1']} - 1)({result['factor2']} - 1) "
        f"= {result['phi']}"
    )
    print(f"recovered d = {e}^(-1) mod {result['phi']} = {result['d']}")
    print("The original private d was not passed to the attack function.")

    heading("7. DECRYPT THE INTERCEPTED CIPHERTEXT")
    print(
        f"recovered message = {ciphertext}^{result['d']} mod {n} "
        f"= {result['message']}"
    )
    print(f"Original message  = {message}")
    print(f"Messages match    = {result['message'] == message}")

    heading("ATTACK SUCCESSFUL")
    print(f"Factors recovered     : {result['factor1']}, {result['factor2']}")
    print(f"Private key recovered : d = {result['d']}")
    print(f"Plaintext recovered   : {result['message']}")
    print()
    print("RSA remains secure against practical classical factoring at proper")
    print("key sizes, but a sufficiently powerful fault-tolerant quantum")
    print("computer could use Shor's algorithm to break its factoring assumption.")
