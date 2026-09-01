"""Interactive ECC versus Shor demonstration."""

from math import gcd

from .ecc import (create_keypair, decrypt, encrypt, make_curve,
                  point_order, show_point)
from .shor_math import attack_ecc


LINE = "=" * 60


def heading(title: str) -> None:
    print(f"\n{LINE}\n{title}\n{LINE}")


def read_number(prompt: str) -> int:
    while True:
        try:
            return int(input(prompt))
        except ValueError:
            print("Please enter a whole number.")


def read_curve():
    """Ask for a valid small curve and generator point."""

    while True:
        p = read_number("Field prime p (try 17): ")
        a = read_number("Curve value a (try 2): ")
        b = read_number("Curve value b (try 2): ")
        gx = read_number("Generator x (try 5): ")
        gy = read_number("Generator y (try 1): ")

        try:
            curve = make_curve(p, a, b)
            generator = (gx, gy)
            order = point_order(curve, generator)
            return curve, generator, order
        except ValueError as error:
            print(f"Invalid curve: {error}. Try again.\n")


def run_demo() -> None:
    """Run the complete ECC attack demonstration."""

    heading("ECC VS SHOR'S ALGORITHM")
    print("ECC uses points on the curve y^2 = x^3 + ax + b (mod p).")
    print("The private key is d and the public key is Q = dG.")
    print("No quantum computer or simulator is used in this demonstration.")

    heading("1. CURVE AND KEY GENERATION")
    print("Enter a small curve. Known example: p=17, a=2, b=2, G=(5,1).\n")
    curve, generator, order = read_curve()

    while True:
        private_key = read_number(f"Private key d (1 <= d < {order}): ")
        try:
            order, public_key = create_keypair(curve, generator, private_key)
            break
        except ValueError as error:
            print(f"Invalid key: {error}.")

    print(f"\nCurve = y^2 = x^3 + {curve[1]}x + {curve[2]} (mod {curve[0]})")
    print(f"G = {show_point(generator)}, order of G = {order}")
    print(f"Q = dG = {private_key}G = {show_point(public_key)}")

    heading("2. EC ELGAMAL ENCRYPTION")
    print("For this toy demo, integer message m is represented by point M = mG.\n")

    while True:
        message = read_number(f"Message m (1 <= m < {order}): ")
        one_time_key = read_number(f"One-time key k (1 <= k < {order}): ")
        try:
            encrypted = encrypt(curve, generator, public_key, order,
                                message, one_time_key)
            break
        except ValueError as error:
            print(f"Invalid value: {error}. Try again.\n")

    print(f"\nM = mG = {show_point(encrypted['message_point'])}")
    print(f"C1 = kG = {show_point(encrypted['c1'])}")
    print(f"Shared point = kQ = {show_point(encrypted['shared'])}")
    print(f"C2 = M + kQ = {show_point(encrypted['c2'])}")

    received_point = decrypt(curve, encrypted["c1"], encrypted["c2"], private_key)
    print(f"\nReceiver decrypts M = C2 - dC1 = {show_point(received_point)}")

    heading("3. WHAT THE ATTACKER KNOWS")
    print(f"Public curve = {curve}")
    print(f"G = {show_point(generator)}, order = {order}")
    print(f"Q = {show_point(public_key)}")
    print(f"Ciphertext = ({show_point(encrypted['c1'])}, "
          f"{show_point(encrypted['c2'])})")
    print("The attacker is not given d, k, or m.")

    heading("4. SHOR'S ECC WORKFLOW")
    print("The attacker must solve Q = dG, called the elliptic-curve")
    print("discrete logarithm problem. A real Shor attack would use a quantum")
    print("subroutine. Here a small classical loop demonstrates the result.\n")

    result = attack_ecc(curve, generator, public_key, order,
                        encrypted["c1"], encrypted["c2"])

    for candidate, point in result["steps"]:
        marker = "  <-- Q" if point == public_key else ""
        print(f"  {candidate}G = {show_point(point)}{marker}")

    heading("5. ATTACKER DECRYPTION")
    print(f"Recovered private key d = {result['d']}")
    print(f"Recovered point M = {show_point(result['message_point'])}")
    print(f"Recovered message m = {result['message']}")
    print(f"Message matches = {result['message'] == message}")

    heading("ATTACK SUCCESSFUL")
    print("The toy ECC private key and message were recovered.")
    print("Real ECC remains secure against practical classical attacks at proper")
    print("key sizes, but its discrete-logarithm assumption is vulnerable to")
    print("Shor's algorithm on a sufficiently capable quantum computer.")
