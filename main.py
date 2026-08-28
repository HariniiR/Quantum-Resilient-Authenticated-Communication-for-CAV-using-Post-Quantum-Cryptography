"""Interactive entry point for the quantum cryptography education project."""

from modules.ecc_shor.demo import run_demo as run_ecc_demo
from modules.ml_dsa.demo import run_demo as run_ml_dsa_demo
from modules.ml_kem.demo import run_demo as run_ml_kem_demo
from modules.rsa_shor.demo import run_demo as run_rsa_demo


def _read_selection() -> int:
    """Prompt until the user selects an implemented module."""

    while True:
        print("Select a demonstration:")
        print("  1. RSA vs Shor's algorithm")
        print("  2. ECC vs Shor's algorithm")
        print("  3. ML-KEM vs Shor's algorithm")
        print("  4. ML-DSA vs Shor's algorithm")
        choice = input("Enter 1, 2, 3, or 4: ").strip()
        if choice in {"1", "2", "3", "4"}:
            return int(choice)
        print("Invalid selection. Please enter a number from 1 through 4.\n")


def main() -> None:
    """Run the module selected by the user."""

    selection = _read_selection()
    if selection == 1:
        run_rsa_demo()
    elif selection == 2:
        run_ecc_demo()
    elif selection == 3:
        run_ml_kem_demo()
    else:
        run_ml_dsa_demo()


if __name__ == "__main__":
    main()
