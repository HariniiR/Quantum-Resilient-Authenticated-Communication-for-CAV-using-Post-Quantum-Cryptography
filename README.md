# Quantum-Resilient Authenticated Communication for CAV Using Post-Quantum Cryptography

Quantum-resilient authenticated communication for autonomous vehicles using
post-quantum cryptography.

## Cryptography Demonstration Modules

## Purpose

This Python project demonstrates why classical public-key cryptography is
vulnerable to quantum attacks and why post-quantum cryptography is designed
differently. It compares RSA and ECC with ML-KEM and ML-DSA.

The code is educational. The tiny RSA and ECC implementations are **not
suitable for protecting real data**.

## Module 1: RSA vs Shor

Module 1 is **RSA vs Shor's Algorithm**. It:

- asks the user for two small, different primes and a valid public exponent;
- asks the user for an integer plaintext and encrypts it;
- gives the attack routine only the public modulus, public exponent, and
  intercepted ciphertext;
- asks the user to select a Shor base and re-prompts if it is unsuitable;
- reproduces the order-finding mathematics behind Shor's factoring method;
- derives the non-trivial factors of `N = 15` using GCD calculations;
- reconstructs the private exponent independently; and
- decrypts the intercepted ciphertext.

## Module 2: ECC vs Shor

Module 2 demonstrates the corresponding threat to elliptic-curve
cryptography. It:

- asks the user for a small prime-field curve and generator point;
- generates a private scalar `d` and public point `Q = dG`;
- performs transparent toy EC ElGamal encryption;
- gives the attacker only the public curve, `G`, `Q`, and intercepted
  ciphertext points `(C1, C2)`;
- classically searches for `d` on the tiny curve to demonstrate the value that
  Shor's quantum discrete-logarithm algorithm would recover; and
- decrypts the ciphertext using the independently recovered private scalar.

The known working example is:

```text
p = 17, a = 2, b = 2, G = (5, 1)
d = 7, message m = 4, one-time scalar k = 3
```

This produces a generator order of `19`, public point `Q = (0, 6)`, and
ciphertext `((10, 6), (16, 13))`. The attack recovers `d = 7` and `m = 4`.

## Module 3: ML-KEM vs Shor

Module 3 uses the standardized ML-KEM API supplied by the pinned `pqcrypto`
backend. The user can select ML-KEM-512, ML-KEM-768, or ML-KEM-1024. The module
performs:

- randomized encapsulation/decapsulation key generation;
- encapsulation with the public key;
- decapsulation with the private key;
- shared-secret equality verification; and
- an explicit analysis showing that Shor's factoring and discrete-logarithm
  capabilities do not directly solve the Module-LWE problem underlying ML-KEM.

ML-KEM is a KEM, not direct message encryption. A complete application would
use the resulting shared secret with an authenticated symmetric cipher.

## Module 4: ML-DSA vs Shor

Module 4 uses the standardized ML-DSA API supplied by the same backend. The
user can select ML-DSA-44, ML-DSA-65, or ML-DSA-87 and enter a message plus an
optional FIPS 204 context. The module performs:

- randomized signing/verification key generation;
- message signing;
- successful verification of the original message;
- rejection of a modified message; and
- an explicit analysis showing that no known direct Shor attack solves the
  module-lattice assumptions underlying ML-DSA.

## Running the Project

Run the interactive module selector with Python 3:

```console
python -m pip install -r requirements.txt
python main.py
```

Select any of the four modules. Modules 1 and 2 use only the Python standard
library. Modules 3 and 4 require `pqcrypto==1.0.0`, pinned in
`requirements.txt`.

For the original RSA `N = 15` example, enter `3`, `5`, `3`, `2`, and `2` when
prompted for `p`, `q`, `e`, `m`, and `a`, respectively. Other small valid
inputs can also be used.

## Important Limitation

This implementation does **not** execute a quantum circuit and uses no quantum
computer, quantum simulator, Qiskit, or IBM Quantum service.

The RSA order-finding step and ECC discrete-logarithm recovery are performed
with classical loops to reproduce the relevant attack mathematics. Therefore,
these modules demonstrate attack principles; they are not real quantum attacks.
They neither attack production keys nor claim that properly implemented RSA or
ECC can currently be broken by this program.

Modules 3 and 4 perform real ML-KEM and ML-DSA API operations, but the project
and its third-party backend are not presented as a CMVP/FIPS 140 validated
cryptographic module. These demonstrations show correct API behavior and the
different mathematical foundations. They do not prove immunity from every
possible future classical or quantum cryptanalytic advance.

In an actual Shor attack, a sufficiently capable fault-tolerant quantum computer
would accelerate the period/order-finding step. RSA remains secure against
practical classical factorization when appropriately sized, properly generated
keys are used.

## Project Structure

```text
quantum_crypto_demo/
|-- main.py
|-- modules/
|   |-- __init__.py
|   |-- rsa_shor/
|   |   |-- __init__.py
|   |   |-- rsa.py
|   |   |-- shor_math.py
|   |   `-- demo.py
|   |-- ecc_shor/
|   |   |-- __init__.py
|   |   |-- ecc.py
|   |   |-- shor_math.py
|   |   `-- demo.py
|   |-- ml_kem/
|   |   |-- __init__.py
|   |   |-- backend.py
|   |   |-- shor_analysis.py
|   |   `-- demo.py
|   `-- ml_dsa/
|       |-- __init__.py
|       |-- backend.py
|       |-- shor_analysis.py
|       `-- demo.py
|-- tests/
|   |-- __init__.py
|   |-- test_rsa_shor.py
|   |-- test_ecc_shor.py
|   |-- test_ml_kem.py
|   `-- test_ml_dsa.py
|-- requirements.txt
`-- README.md
```

Each module keeps cryptographic operations, attack/applicability logic, and
console presentation separate.

## Standards and Backend

- ML-KEM is standardized in [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203).
- ML-DSA is standardized in [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204).
- The Python operations use the pinned
  [`pqcrypto` package](https://pypi.org/project/pqcrypto/1.0.0/).
