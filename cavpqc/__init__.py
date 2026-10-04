"""
Quantum-resilient blockchain-enabled secure communication for CAVs.

Implementation of the framework proposed in:

    A. M. Aslam, A. Bhardwaj, R. Chaudhary,
    "Quantum-resilient blockchain-enabled secure communication framework for
     connected autonomous vehicles using post-quantum cryptography",
    Vehicular Communications 52 (2025) 100880, Elsevier.
    DOI: 10.1016/j.vehcom.2025.100880

DEVIATIONS FROM THE PUBLISHED PAPER
-----------------------------------
The paper's algorithm listings cannot be executed as printed. Each deviation
below is documented at the point of implementation.

D1  Algorithm 2 / Table 3 -- consensus messages are signed "using KYBER-PQC".
    ML-KEM is a key encapsulation mechanism and defines no signing operation.
    We introduce ML-DSA-65 (FIPS 204) for all signatures.
    -> cavpqc/crypto.py, cavpqc/consensus.py

D2  Algorithm 1 lines 25 and 28 -- the shared secret k_i is defined in terms
    of k_i, and line 28 requires the decapsulating party to use a value it
    cannot possess. We use the standard KEM encaps/decaps interface.
    -> cavpqc/handshake.py

D3  Algorithm 1 line 32 -- K = H(k_i || k'_j) where a correct KEM guarantees
    k_i == k'_j, so this hashes a value against itself. We derive traffic keys
    with a transcript-bound HKDF-SHAKE256 schedule.
    -> cavpqc/crypto.py

D4  Section 5.2.2 vs Table 2 -- the Trusted Authority generates entity private
    keys, which is key escrow and contradicts the paper's own "No key escrow"
    claim; the entity then generates a second keypair, leaving the token bound
    to the wrong key. Entities generate their own keypairs; the TA certifies
    the public key only.
    -> cavpqc/entities.py

D5  Table 4 lists Hyperledger Fabric 2.2 alongside AGS-PBFT. Fabric 2.2 orders
    transactions via Raft and cannot host PBFT-family consensus. We implement
    the ledger directly.
    -> cavpqc/ledger.py

D6  Section 5.4 gives T_low = mu - sigma and T_high = mu + sigma, but all nodes
    start at 100, so sigma = 0 on the first reassignment and every node is
    simultaneously above and below threshold. We add an explicit tie-break.
    -> cavpqc/consensus.py
"""

__version__ = "0.1.0"

PAPER_CITATION = (
    "Aslam, Bhardwaj & Chaudhary, Vehicular Communications 52 (2025) 100880"
)
