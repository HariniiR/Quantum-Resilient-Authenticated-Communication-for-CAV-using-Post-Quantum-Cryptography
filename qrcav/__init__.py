"""
qrcav: quantum-resilient authenticated communication for connected autonomous vehicles.

  crypto/     ML-KEM / ML-DSA suites (OpenSSL and pure-Python backends), HKDF-SHA3-256, AES-GCM records
  pki.py      Trusted Authority, certificates, CRL
  handshake.py  mutually authenticated four-flight handshake (sans-IO)
  consensus/  AGS-PBFT with view change, PBFT baseline, client, simulator
  ledger.py   hash-linked ledger with commit certificates
  net/, nodes/  the distributed system: one process per entity over TCP
  sim/        ns-3 802.11p scenario fed with measured sizes and timings
  eval/       benchmarks, attacks, consensus experiments, ns-3 sweeps, figures
"""

__version__ = "2.0.0"
