"""
THE WHOLE PROJECT, IN 15 LINES.

Run it:  ./.venv/bin/python demo.py

A car and a roadside unit have never met. By the end of this script they share
a secret key that nobody listening could have worked out - and the car knows
it is really talking to the roadside unit, not an impostor.

That is it. That is the core of the project. Everything else we build is
plumbing wrapped around these fifteen lines.
"""

from kyber_py.ml_kem import ML_KEM_1024      # for agreeing a secret key
from dilithium_py.ml_dsa import ML_DSA_65    # for proving who you are

# The roadside unit has a permanent identity keypair. Think of the private key
# as its signature, and the public key as a sample of that signature that
# everyone already has a copy of.
rsu_public, rsu_private = ML_DSA_65.keygen()

# 1. The RSU creates a TEMPORARY lock, just for this one conversation.
temp_lock, temp_key = ML_KEM_1024.keygen()

# 2. The RSU signs the temporary lock, to prove the lock really came from it.
proof = ML_DSA_65.sign(rsu_private, temp_lock)

# 3. The car checks the signature. If this fails, someone is impersonating.
assert ML_DSA_65.verify(rsu_public, temp_lock, proof), "impostor!"

# 4. The car invents a secret, puts it in a box, and locks it with temp_lock.
car_secret, box = ML_KEM_1024.encaps(temp_lock)

# 5. The RSU opens the box with the matching temporary key.
rsu_secret = ML_KEM_1024.decaps(temp_key, box)

# Both sides now hold the identical secret, never having sent it.
assert car_secret == rsu_secret

print("Car secret :", car_secret.hex()[:32], "...")
print("RSU secret :", rsu_secret.hex()[:32], "...")
print("Match      :", car_secret == rsu_secret)
print()
print("They now share a key. Use it with AES to encrypt actual messages.")
