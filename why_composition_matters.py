"""
WHY THIS IS NOT "JUST CALLING FUNCTIONS".

Below are two handshakes. Both use the SAME six library calls. Both agree a
shared secret. Both "work".

One is completely broken.

Run it:  ./.venv/bin/python why_composition_matters.py
"""

from kyber_py.ml_kem import ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_65


# ==========================================================================
#  VERSION A - the obvious way. Agrees a key. Uses the library correctly.
#              Totally insecure.
# ==========================================================================

def version_a_naive():
    """RSU sends its temporary lock. Car uses it. What could go wrong?"""

    # --- honest RSU prepares ---
    rsu_lock, rsu_key = ML_KEM_1024.keygen()

    # --- the wire: attacker sits in the middle and swaps the lock ---
    atk_lock, atk_key = ML_KEM_1024.keygen()
    lock_the_car_receives = atk_lock          # <-- substitution

    # --- car does everything right ---
    car_secret, box = ML_KEM_1024.encaps(lock_the_car_receives)

    # --- attacker opens the box, learns the secret, forwards a new one ---
    attacker_secret = ML_KEM_1024.decaps(atk_key, box)
    rsu_secret, box2 = ML_KEM_1024.encaps(rsu_lock)
    rsu_opened = ML_KEM_1024.decaps(rsu_key, box2)

    car_thinks_its_fine = (car_secret == attacker_secret)
    rsu_thinks_its_fine = (rsu_secret == rsu_opened)
    attacker_knows_car_key = (attacker_secret == car_secret)

    return car_thinks_its_fine, rsu_thinks_its_fine, attacker_knows_car_key


# ==========================================================================
#  VERSION B - bind the lock to a signed identity. Same six calls.
#              The substitution now fails.
# ==========================================================================

def version_b_correct(rsu_public, rsu_private):
    """The RSU signs its temporary lock, so the lock cannot be swapped."""

    rsu_lock, rsu_key = ML_KEM_1024.keygen()
    proof = ML_DSA_65.sign(rsu_private, rsu_lock)       # <-- the whole difference

    # --- attacker tries the same substitution ---
    atk_lock, atk_key = ML_KEM_1024.keygen()
    lock_the_car_receives = atk_lock
    proof_the_car_receives = proof      # attacker cannot forge a new one

    # --- car verifies BEFORE using the lock ---
    accepted = ML_DSA_65.verify(rsu_public, lock_the_car_receives,
                                proof_the_car_receives)
    return accepted


# ==========================================================================

def main():
    print("=" * 66)
    print("SAME SIX LIBRARY CALLS. DIFFERENT COMPOSITION.")
    print("=" * 66)

    car_ok, rsu_ok, attacker_won = version_a_naive()
    print("\nVERSION A  (no signature binding the temporary lock)")
    print(f"  car believes handshake succeeded      : {car_ok}")
    print(f"  RSU believes handshake succeeded      : {rsu_ok}")
    print(f"  attacker knows the car's session key  : {attacker_won}   <-- BROKEN")
    print("  Both parties are happy. Everything 'works'. The attacker")
    print("  reads and rewrites every safety message.")

    rsu_public, rsu_private = ML_DSA_65.keygen()
    accepted = version_b_correct(rsu_public, rsu_private)
    print("\nVERSION B  (temporary lock signed with the RSU's identity key)")
    print(f"  car accepts the substituted lock      : {accepted}   <-- SAFE")
    print("  The signature does not match the swapped lock, so the car")
    print("  aborts before a key is ever agreed.")

    print("\n" + "=" * 66)
    print("The library cannot make this decision for you.")
    print("Deciding WHAT gets signed, and WHEN it gets checked, is the")
    print("engineering. This exact class of mistake is what our base paper")
    print("gets wrong - it never binds identity to key material correctly.")
    print("=" * 66)


if __name__ == "__main__":
    main()
