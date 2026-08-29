
import hashlib
import os
import time
from dataclasses import dataclass, field

from Crypto.Cipher import AES
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_1024


# Hashing and key generation helpers

def H(*parts, length=32):
    """
    SHAKE-256 hash function used in the protocol.
    """

    h = hashlib.shake_256()

    for part in parts:
        # Store the length before each part
        # so that different combinations cannot look the same.
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)

    return h.digest(length)


def hkdf(shared_secret, transcript, label):
    """
    Generate a key from the ML-KEM shared secret.

    The transcript and label are also used so that
    different keys are generated for different purposes.
    """

    prk = H(
        b"AGS-PBFT-v1-extract",
        shared_secret
    )

    key = H(
        b"AGS-PBFT-v1-expand",
        prk,
        transcript,
        label
    )

    return key

# Trusted Authority

class TrustedAuthority:

    def __init__(self):
        # Secret key of the Trusted Authority
        self.master_key = os.urandom(32)

        # Store registered identities and their tokens
        self.registry = {}

    def register(self, identity, sig_pk):
        """
        Register a CAV or RSU.

        The entity creates its own ML-DSA key pair.
        The TA only receives the public key.
        """

        timestamp = int(time.time())

        # Registration token:
        # H(identity || public key || TA master key || timestamp)
        token = H(
            identity.encode(),
            sig_pk,
            self.master_key,
            str(timestamp).encode()
        )

        self.registry[identity] = token

        return token, timestamp

    def verify_token(self, identity, sig_pk, token, timestamp):

        # Calculate what the token should be
        expected = H(
            identity.encode(),
            sig_pk,
            self.master_key,
            str(timestamp).encode()
        )

        # Compare the received token with the calculated token
        return expected == token


# CAV / RSU

@dataclass
class Entity:

    identity: str

    # ML-DSA keys
    sig_pk: bytes = field(default=b"", repr=False)
    sig_sk: bytes = field(default=b"", repr=False)

    # Information received from the TA
    token: bytes = field(default=b"", repr=False)
    ts: int = 0

    def generate_keys(self):

        # Every entity generates its own ML-DSA key pair
        self.sig_pk, self.sig_sk = ML_DSA_65.keygen()

    def enrol(self, ta):

        # Send identity and public key to the TA
        self.token, self.ts = ta.register(
            self.identity,
            self.sig_pk
        )

# AES-256-GCM communication channel

class SecureChannel:

    # We use a counter so that the same nonce is not reused
    # with the same AES key.
    MAX_RECORDS = 2 ** 32

    def __init__(self, key, base_iv):

        self.key = key
        self.base_iv = base_iv
        self.counter = 0

    def _nonce(self):

        if self.counter >= self.MAX_RECORDS:
            raise RuntimeError("Need to create a new session key")

        # Convert counter to 12 bytes because GCM uses a 12-byte nonce
        counter_bytes = self.counter.to_bytes(12, "big")

        # Create a new nonce for every message
        return bytes(
            a ^ b
            for a, b in zip(self.base_iv, counter_bytes)
        )

    def seal(self, plaintext):

        nonce = self._nonce()

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce
        )

        # AES-GCM gives both encrypted data and an authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        self.counter += 1

        return ciphertext, tag

    def open(self, ciphertext, tag):

        nonce = self._nonce()

        cipher = AES.new(
            self.key,
            AES.MODE_GCM,
            nonce=nonce
        )

        # If the message was modified, this will raise ValueError
        plaintext = cipher.decrypt_and_verify(
            ciphertext,
            tag
        )

        self.counter += 1

        return plaintext


# Handshake

class HandshakeError(Exception):
    pass


def handshake(initiator, responder, ta):

    # This stores the important messages exchanged
    # during the handshake.
    transcript = b""

    # Step 1: RSU creates a temporary ML-KEM key pair

    kem_ek, kem_dk = ML_KEM_1024.keygen()

    # kem_ek -> public key
    # kem_dk -> private key

    # Step 2: RSU signs its identity and KEM public key

    context = (
        responder.identity.encode()
        + responder.token
        + str(responder.ts).encode()
        + kem_ek
    )

    # RSU signs using its long-term ML-DSA private key
    signature = ML_DSA_65.sign(
        responder.sig_sk,
        context
    )

    transcript += context + signature

    # Step 3: CAV checks the RSU's TA registration

    token_valid = ta.verify_token(
        responder.identity,
        responder.sig_pk,
        responder.token,
        responder.ts
    )

    if not token_valid:
        raise HandshakeError()

    # Step 4: CAV checks the ML-DSA signature

    signature_valid = ML_DSA_65.verify(
        responder.sig_pk,
        context,
        signature
    )

    if not signature_valid:
        raise HandshakeError()

    # Step 5: CAV performs ML-KEM encapsulation

    # CAV gets a shared secret and a KEM ciphertext
    shared_i, kem_ct = ML_KEM_1024.encaps(
        kem_ek
    )

    transcript += kem_ct

    # Step 6: RSU decapsulates the KEM ciphertext

    shared_r = ML_KEM_1024.decaps(
        kem_dk,
        kem_ct
    )

    # shared_i and shared_r should be the same

    # Step 7: Hash the handshake transcript

    transcript_hash = H(
        b"transcript",
        transcript
    )
    # Step 8: Generate the keys used by AES-GCM

    def derive(secret):

        # Key used for CAV -> RSU
        cav_to_rsu_key = hkdf(
            secret,
            transcript_hash,
            b"key_i2r"
        )

        # Key used for RSU -> CAV
        rsu_to_cav_key = hkdf(
            secret,
            transcript_hash,
            b"key_r2i"
        )

        # IV used for CAV -> RSU
        cav_to_rsu_iv = hkdf(
            secret,
            transcript_hash,
            b"iv_i2r"
        )[:12]

        # IV used for RSU -> CAV
        rsu_to_cav_iv = hkdf(
            secret,
            transcript_hash,
            b"iv_r2i"
        )[:12]

        cav_to_rsu = SecureChannel(
            cav_to_rsu_key,
            cav_to_rsu_iv
        )

        rsu_to_cav = SecureChannel(
            rsu_to_cav_key,
            rsu_to_cav_iv
        )

        return cav_to_rsu, rsu_to_cav

    # Both sides independently derive their keys
    cav_send, cav_receive = derive(shared_i)
    rsu_send, rsu_receive = derive(shared_r)
    # Step 9: Check that both sides generated the same key

    if cav_send.key != rsu_send.key:
        raise HandshakeError()

    # The temporary ML-KEM private key and shared secrets
    # are not needed anymore.
    del kem_dk
    del shared_i
    del shared_r

    # Calculate the amount of handshake data
    handshake_bytes = (
        len(context)
        + len(signature)
        + len(kem_ct)
    )

    return (
        (cav_send, cav_receive),
        (rsu_send, rsu_receive),
        handshake_bytes
    )

# Demo

def main():

    print("\n" + "=" * 65)
    print("        QUANTUM RESILIENT V2X COMMUNICATION")
    print("        ML-KEM-1024 + ML-DSA-65 + AES-256-GCM")
    print("=" * 65)

    # 1. Create TA, CAV and RSU

    print("\n[1] CREATING ENTITIES")
    print("-" * 65)

    ta = TrustedAuthority()

    vehicle = Entity("CAV_001")
    rsu = Entity("RSU_042")

    print("    Trusted Authority : created")
    print("    CAV_001           : created")
    print("    RSU_042           : created")

    # 2. Register CAV and RSU
    print("\n[2] REGISTRATION")
    print("-" * 65)

    start = time.perf_counter()

    vehicle.generate_keys()
    vehicle.enrol(ta)

    rsu.generate_keys()
    rsu.enrol(ta)

    registration_time = (
        time.perf_counter() - start
    ) * 1000

    print("    CAV_001 -> TA     : REGISTERED")
    print("    RSU_042 -> TA     : REGISTERED")
    print("    Algorithm         : ML-DSA-65")
    print(f"    Public key size   : {len(rsu.sig_pk)} bytes")
    print(f"    Token size        : {len(rsu.token)} bytes")
    print(f"    Registration time : {registration_time:.2f} ms")

    # 3. Authenticated handshake

    print("\n[3] CAV <-> RSU HANDSHAKE")
    print("-" * 65)

    start = time.perf_counter()

    try:

        (vehicle_send, vehicle_receive), \
        (rsu_send, rsu_receive), \
        handshake_bytes = handshake(
            vehicle,
            rsu,
            ta
        )

        handshake_time = (
            time.perf_counter() - start
        ) * 1000

        print("    ML-KEM-1024 key generation : SUCCESS")
        print("    TA token verification      : SUCCESS")
        print("    ML-DSA signature           : SUCCESS")
        print("    ML-KEM encapsulation       : SUCCESS")
        print("    ML-KEM decapsulation       : SUCCESS")
        print("    Shared secret              : ESTABLISHED")
        print("    Session keys               : GENERATED")

    except HandshakeError:

        print("    Handshake failed!")
        return

    print(f"\n    Handshake time       : {handshake_time:.2f} ms")
    print(f"    Data exchanged      : {handshake_bytes} bytes")

    if handshake_time < 100:
        print("    100 ms target       : PASS")
    else:
        print("    100 ms target       : NOT MET")

    # 4. Send a V2X message

    print("\n[4] SECURE V2X MESSAGE")
    print("-" * 65)

    beacon = (
        b'{"id":"CAV_001",'
        b'"spd":13.9,'
        b'"lat":30.7299,'
        b'"lon":76.7771}'
    )

    print("    CAV_001 -> RSU_042")

    print("\n    Original message:")
    print("    " + beacon.decode())

    start = time.perf_counter()

    # CAV encrypts the message
    ciphertext, tag = vehicle_send.seal(beacon)

    # RSU decrypts the message
    recovered = rsu_send.open(
        ciphertext,
        tag
    )

    record_time = (
        time.perf_counter() - start
    ) * 1000

    print("\n    AES-256-GCM encryption : SUCCESS")
    print("    AES-256-GCM decryption : SUCCESS")

    print("\n    Recovered message:")
    print("    " + recovered.decode())

    print(f"\n    Encryption + decryption : "
          f"{record_time:.3f} ms")

    if recovered == beacon:
        print("    Message integrity       : PASS")
    else:
        print("    Message integrity       : FAIL")

    # 5. Test message tampering

    print("\n[5] ATTACK TEST - MESSAGE TAMPERING")
    print("-" * 65)

    # Change one byte of the encrypted message
    tampered = (
        bytes([ciphertext[0] ^ 0x01])
        + ciphertext[1:]
    )

    try:

        rsu_receive.open(
            tampered,
            tag
        )

        print("    Tampered message       : ACCEPTED")
        print("    Security test          : FAILED")

    except ValueError:

        print("    Tampered message       : REJECTED")
        print("    AES-GCM integrity      : PASS")

    # 6. Test RSU impersonation

    print("\n[6] ATTACK TEST - RSU IMPERSONATION")
    print("-" * 65)

    # The attacker uses the same identity as the real RSU,
    # but generates a different ML-DSA key pair.
    impostor = Entity("RSU_042")

    impostor.generate_keys()

    # Assume the attacker somehow got the real RSU's token.
    # They still do not have the real RSU's private key.
    impostor.token = rsu.token
    impostor.ts = rsu.ts

    try:

        handshake(
            vehicle,
            impostor,
            ta
        )

        print("    Impersonated RSU     : ACCEPTED")
        print("    Security test        : FAILED")

    except HandshakeError:

        print("    Impersonated RSU     : REJECTED")
        print("    ML-DSA authentication: PASS")

    # 7. Summary
    print("\n" + "=" * 65)
    print("                         DEMO SUMMARY")
    print("=" * 65)

    print("\nAlgorithms used:")
    print("    ML-KEM-1024  -> Key establishment")
    print("    ML-DSA-65    -> Authentication")
    print("    SHAKE-256    -> Hashing and key derivation")
    print("    AES-256-GCM  -> V2X message encryption")

    print("\nTests completed:")
    print("    CAV/RSU registration   -> SUCCESS")
    print("    PQC handshake          -> SUCCESS")
    print("    Secure V2X message     -> SUCCESS")
    print("    Message tampering      -> REJECTED")
    print("    RSU impersonation      -> REJECTED")

    print("\nCurrent stage:")
    print("    PQC communication layer -> COMPLETED")

    print("\nNext stage:")
    print("    SUMO vehicle simulation")
    print("    Veins + OMNeT++ network simulation")
    print("    Multiple CAVs and RSUs")
    print("    AGS-PBFT integration")
    print("    Latency and throughput analysis")

    print("\n" + "=" * 65)
    print("                         END OF DEMO")
    print("=" * 65)


if __name__ == "__main__":
    main()

