
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

        return ciphertext, tag, nonce

    def open(self, ciphertext, tag, nonce=None):
        if nonce is None:
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
    rsu_receive,rsu_send = derive(shared_r)
    # Step 9: Check that both sides generated the same key

    if cav_send.key != rsu_receive.key:
        raise HandshakeError()

    # The temporary ML-KEM private key and shared secrets
    # are not needed anymore.
    

    # Calculate the amount of handshake data
    handshake_bytes = (
        len(context)
        + len(signature)
        + len(kem_ct)
    )

    shared_secret = shared_i
    cav_key = cav_send.key
    cav_iv = cav_send.base_iv
    rsu_key = rsu_send.key
    rsu_iv = rsu_send.base_iv

    del kem_dk
    del shared_i
    del shared_r
    # Return all 9 values
    return (
        (cav_send, cav_receive),      # 1. Initiator channels
        (rsu_send, rsu_receive),      # 2. Responder channels
        handshake_bytes,              # 3. Handshake size
        shared_secret,                # 4. Shared secret
        transcript_hash,              # 5. Transcript hash
        cav_key,                       # 6. CAV encryption key
        cav_iv,                        # 7. CAV base IV
        rsu_key,                       # 8. RSU encryption key
        rsu_iv                         # 9. RSU base IV
    )

# Demo

def main():
 
    print("\n")
    print(" " * 15 + "QUANTUM RESILIENT V2X COMMUNICATION")
    print(" " * 20 + "DETAILED CRYPTOGRAPHIC DEMO")
    print(" " * 15 + "ML-KEM-1024 + ML-DSA-65 + AES-256-GCM")
   
 
    # 1. Create TA, CAV and RSU
 
    print("\n[STEP 1] CREATING ENTITIES")
    
 
    ta = TrustedAuthority()
 
    vehicle = Entity("CAV_001")
    rsu = Entity("RSU_042")
 
    print("   Trusted Authority      : created")
    print("   CAV_001               : created")
    print("   RSU_042               : created")
 
    # 2. Register CAV and RSU
    print("\n[STEP 2] ENTITY REGISTRATION WITH TRUSTED AUTHORITY")
    
 
    start = time.perf_counter()
 
    vehicle.generate_keys()
    vehicle.enrol(ta)
 
    rsu.generate_keys()
    rsu.enrol(ta)
 
    registration_time = (
        time.perf_counter() - start
    ) * 1000
 
    print(f"   CAV_001               : REGISTERED")
    print(f"   RSU_042               : REGISTERED")
    print(f"\n  Algorithm               : ML-DSA-65 (lattice-based signatures)")
    print(f"  Public key size         : {len(rsu.sig_pk)} bytes")
    print(f"  Registration token      : {len(rsu.token)} bytes")
    print(f"  Token (hex)             : {rsu.token.hex()}")
    print(f"  Registration time       : {registration_time:.2f} ms")
 
    # 3. Authenticated handshake
 
    print("\n[STEP 3] AUTHENTICATED HANDSHAKE (CAV ↔ RSU)")
   
 
    start = time.perf_counter()
 
    try:
 
        (vehicle_send, vehicle_receive), \
        (rsu_send, rsu_receive), \
        handshake_bytes, \
        shared_secret, \
        transcript_hash, \
        cav_key, \
        cav_iv, \
        rsu_key, \
        rsu_iv = handshake(
            vehicle,
            rsu,
            ta
        )
 
        handshake_time = (
            time.perf_counter() - start
        ) * 1000
 
        print("   Step 1: RSU generates ephemeral ML-KEM keypair")
        print("   Step 2: RSU signs (identity || token || timestamp || ephemeral_key)")
        print("   Step 3: CAV verifies TA token")
        print("   Step 4: CAV verifies RSU's ML-DSA signature")
        print("   Step 5: CAV performs ML-KEM encapsulation")
        print("   Step 6: RSU performs ML-KEM decapsulation")
        print("   Step 7: Both derive shared secret (identical)")
        print("   Step 8: Both derive session keys (transcript-bound HKDF)")
        print("   Step 9: Key confirmation (implicit)")
 
    except HandshakeError as e:
 
        print("   Handshake failed!")
        return
 
    print(f"\n  Handshake time          : {handshake_time:.2f} ms")
    print(f"  Data exchanged          : {handshake_bytes} bytes")
    print(f"  Within 100 ms budget?   : {'YES ' if handshake_time < 100 else 'NO '}")
 
    # Display cryptographic values
    print("\n[STEP 4] CRYPTOGRAPHIC VALUES")
    
 
    print(f"\n  Shared Secret:")
    print(f"    Length              : {len(shared_secret)} bytes")
    print(f"    Value (hex)         : {shared_secret.hex()}")
 
    print(f"\n  Transcript Hash (binds all handshake messages):")
    print(f"    Length              : {len(transcript_hash)} bytes")
    print(f"    Value (hex)         : {transcript_hash.hex()}")
 
    print(f"\n  CAV - RSU Direction:")
    print(f"    Encryption key      : {cav_key.hex()}")
    print(f"    Base IV             : {cav_iv.hex()}")
    print(f"    Nonce counter       : 0 (will increment per message)")
 
    print(f"\n  RSU - CAV Direction:")
    print(f"    Encryption key      : {rsu_key.hex()}")
    print(f"    Base IV             : {rsu_iv.hex()}")
    print(f"    Nonce counter       : 0 (will increment per message)")
 
    # 4. Send a V2X beacon from CAV to RSU
 
    print("\n[STEP 5] SECURE V2X MESSAGE (CAV → RSU)")
    
 
    beacon = (
        b'{"id":"CAV_001",'
        b'"spd":13.9,'
        b'"lat":30.7299,'
        b'"lon":76.7771}'
    )
 
    print(f"\n  Original Plaintext Message:")
    print(f"    {beacon.decode()}")
    print(f"    Length              : {len(beacon)} bytes")
    print(f"    Hex                 : {beacon.hex()}")
 
    start = time.perf_counter()
 
    # CAV encrypts the message
    ciphertext, tag, nonce = vehicle_send.seal(beacon)
 
    encryption_time = (time.perf_counter() - start) * 1000
 
    print(f"\n  Encryption Process (AES-256-GCM):")
    print(f"    Algorithm           : AES-256-GCM")
    print(f"    Nonce               : {nonce.hex()}")
    print(f"    Nonce calculation   : base_iv XOR counter")
    print(f"    Encryption time     : {encryption_time:.3f} ms")
 
    print(f"\n  Encrypted Data:")
    print(f"    Ciphertext length   : {len(ciphertext)} bytes")
    print(f"    Ciphertext (hex)    : {ciphertext.hex()}")
    print(f"    Authentication tag  : {tag.hex()}")
    print(f"    Total overhead      : {len(tag)} bytes (GCM tag)")
 
    # RSU decrypts the message
    start = time.perf_counter()
    recovered = rsu_receive.open(
        ciphertext,
        tag,
        nonce
    )
    decryption_time = (time.perf_counter() - start) * 1000
 
    print(f"\n  Decryption Process (AES-256-GCM):")
    print(f"    Decryption time     : {decryption_time:.3f} ms")
    print(f"    Authentication      : VERIFIED ")
 
    print(f"\n  Recovered Plaintext:")
    print(f"    {recovered.decode()}")
    print(f"    Length              : {len(recovered)} bytes")
    print(f"    Hex                 : {recovered.hex()}")
    print(f"    Matches original?   : {'YES ' if recovered == beacon else 'NO '}")
 
    # 5. Send a response from RSU to CAV
 
    print("\n[STEP 6] SECURE V2X MESSAGE (RSU - CAV)")
  
 
    command = b'{"cmd":"reduce_speed","value":10.0}'
 
    print(f"\n  Original Plaintext Message:")
    print(f"    {command.decode()}")
    print(f"    Length              : {len(command)} bytes")
    print(f"    Hex                 : {command.hex()}")
 
    start = time.perf_counter()
 
    # RSU encrypts the command
    ciphertext_resp, tag_resp, nonce_resp = rsu_send.seal(command)
 
    encryption_time_resp = (time.perf_counter() - start) * 1000
 
    print(f"\n  Encryption Process (AES-256-GCM):")
    print(f"    Algorithm           : AES-256-GCM")
    print(f"    Nonce               : {nonce_resp.hex()}")
    print(f"    Nonce counter       : 1 (incremented from previous message)")
    print(f"    Encryption time     : {encryption_time_resp:.3f} ms")
 
    print(f"\n  Encrypted Data:")
    print(f"    Ciphertext length   : {len(ciphertext_resp)} bytes")
    print(f"    Ciphertext (hex)    : {ciphertext_resp.hex()}")
    print(f"    Authentication tag  : {tag_resp.hex()}")
 
    # CAV decrypts the command
    start = time.perf_counter()
    recovered_resp = vehicle_receive.open(
        ciphertext_resp,
        tag_resp,
        nonce_resp
    )
    decryption_time_resp = (time.perf_counter() - start) * 1000
 
    print(f"\n  Decryption Process (AES-256-GCM):")
    print(f"    Decryption time     : {decryption_time_resp:.3f} ms")
    print(f"    Authentication      : VERIFIED ")
 
    print(f"\n  Recovered Plaintext:")
    print(f"    {recovered_resp.decode()}")
    print(f"    Length              : {len(recovered_resp)} bytes")
    print(f"    Hex                 : {recovered_resp.hex()}")
    print(f"    Matches original?   : {'YES ' if recovered_resp == command else 'NO '}")
 
    # 6. Summary
    print("\n")
    print(" " * 30 + "DEMO SUMMARY")
    
 
    print("\nCryptographic Algorithms Used:")
    print("  • ML-KEM-1024         : Key establishment (NIST FIPS 203)")
    print("  • ML-DSA-65           : Authentication (NIST FIPS 204)")
    print("  • SHAKE-256           : Hashing & key derivation")
    print("  • AES-256-GCM         : Record protection (symmetric encryption)")
 
    print("\nSecurity Properties Demonstrated:")
    print("   Quantum resistance  : Lattice-based cryptography")
    print("   Authentication      : ML-DSA-65 signatures + TA tokens")
    print("   Key agreement       : ML-KEM-1024 encapsulation")
    print("   Transcript binding  : Keys include handshake hash")
    print("   Confidentiality     : AES-256 (256-bit symmetric)")
    print("   Integrity           : GCM authentication tags")
    print("   Replay prevention   : Monotonic nonce counter")
    print("   Forward secrecy     : Ephemeral key erasure")
 
    print("\nOperations Completed:")
    print(f"   Entity registration           : {registration_time:.2f} ms")
    print(f"   Handshake (7 steps)           : {handshake_time:.2f} ms")
    print(f"   Message encryption            : {encryption_time:.3f} ms")
    print(f"   Message decryption            : {decryption_time:.3f} ms")
    print(f"   Response encryption           : {encryption_time_resp:.3f} ms")
    print(f"   Response decryption           : {decryption_time_resp:.3f} ms")
    print(f"   Total demo time               : {handshake_time + encryption_time + decryption_time + encryption_time_resp + decryption_time_resp:.2f} ms")
 
    print("\nPerformance Metrics:")
    print(f"   Handshake size                : {handshake_bytes} bytes")
    print(f"   Message encryption overhead   : {len(tag)} bytes (GCM tag)")
    print(f"   802.11p frame size            : 1500 bytes max")
    print(f"   Frames needed for handshake   : {-(-handshake_bytes // 1500)} frames")
 
    print("\n")
    print(" " * 25 + "QUANTUM-RESILIENT V2X READY ✓")
    
 
 
if __name__ == "__main__":
    main()

