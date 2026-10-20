"""
Watch two processes talk: an RSU in one terminal, a vehicle in another.

    python scripts/two_terminals.py setup      # once: TA issues certificates, then exits
    python scripts/two_terminals.py rsu        # terminal 1: RSU_01 waits on port 7401
    python scripts/two_terminals.py cav        # terminal 2: CAV_01 connects and you type commands

In the vehicle's terminal:
    b          send a beacon           e      send a critical event
    t          send a TAMPERED record  r      REPLAY the last record
    any text   send it as a message    q      quit

Revocation: setup also registers CAV_02 and has the TA revoke it, so
    python scripts/two_terminals.py cav --id CAV_02
is refused by the RSU during the handshake.

Same code as the full system (handshake.py, records.py, net/secure.py
framing); only the TA is done ahead of time, so just two processes run.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrcav import codec  # noqa: E402
from qrcav.crypto import get_suite  # noqa: E402
from qrcav.crypto.records import RecordError  # noqa: E402
from qrcav.handshake import ClientHandshake, HandshakeError, ReplayCache, ServerHandshake  # noqa: E402
from qrcav.net.secure import ChannelClosed, read_frame, write_frame  # noqa: E402
from qrcav.pki import CRL, Certificate, Identity, TrustedAuthority  # noqa: E402

DIR = ROOT / "run_two"
B, D, G, R, Y, X = "\033[1m", "\033[2m", "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def say(who: str, text: str) -> None:
    t = time.strftime("%H:%M:%S") + f".{int(time.time() % 1 * 1000):03d}"
    print(f"{D}{t}{X} {B}[{who}]{X} {text}", flush=True)


def hx(b: bytes, n: int = 12) -> str:
    return b[:n].hex() + ("..." if len(b) > n else "")


# ------------------------------------------------------------------ setup (the TA)

def setup(suite_name: str) -> None:
    suite = get_suite(suite_name)
    DIR.mkdir(exist_ok=True)
    ta = TrustedAuthority(suite)
    say("TA", f"key pair made ({suite.sig.name}); public key {len(ta.pk)} B")
    for ident, role in (("RSU_01", "RSU"), ("CAV_01", "CAV"), ("CAV_02", "CAV")):
        me = Identity.generate(ident, role, suite)          # the entity makes its own keys
        cert = ta.register(me.registration_request())       # TA checks proof of possession, signs
        me.accept_certificate(cert, ta.anchor())
        me.save(DIR / f"{ident}.key")
        say("TA", f"certified {ident} ({role}), serial {cert.serial}, {len(cert.encode())} B "
                  f"-> run_two/{ident}.key")
    crl = ta.revoke("CAV_02")
    (DIR / "crl.bin").write_bytes(crl.encode())
    say("TA", f"revoked CAV_02: signed CRL v{crl.version} with serials {list(crl.revoked_serials)} "
              f"-> run_two/crl.bin")
    say("TA", "done. Now run 'rsu' in one terminal and 'cav' in another.")


def load(ident: str) -> Identity:
    path = DIR / f"{ident}.key"
    if not path.exists():
        raise SystemExit(f"{path} not found: run  python scripts/two_terminals.py setup  first")
    return Identity.load(path)


# ------------------------------------------------------------------ RSU (server)

async def rsu_main(port: int) -> None:
    me = load("RSU_01")
    crl = CRL.decode((DIR / "crl.bin").read_bytes())
    ok = me.anchor.update_crl(crl)
    say("RSU_01", f"loaded TA-signed CRL v{crl.version} ({'signature OK' if ok else 'BAD signature'}), "
                  f"revoked serials {list(crl.revoked_serials)}")
    replay_cache = ReplayCache()

    async def handle(reader, writer):
        peer = "%s:%s" % writer.get_extra_info("peername")[:2]
        say("RSU_01", f"{Y}TCP connection from {peer}{X}")
        hs = ServerHandshake(me, allowed_roles=("CAV",), replay_cache=replay_cache)
        try:
            ch = await read_frame(reader)
            cert = Certificate.decode(codec.decode(ch)["cert"])
            say("RSU_01", f"<- flight 1 ClientHello {len(ch)} B: claims to be {cert.id} ({cert.role}), "
                          f"serial {cert.serial}")
            if me.anchor.crl.is_revoked(cert.serial):
                say("RSU_01", f"   {R}serial {cert.serial} is on the CRL{X}")
            sh = hs.on_client_hello(ch)
            say("RSU_01", "   certificate checked against the TA key, CRL, role; made a fresh ML-KEM key pair")
            await write_frame(writer, sh)
            say("RSU_01", f"-> flight 2 ServerHello {len(sh)} B (my cert, ephemeral pk_kem, my signature)")
            ck = await read_frame(reader)
            say("RSU_01", f"<- flight 3 ClientKey {len(ck)} B (KEM ciphertext, client signature, Finished)")
            fs, sess = hs.on_client_key(ck)
            say("RSU_01", "   client signature OK, decapsulated the shared secret, derived keys, Finished OK")
            await write_frame(writer, fs)
            say("RSU_01", f"-> flight 4 Finished {len(fs)} B")
            say("RSU_01", f"{G}secure session with {sess.peer.id}: {sess.handshake_bytes} B, "
                          f"{sess.elapsed_ms:.1f} ms{X}  k_s2c {hx(sess.sender.key)}")
        except HandshakeError:
            say("RSU_01", f"{R}handshake REJECTED; closing the connection (no reason is sent back){X}")
            writer.close()
            return
        except ChannelClosed:
            writer.close()
            return

        try:
            while True:
                rec = await read_frame(reader)
                ctr = int.from_bytes(rec[:8], "big")
                try:
                    msg = sess.open(rec)
                except RecordError:
                    say("RSU_01", f"{R}<- record ctr {ctr}, {len(rec)} B: DROPPED "
                                  f"(tag check failed or counter already seen){X}")
                    continue
                say("RSU_01", f"<- record ctr {ctr}, {len(rec)} B on the wire: {D}{hx(rec[8:], 16)}{X}")
                say("RSU_01", f"   decrypted: {msg}")
                if msg.get("src") != sess.peer.id:
                    say("RSU_01", f"   {R}src does not match the session's peer: ignored{X}")
                    continue
                reply = sess.seal({"type": "ack", "seq": msg.get("seq")})
                await write_frame(writer, reply)
                say("RSU_01", f"-> ack, {len(reply)} B")
        except ChannelClosed:
            say("RSU_01", f"{Y}{sess.peer.id} disconnected{X}")
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    say("RSU_01", f"listening on 127.0.0.1:{port}; accepts vehicles only. Ctrl+C to stop.")
    async with server:
        await server.serve_forever()


# ------------------------------------------------------------------ vehicle (client)

async def cav_main(ident: str, port: int, auto: bool) -> None:
    me = load(ident)
    say(ident, f"loaded my keys and certificate (serial {me.cert.serial})")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    say(ident, f"{Y}TCP connected to 127.0.0.1:{port}{X}")
    hs = ClientHandshake(me, expected_role="RSU", expected_id="RSU_01")
    try:
        ch = hs.client_hello()
        await write_frame(writer, ch)
        say(ident, f"-> flight 1 ClientHello {len(ch)} B (suite, my cert, nonce, time)")
        sh = await read_frame(reader)
        say(ident, f"<- flight 2 ServerHello {len(sh)} B")
        ck = hs.on_server_hello(sh)
        say(ident, "   RSU_01 cert and signature OK; encapsulated to its pk_kem; signed; derived keys")
        await write_frame(writer, ck)
        say(ident, f"-> flight 3 ClientKey {len(ck)} B")
        fs = await read_frame(reader)
        sess = hs.on_server_finished(fs)
        say(ident, f"<- flight 4 Finished {len(fs)} B: OK")
        say(ident, f"{G}secure session with {sess.peer.id}: {sess.handshake_bytes} B, "
                   f"{sess.elapsed_ms:.1f} ms{X}  k_c2s {hx(sess.sender.key)}")
    except ChannelClosed:
        say(ident, f"{R}RSU closed the connection: handshake rejected{X}")
        return
    except HandshakeError:
        say(ident, f"{R}handshake failed on my side (the RSU did not prove its identity){X}")
        return

    async def listen():
        try:
            while True:
                rec = await read_frame(reader)
                say(ident, f"<- {sess.open(rec)}")
        except (ChannelClosed, RecordError):
            pass

    asyncio.ensure_future(listen())
    seq, last = 0, None
    loop = asyncio.get_running_loop()
    script = ["b", "e", "t", "r", "hello RSU", "q"] if auto else None
    print(f"\n  commands: {B}b{X} beacon  {B}e{X} event  {B}t{X} tampered  {B}r{X} replay  "
          f"{B}<text>{X} message  {B}q{X} quit\n", flush=True)
    while True:
        if script:
            await asyncio.sleep(0.6)
            cmd = script.pop(0)
            print(f"> {cmd}", flush=True)
        else:
            cmd = (await loop.run_in_executor(None, input, "> ")).strip()
        if cmd in ("q", "quit", "exit"):
            break
        if not cmd:
            continue
        if cmd == "r":
            if last is None:
                print("  nothing to replay yet", flush=True)
                continue
            await write_frame(writer, last)
            say(ident, f"-> REPLAYED the last record (ctr {int.from_bytes(last[:8], 'big')})")
            continue
        seq += 1
        if cmd in ("b", "t"):
            obj = {"type": "beacon", "src": ident, "seq": seq, "pos": [80.3, 13.1], "speed": 13.9}
        elif cmd == "e":
            obj = {"type": "event", "src": ident, "seq": seq, "kind": "collision_ahead", "criticality": 1}
        else:
            obj = {"type": "text", "src": ident, "seq": seq, "text": cmd}
        rec = sess.seal(obj)
        if cmd == "t":
            bad = bytearray(rec)
            bad[12] ^= 1
            await write_frame(writer, bytes(bad))
            say(ident, f"-> TAMPERED record ctr {seq}: one bit flipped in the ciphertext")
            continue
        await write_frame(writer, rec)
        last = rec
        say(ident, f"-> {obj['type']} seq {seq}: encrypted record ctr {seq}, {len(rec)} B")
    writer.close()
    await asyncio.sleep(0.2)
    say(ident, "closed")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("role", choices=["setup", "rsu", "cav"])
    ap.add_argument("--suite", default="DECK", help="for setup: DECK, L1, L3, L5, CLASSIC")
    ap.add_argument("--id", default="CAV_01", help="for cav: CAV_01, or CAV_02 (revoked)")
    ap.add_argument("--port", type=int, default=7401)
    ap.add_argument("--auto", action="store_true", help="for cav: run b, e, t, r, text, q by itself")
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")
    try:
        if args.role == "setup":
            setup(args.suite)
        elif args.role == "rsu":
            asyncio.run(rsu_main(args.port))
        else:
            asyncio.run(cav_main(args.id, args.port, args.auto))
    except KeyboardInterrupt:
        pass
    except ConnectionRefusedError:
        print("could not connect: start the RSU first (python scripts/two_terminals.py rsu)")


if __name__ == "__main__":
    main()
