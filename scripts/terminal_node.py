"""
Run the real system's entities in separate terminals, and watch every message.

Each command starts the same real processes that run_network.py starts, with
message tracing on, so every record shows up as "->" in the sender's terminal
and "<-" in the receiver's. Start them in this order, each in its own terminal:

    python scripts/terminal_node.py TA        # 1: Trusted Authority (wipes run_terminals/ first)
    python scripts/terminal_node.py NODES     # 2: the 4 consensus nodes + the cloud, together
    python scripts/terminal_node.py MEC       # 3: the edge server (consensus client)
    python scripts/terminal_node.py RSU_01    # 4: the roadside unit (server for the vehicles)
    python scripts/terminal_node.py CAV_01    # 5: a vehicle (client)
    python scripts/terminal_node.py CAV_02    # 6: a second vehicle (optional)

In a vehicle's terminal, type:
    event collision_ahead        critical event: alert to every vehicle, then a block on the ledger
    event pothole 0              routine event: stored in the cloud, no consensus
    CAV_02 hello there           V2V message to CAV_02 through the RSU
    quit                         stop this vehicle

Revoke a vehicle from another terminal (the RSU then drops it and refuses it):
    python scripts/terminal_node.py revoke CAV_02

Vehicles send a beacon every 2 s; --beacon-every 10 slows them down and
--beacon-every 0 switches them off. Uses config/terminals.json (ports 76xx).
Stop any terminal with Ctrl+C.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("QRCAV_TRACE", "1")          # print every record sent and received

from qrcav.net.secure import plain_request  # noqa: E402
from qrcav.nodes.base import all_entities, load_config  # noqa: E402
from qrcav.nodes.cav import CAVNode  # noqa: E402
from qrcav.nodes.mec import MECNode  # noqa: E402
from qrcav.nodes.rsu import RSUNode  # noqa: E402
from qrcav.nodes.ta import TANode  # noqa: E402


class InteractiveCAV(CAVNode):
    """The normal vehicle, plus commands typed in its terminal (events and V2V messages)."""

    async def run(self) -> None:
        asyncio.ensure_future(self._keyboard())
        await super().run()

    async def _keyboard(self) -> None:
        while getattr(self, "rsu", None) not in self.channels:
            await asyncio.sleep(0.2)                     # wait until registered and connected
        await asyncio.sleep(0.5)
        print("\n  type:  event collision_ahead  |  event pothole 0  |  CAV_02 hello there  |  quit\n",
              flush=True)
        loop = asyncio.get_running_loop()
        while True:
            raw = await loop.run_in_executor(None, sys.stdin.readline)
            if raw == "":                                # stdin closed: stop reading, keep running
                return
            line = raw.strip()
            if not line:
                continue
            if line.lower() in ("quit", "exit", "q"):
                os._exit(0)
            first, _, rest = line.partition(" ")
            self.ev += 1
            if first.lower() == "event":
                parts = rest.split()
                kind = parts[0] if parts else "collision_ahead"
                crit = int(parts[1]) if len(parts) > 1 and parts[1] in ("0", "1") else 1
                eid = f"{self.id}-E{self.ev}"
                ok = await self.send(self.rsu, {
                    "type": "event", "event_id": eid, "src": self.id, "kind": kind, "criticality": crit,
                    "ts": time.time(), "pos": [round(self.pos[0], 1), round(self.pos[1], 1)], "data": {}})
                self.log("event-sent", f"reported {'CRITICAL' if crit else 'routine'} event {kind} as {eid}"
                         + ("" if ok else "  (FAILED: no session)"))
            else:
                mid = f"{self.id}-M{self.ev}"
                ok = await self.send(self.rsu, {"type": "v2v", "msg_id": mid, "src": self.id, "dst": first,
                                                "text": rest, "ts": time.time()})
                self.log("v2v-sent", f"V2V {mid} -> {first}: {rest!r}" + ("" if ok else "  (FAILED: no session)"))


def run_backend(cfg: dict, eff: Path) -> None:
    """The 4 consensus nodes and the cloud: one real process each, output shared in this terminal."""
    ents = all_entities(cfg)
    ids = [i for i, e in ents.items() if e["role"] == "NODE"] + [cfg["cloud"]["id"]]
    env = {**os.environ, "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "PYTHONUNBUFFERED": "1", "QRCAV_TRACE": os.environ.get("QRCAV_TRACE", "1")}
    procs = []
    for ident in ids:
        mod = "cloud" if ents[ident]["role"] == "CLOUD" else "consensus_node"
        p = subprocess.Popen([sys.executable, "-m", f"qrcav.nodes.{mod}", "--config", str(eff), "--id", ident],
                             cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procs.append(p)
        threading.Thread(target=lambda p=p: [sys.stdout.write(l) for l in iter(p.stdout.readline, "")],
                         daemon=True).start()
        print(f"== {ident}: process {p.pid}", flush=True)
    try:
        while any(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()


def prepare(cfg_path: Path) -> Path:
    """Wipe the run directory and write the effective config (done by the TA terminal)."""
    cfg = load_config(cfg_path)
    run_dir = ROOT / cfg["run_dir"]
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    cfg["run_dir"] = str(run_dir)
    eff = run_dir / "effective_config.json"
    eff.write_text(json.dumps(cfg, indent=2))
    return eff


async def revoke(cfg: dict, ident: str) -> None:
    token = (Path(cfg["run_dir"]) / "admin.token").read_text()
    resp = await plain_request(cfg["host"], cfg["ta"]["port"], {"op": "revoke", "id": ident, "token": token})
    print(f"TA replied: {resp}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("who", help="TA, NODES, MEC, RSU_01, CAV_01, CAV_02, or 'revoke'")
    ap.add_argument("target", nargs="?", help="for revoke: the vehicle id")
    ap.add_argument("--config", default=str(ROOT / "config" / "terminals.json"))
    ap.add_argument("--beacon-every", type=float, default=None, metavar="SECONDS",
                    help="vehicles: seconds between beacons (default 2); 0 = no beacons")
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")

    eff = Path(load_config(args.config)["run_dir"])
    eff = (eff if eff.is_absolute() else ROOT / eff) / "effective_config.json"
    who = args.who.upper()

    if who == "TA":
        eff = prepare(Path(args.config))
    elif not eff.exists():
        raise SystemExit("start the TA first:  python scripts/terminal_node.py TA")
    cfg = load_config(eff)
    if args.beacon_every is not None:
        cfg["beacon_hz"] = 0 if args.beacon_every <= 0 else 1.0 / args.beacon_every

    if who == "REVOKE":
        if not args.target:
            raise SystemExit("usage: python scripts/terminal_node.py revoke CAV_02")
        asyncio.run(revoke(cfg, args.target.upper()))
        return

    if who in ("NODES", "BACKEND"):
        run_backend(cfg, eff)
        return

    ents = all_entities(cfg)
    if who == "MEC":
        who = cfg["mec"][0]["id"]
    if who == "TA":
        node = TANode(cfg, "TA")
    elif who in ents and ents[who]["role"] == "MEC":
        node = MECNode(cfg, who)
    elif who in ents and ents[who]["role"] == "RSU":
        node = RSUNode(cfg, who)
    elif who in ents and ents[who]["role"] == "CAV":
        node = InteractiveCAV(cfg, who)
    else:
        raise SystemExit(f"unknown id {who!r}; choose TA, NODES, "
                         + ", ".join(i for i, e in ents.items() if e["role"] in ("MEC", "RSU", "CAV")))
    print(f"== {who}: process {os.getpid()}, config {eff} ==", flush=True)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
