"""
Run the real system's entities one per terminal, and watch every message.

Each command starts ONE real process (the same TA / RSU / vehicle code that
run_network.py starts), with message tracing on, so a server terminal and a
client terminal show the same records leaving one side and arriving at the
other. Start them in this order, each in its own terminal:

    python scripts/terminal_node.py TA        # terminal 1: Trusted Authority (wipes run_terminals/ first)
    python scripts/terminal_node.py RSU_01    # terminal 2: the server
    python scripts/terminal_node.py CAV_01    # terminal 3: a client
    python scripts/terminal_node.py CAV_02    # terminal 4: a second client (optional)

In a vehicle's terminal, type:
    CAV_02 hello there     send a V2V message to CAV_02 (via the RSU)
    quit                   stop this vehicle

Revoke a vehicle from a fifth terminal (the RSU then drops it and refuses it):
    python scripts/terminal_node.py revoke CAV_02

Uses config/terminals.json (ports 76xx). Stop any process with Ctrl+C.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("QRCAV_TRACE", "1")          # print every record sent and received

from qrcav.net.secure import plain_request  # noqa: E402
from qrcav.nodes.base import all_entities, load_config  # noqa: E402
from qrcav.nodes.cav import CAVNode  # noqa: E402
from qrcav.nodes.rsu import RSUNode  # noqa: E402
from qrcav.nodes.ta import TANode  # noqa: E402


class InteractiveCAV(CAVNode):
    """The normal vehicle, plus: lines typed in the terminal are sent as V2V messages."""

    async def run(self) -> None:
        asyncio.ensure_future(self._keyboard())
        await super().run()

    async def _keyboard(self) -> None:
        while getattr(self, "rsu", None) not in self.channels:
            await asyncio.sleep(0.2)                     # wait until registered and connected
        await asyncio.sleep(0.5)
        print("\n  type:  CAV_02 hello there   (send a V2V message)   or   quit\n", flush=True)
        loop = asyncio.get_running_loop()
        n = 0
        while True:
            raw = await loop.run_in_executor(None, sys.stdin.readline)
            if raw == "":                                # stdin closed: stop reading, keep running
                return
            line = raw.strip()
            if not line:
                continue
            if line.lower() in ("quit", "exit", "q"):
                os._exit(0)
            dst, _, text = line.partition(" ")
            n += 1
            mid = f"{self.id}-T{n}"
            ok = await self.send(self.rsu, {"type": "v2v", "msg_id": mid, "src": self.id, "dst": dst,
                                            "text": text, "ts": time.time()})
            self.log("v2v-sent", f"V2V {mid} -> {dst}: {text!r}" + ("" if ok else "  (FAILED: no session)"))


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
    ap.add_argument("who", help="TA, RSU_01, CAV_01, CAV_02, or 'revoke'")
    ap.add_argument("target", nargs="?", help="for revoke: the vehicle id")
    ap.add_argument("--config", default=str(ROOT / "config" / "terminals.json"))
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

    if who == "REVOKE":
        if not args.target:
            raise SystemExit("usage: python scripts/terminal_node.py revoke CAV_02")
        asyncio.run(revoke(cfg, args.target.upper()))
        return

    ents = all_entities(cfg)
    if who == "TA":
        node = TANode(cfg, "TA")
    elif who in ents and ents[who]["role"] == "RSU":
        node = RSUNode(cfg, who)
    elif who in ents and ents[who]["role"] == "CAV":
        node = InteractiveCAV(cfg, who)
    else:
        raise SystemExit(f"unknown id {who!r}; choose TA, "
                         + ", ".join(i for i, e in ents.items() if e["role"] in ("RSU", "CAV")))
    print(f"== {who}: process {os.getpid()}, config {eff} ==", flush=True)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
