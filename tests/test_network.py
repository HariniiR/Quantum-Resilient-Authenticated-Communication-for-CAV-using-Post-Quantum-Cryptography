"""
End-to-end: launch real processes over TCP and check the run.
Takes about 30 seconds. Skip with:  pytest -m "not slow"
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.slow
def test_distributed_system(tmp_path):
    cfg = json.loads((ROOT / "config" / "demo.json").read_text())
    cfg["run_dir"] = str(tmp_path / "run")
    base = 17000 + (hash(str(tmp_path)) % 500) * 20     # avoid port clashes with a running demo
    cfg["ta"]["port"] = base
    cfg["ta"]["revoke"] = [{"at": 14, "id": "CAV_05"}]
    cfg["cloud"]["port"] = base + 1
    cfg["mec"][0]["port"] = base + 2
    for i, n in enumerate(cfg["consensus"]["nodes"]):
        n["port"] = base + 3 + i
        n.pop("crash_at", None)
    for i, r in enumerate(cfg["rsus"]):
        r["port"] = base + 12 + i
    cfg["cavs"] = [
        {"id": "CAV_01", "rsu": "RSU_01", "script": [
            {"at": 5, "action": "event", "kind": "collision_ahead", "criticality": 1},
            {"at": 6, "action": "event", "kind": "pothole", "criticality": 0},
            {"at": 7, "action": "v2v", "dst": "CAV_05", "text": "hello"}]},
        {"at": 0, "id": "CAV_05", "rsu": "RSU_03", "script": [
            {"at": 8, "action": "event", "kind": "traffic_jam", "criticality": 1, "repeat": 3, "every": 1.0},
            {"at": 17, "action": "reconnect"}]},
    ]
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg))
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "run_network.py"), "--config", str(p),
                          "--duration", "22", "--quiet"], capture_output=True, text=True, timeout=120)
    summary = json.loads((tmp_path / "run" / "summary.json").read_text())
    assert summary["ledgers_consistent"] and summary["ledger_verifies"], out.stdout[-2000:]
    assert min(summary["ledger_heights"].values()) >= 4          # 1 + 3 critical events
    assert summary["alerts_delivered"] >= 4
    assert summary["cloud_records"] == 1
    assert summary["v2v_ms"], "V2V message not delivered across RSUs"
    assert summary["revoked"] == ["CAV_05"]
    assert summary["handshake_rejected"] >= 1                   # revoked vehicle locked out
