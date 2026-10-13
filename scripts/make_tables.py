"""
Generate LaTeX tables and number macros for the report and the slides from
results/*.csv, so every number in the documents comes from the measurements.

    python scripts/make_tables.py        # writes report/generated/*.tex

In LaTeX: \\input{generated/numbers} once, then \\V{deck-hs-bytes} anywhere,
and \\input{generated/tab-sizes} for a table.
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
OUT = ROOT / "report" / "generated"

SUITES = ["CLASSIC", "L1", "L3", "DECK", "L5"]
SUITE_TEX = {"CLASSIC": "Classical", "L1": "L1", "L3": "L3", "DECK": "DECK", "L5": "L5",
             "DECK+cache": "DECK + cache"}


def rd(name: str) -> list[dict]:
    p = RES / name
    if not p.exists():
        return []
    with p.open() as f:
        return list(csv.DictReader(f))


def num(x, d=0) -> str:
    """LaTeX-safe number with thousands separators."""
    if x is None or x == "" or (isinstance(x, float) and x != x):
        return "--"
    from decimal import ROUND_HALF_UP, Decimal
    q = Decimal(str(x)).quantize(Decimal(1).scaleb(-d), rounding=ROUND_HALF_UP)  # 24.5 -> 25, not 24
    s = f"{q:,.{d}f}"
    return s.replace(",", "{,}")


def ms(x) -> str:
    """Milliseconds with sensible precision."""
    x = float(x)
    if x < 0.1:
        return num(x, 3)
    if x < 10:
        return num(x, 2)
    if x < 100:
        return num(x, 1)
    return num(x, 0)


V: dict[str, str] = {}


def table(name: str, cols: str, head: list[str], rows: list[list[str]], note: str = "") -> None:
    lines = [r"\begin{adjustbox}{max width=\linewidth}", r"\begin{tabular}{" + cols + "}", r"\toprule",
             " & ".join(head) + r" \\", r"\midrule"]
    for r in rows:
        if r == ["--mid--"]:
            lines.append(r"\midrule")
            continue
        lines.append(" & ".join(r) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{adjustbox}"]
    if note:
        lines.append(r"\par\smallskip{\footnotesize " + note + "}")
    (OUT / f"tab-{name}.tex").write_text("\n".join(lines) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # ---- sizes ---------------------------------------------------------------------
    sz = {r["suite"]: r for r in rd("sizes.csv")}
    rows = []
    for s in SUITES:
        r = sz[s]
        rows.append([SUITE_TEX[s], r["kem"], r["sig_alg"], num(r["kem_pk"]), num(r["sig"]), num(r["cert"]),
                     num(r["handshake_total"]), num(r["frames"]), ms(r["airtime_ms"]),
                     num(r["handshake_total_cached"]), num(r["frames_cached"]), r["cache_saving_pct"] + r"\,\%"])
    table("sizes", "lllrrrrrrrrr",
          ["Suite", "KEM", "Signature", "pk$_\\text{KEM}$", "sig", "cert", "bytes", "frames", "air (ms)",
           "cached", "frames", "saving"], rows)
    for s in SUITES:
        k = s.lower()
        r = sz[s]
        V[f"{k}-hs-bytes"] = num(r["handshake_total"])
        V[f"{k}-hs-kb"] = num(float(r["handshake_total"]) / 1000, 1)
        V[f"{k}-hs-frames"] = num(r["frames"])
        V[f"{k}-hs-air"] = ms(r["airtime_ms"])
        V[f"{k}-cert"] = num(r["cert"])
        V[f"{k}-sig"] = num(r["sig"])
        V[f"{k}-cached-bytes"] = num(r["handshake_total_cached"])
        V[f"{k}-cached-kb"] = num(float(r["handshake_total_cached"]) / 1000, 1)
        V[f"{k}-cached-frames"] = num(r["frames_cached"])
        V[f"{k}-cache-saving"] = num(r["cache_saving_pct"], 0)
        V[f"{k}-ch"] = num(r["client_hello"])
        V[f"{k}-sh"] = num(r["server_hello"])
        V[f"{k}-ck"] = num(r["client_key"])
        V[f"{k}-fs"] = num(r["server_finished"])
        V[f"{k}-ch-cached"] = num(r["client_hello_cached"])
        V[f"{k}-sh-cached"] = num(r["server_hello_cached"])
    V["pq-cache-lo"] = num(min(float(sz[x]["cache_saving_pct"]) for x in SUITES[1:]), 0)
    V["pq-cache-hi"] = num(max(float(sz[x]["cache_saving_pct"]) for x in SUITES[1:]), 0)
    V["pq-size-ratio-lo"] = num(min(float(sz[s]["handshake_total"]) for s in SUITES[1:]) /
                                float(sz["CLASSIC"]["handshake_total"]), 0)
    V["pq-size-ratio-hi"] = num(max(float(sz[s]["handshake_total"]) for s in SUITES[1:]) /
                                float(sz["CLASSIC"]["handshake_total"]), 0)

    # ---- primitives -----------------------------------------------------------------
    prim = rd("primitives.csv")

    def p(suite, op, key="mean_ms"):
        for r in prim:
            if r["suite"] == suite and r["operation"].endswith(op):
                return float(r[key])
        return None

    rows = []
    for s in SUITES:
        kg = next(float(r["mean_ms"]) for r in prim if r["suite"] == s
                  and ("KEM" in r["operation"] or "ECDH" in r["operation"]) and r["operation"].endswith("keygen"))
        rows.append([SUITE_TEX[s] + (" (KEM in kyber-py)" if s == "L1" else ""), ms(kg), ms(p(s, "encaps")),
                     ms(p(s, "decaps")), ms(p(s, "sign")), ms(p(s, "sign", "p99_ms")), ms(p(s, "verify"))])
    table("primitives", "lrrrrrr", ["Suite", "KEM keygen", "encaps", "decaps", "sign", "sign p99", "verify"], rows,
          "Mean of 200 runs after warm-up, in ms. All operations use OpenSSL through the \\texttt{cryptography} "
          "library, except L1's ML-KEM-512, which that library does not expose; it comes from \\texttt{kyber-py} "
          "(pure Python).")
    V["deck-sign-native"] = ms(p("DECK", "ML-DSA-65 sign"))
    V["deck-sign-native-p99"] = ms(p("DECK", "ML-DSA-65 sign", "p99_ms"))
    V["deck-verify-native"] = ms(p("DECK", "ML-DSA-65 verify"))
    V["deck-encaps-native"] = ms(p("DECK", "ML-KEM-1024 encaps"))
    V["deck-decaps-native"] = ms(p("DECK", "ML-KEM-1024 decaps"))
    V["l1-encaps"] = ms(p("L1", "ML-KEM-512 encaps"))
    V["l1-decaps"] = ms(p("L1", "ML-KEM-512 decaps"))
    V["classic-sign"] = ms(p("CLASSIC", "ECDSA-P256 sign"))

    # ---- handshake timing -------------------------------------------------------------
    ht = rd("handshake_timing.csv")
    rows = []
    for s in SUITES:
        r = next(r for r in ht if r["suite"] == s)
        rows.append([SUITE_TEX[s], ms(r["mean_ms"]), ms(r["p95_ms"])])
        V[f"{s.lower()}-hs-ms"] = ms(r["mean_ms"])
    table("hstime", "lrr", ["Suite", "mean", "p95"], rows,
          "Compute time of one complete mutual handshake, both sides together, in ms (no network).")

    # ---- beacon budget ------------------------------------------------------------------
    bb = rd("beacon_budget.csv")
    rows = []
    for s in SUITES:
        a = next(r for r in bb if r["suite"] == s and r["mode"].startswith("AEAD"))
        sn = next(r for r in bb if r["suite"] == s and r["mode"].startswith("signed"))
        rows.append([SUITE_TEX[s], f"{ms(a['total_p99_ms'])} ({num(a['bytes'])} B)",
                     f"{ms(sn['total_p99_ms'])} ({num(sn['bytes'])} B, {sn['frames']} fr.)"])
        V[f"{s.lower()}-beacon-aead"] = ms(a["total_p99_ms"])
        V[f"{s.lower()}-beacon-aead-bytes"] = num(a["bytes"])
        V[f"{s.lower()}-beacon-signed"] = ms(sn["total_p99_ms"])
        V[f"{s.lower()}-beacon-signed-bytes"] = num(sn["bytes"])
        V[f"{s.lower()}-beacon-signed-frames"] = sn["frames"]
    table("beacon", "lrr", ["Suite", "AEAD in a session", "signed broadcast"], rows,
          "p99 of cryptographic processing plus 802.11p airtime per beacon, in ms, against the 100 ms beacon interval.")

    # ---- ns-3 ---------------------------------------------------------------------------
    dens = rd("ns3_density.csv") + rd("ns3_density_seeds.csv")
    groups: dict = {}
    for r in dens:
        key = r["suite"] + ("+cache" if float(r.get("cert_cache") or 0) > 0 else "")
        groups.setdefault((key, int(float(r["vehicles"]))), []).append(r)
    veh = sorted({v for _, v in groups})
    order = SUITES + ["DECK+cache"]
    seeds = max((len(g) for g in groups.values()), default=1)
    V["ns3-seeds"] = str(seeds)

    def agg(key, metric, d=0):
        g = groups.get(key)
        if not g:
            return None
        return statistics.fmean(float(x[metric]) for x in g)

    for metric, name, d, note in [
        ("handshake_success_pct", "ns3-success", 0, "Handshakes completed, \\%"),
        ("hs_p50_ms", "ns3-p50", 0, "Median handshake completion time, ms"),
        ("hs_p95_ms", "ns3-p95", 0, "95th-percentile handshake completion time, ms"),
        ("airtime_pct", "ns3-airtime", 0, "Aggregate airtime, \\% of one channel summed over cells"),
        ("beacon_coverage_pct", "ns3-coverage", 1, "Beacon slots with a live session, \\%"),
        ("alert_p50_ms", "ns3-alert", 1, "Critical event to alert at the reporting vehicle, median ms"),
    ]:
        rows = []
        for v in veh:
            rows.append([f"{v} ({v / 2.25:.0f})"] + [num(agg((s, v), metric), d) for s in order])
            for s in order:
                val = agg((s, v), metric)
                if val is not None:
                    V[f"{name}-{s.lower().replace('+', '-')}-{v}"] = num(val, d)
        present = [s for s in order if any((s, v) in groups for v in veh)]
        idx = [0] + [1 + order.index(s) for s in present]
        rows = [[r[i] for i in idx] for r in rows]
        table(name, "l" + "r" * len(present), ["Vehicles (/km$^2$)"] + [SUITE_TEX[s] for s in present], rows,
              f"{note}. Mean of {seeds} seeds; 1.5\\,km $\\times$ 1.5\\,km Manhattan grid, 9 RSUs, IEEE 802.11p at 6\\,Mb/s.")

    # other measures at 100 vehicles
    mid = 100 if 100 in veh else veh[len(veh) // 2]
    V["ns3-mid"] = str(mid)
    rows = []
    for metric, label, d in [("beacon_coverage_pct", "Beacon slots with a session (\\%)", 1),
                             ("airtime_pct", "Aggregate airtime (\\% of one channel)", 0),
                             ("hs_p95_ms", "Handshake time, p95 (ms)", 0),
                             ("alert_p50_ms", "Event $\\rightarrow$ alert at the reporter, median (ms)", 1),
                             ("commit_p50_ms", "Ledger commit after the event, median (ms)", 1),
                             ("links_lost", "Sessions lost (link timeout)", 1)]:
        rows.append([label] + [num(agg((s, mid), metric), d) for s in ("CLASSIC", "DECK", "DECK+cache")])
        for s in ("CLASSIC", "DECK", "DECK+cache"):
            val = agg((s, mid), metric)
            if val is not None:
                V[f"ns3-{metric.replace('_', '')}-{s.lower().replace('+', '-')}-{mid}"] = num(val, d)
    table("ns3-mid", "lrrr", ["Measure", "Classical", "DECK", "DECK + cache"], rows,
          f"{mid} vehicles, mean of {seeds} seeds.")

    # variants
    var = rd("ns3_variants.csv")

    def vpick(**kw):
        for r in var:
            if all(str(r.get(k)) == str(v) for k, v in kw.items()):
                return r
        return None

    cases = [
        ("DECK, EDCA + backoff (baseline)", vpick(suite="DECK", signed_beacons="False", edca="True",
                                                  backoff="True", cert_cache="0")),
        ("DECK, neither", vpick(suite="DECK", signed_beacons="False", edca="False", backoff="False")),
        ("DECK, EDCA only", vpick(suite="DECK", signed_beacons="False", edca="True", backoff="False")),
        ("DECK, backoff only", vpick(suite="DECK", signed_beacons="False", edca="False", backoff="True")),
        ("--mid--", None),
        ("DECK + cache (directory)", vpick(suite="DECK", signed_beacons="False", edca="True",
                                           backoff="True", cert_cache="1")),
        ("DECK + cache (all warm)", vpick(suite="DECK", cert_cache="2")),
        ("L3 + cache (directory)", vpick(suite="L3", cert_cache="1")),
        ("--mid--", None),
        ("DECK, signed beacons", vpick(suite="DECK", signed_beacons="True")),
        ("Classical, signed beacons", vpick(suite="CLASSIC", signed_beacons="True")),
    ]
    rows = []
    for label, r in cases:
        if label == "--mid--":
            rows.append(["--mid--"])
            continue
        if r is None:
            continue
        rows.append([label, num(r["handshake_success_pct"], 0), num(r["hs_p50_ms"], 0), num(r["beacon_coverage_pct"], 1),
                     num(r["alert_p50_ms"], 1), num(r["airtime_pct"], 0)])
        slug = label.lower().replace(",", "").replace("(", "").replace(")", "").replace("+", "").replace(" ", "-")
        slug = "-".join(x for x in slug.split("-") if x)
        V[f"var-{slug}-success"] = num(r["handshake_success_pct"], 0)
        V[f"var-{slug}-coverage"] = num(r["beacon_coverage_pct"], 0)
        V[f"var-{slug}-alert"] = num(r["alert_p50_ms"], 1)
        V[f"var-{slug}-p50"] = num(r["hs_p50_ms"], 0)
    table("variants", "lrrrrr", ["Scenario (seed 1)", "completed \\%", "p50 ms", "coverage \\%", "alert ms",
                                 "airtime \\%"], rows,
          f"Single-seed variants at {mid} vehicles. Coverage: beacon slots with a live session. "
          "Alert: event $\\rightarrow$ alert at the reporter, median. Airtime: summed over all cells.")

    # ---- consensus -------------------------------------------------------------------------
    cs = rd("consensus_scaling.csv")

    def red(a, b, k):
        """reduction of AGS relative to PBFT, % (computed from the raw columns, not the CSV's rounded %)"""
        return 100 * (1 - float(a[k]) / float(b[k]))

    rows, msg, byt, nsb, lat, cpu = [], [], [], [], [], []
    for n in sorted({int(r["nodes"]) for r in cs}):
        a = next(r for r in cs if int(r["nodes"]) == n and r["mode"] == "ags")
        ns_ = next(r for r in cs if int(r["nodes"]) == n and r["mode"] == "ags-noshadow")
        pb = next(r for r in cs if int(r["nodes"]) == n and r["mode"] == "pbft")
        m, b, sb = red(a, pb, "msgs_per_req"), red(a, pb, "kbytes_per_req"), red(ns_, pb, "kbytes_per_req")
        l, c = -red(a, pb, "latency_p50_ms"), red(a, pb, "cpu_s")
        msg.append(m); byt.append(b); nsb.append(sb); lat.append(l); cpu.append(c)
        rows.append([str(n), a["consensus_set"], f"{num(a['msgs_per_req'])} / {num(pb['msgs_per_req'])}",
                     num(m, 0), num(b, 0), num(sb, 0), ("+" if l >= 0 else "") + num(l, 0), num(c, 0)])
    table("consensus", "rrrrrrrr", ["Nodes", "$|CN|$", "msgs/req AGS / PBFT", "fewer msgs \\%", "fewer bytes \\%",
                                    "no shadow \\%", "latency \\%", "less CPU \\%"], rows,
          "Real ML-DSA-65 signatures, 1\\,ms links, 20 requests at light load. Percentages are AGS-PBFT relative "
          "to PBFT; latency is the median commit latency.")
    V["cons-msg-lo"], V["cons-msg-hi"] = num(min(msg), 0), num(max(msg), 0)
    V["cons-msg-8"] = num(msg[0], 0)
    V["cons-msg-rest-lo"] = num(min(msg[1:]), 0)
    V["cons-byte-lo"], V["cons-byte-hi"] = num(min(byt), 0), num(max(byt), 0)
    V["cons-noshadow-byte-lo"], V["cons-noshadow-byte-hi"] = num(min(nsb), 0), num(max(nsb), 0)
    V["cons-lat-lo"], V["cons-lat-hi"] = num(min(lat), 0), num(max(lat), 0)
    V["cons-cpu-lo"], V["cons-cpu-hi"] = num(min(cpu), 0), num(max(cpu), 0)
    tp = {r["mode"]: r for r in rd("consensus_throughput.csv")}
    V["tps-ags"] = num(tp["ags"]["tps"], 0)
    V["tps-pbft"] = num(tp["pbft"]["tps"], 0)
    V["burst-cpu-ags"] = num(tp["ags"]["cpu_s_total"], 1)
    V["burst-cpu-pbft"] = num(tp["pbft"]["cpu_s_total"], 1)
    V["burst-cpu-more"] = num(100 * (float(tp["ags"]["cpu_s_total"]) / float(tp["pbft"]["cpu_s_total"]) - 1), 0)

    ft = rd("fault_tolerance.csv")
    table("fault", "l" + "r" * len(ft), ["Byzantine nodes"] + [r["byzantine"] for r in ft],
          [["Requests committed (\\%)"] + [num(r["commit_pct"], 0) for r in ft],
           ["Safety held"] + ["yes" if r["safety"] == "True" else "no" for r in ft]],
          f"Consensus set {ft[0]['consensus_set']}, f = {ft[0]['f']}, colluding wrong results, regrouping off.")
    vc = rd("view_change.csv")
    rows = []
    for t in sorted({r["vc_timeout_s"] for r in vc}, key=float):
        a = next(r for r in vc if r["vc_timeout_s"] == t and r["mode"] == "ags")
        b_ = next(r for r in vc if r["vc_timeout_s"] == t and r["mode"] == "pbft")
        rows.append([t + " s", num(float(a["recovery_first_commit_ms"]) / 1000, 2) + " s",
                     num(float(b_["recovery_first_commit_ms"]) / 1000, 2) + " s"])
    table("viewchange", "lrr", ["View-change timeout", "AGS-PBFT", "PBFT"], rows,
          "Time from the leader's crash to the first commit in the new view (8 nodes).")

    # ---- attacks ------------------------------------------------------------------------------
    at = rd("attacks.csv")
    rows = [[r["attack"].replace("%", "\\%").replace("_", "\\_"), "yes" if r["rejected"] == "True" else "\\textbf{NO}",
             r["mechanism"].replace("%", "\\%").replace("_", "\\_").replace("^", "\\^{}").replace("&", "\\&")]
            for r in at]
    table("attacks", "p{5.4cm}cp{7.2cm}", ["Attack", "Rejected", "Mechanism"], rows)
    V["attacks-total"] = str(len(at))
    V["attacks-rejected"] = str(sum(r["rejected"] == "True" for r in at))

    # ---- distributed run -------------------------------------------------------------------------
    sp = ROOT / "run" / "summary.json"
    if sp.exists():
        d = json.loads(sp.read_text())

        def med(xs):
            return statistics.median(xs) if xs else float("nan")
        V["net-handshakes"] = str(d.get("handshakes"))
        V["net-rejected"] = str(d.get("handshake_rejected"))
        V["net-alert-ms"] = num(med(d.get("alert_latency_ms", [])), 1)
        V["net-commit-ms"] = num(med(d.get("commit_latency_ms", [])), 0)
        V["net-ledger-ms"] = num(med(d.get("recorded_to_vehicle_ms", [])), 0)
        V["net-v2v-ms"] = num(med(d.get("v2v_ms", [])), 1)
        V["net-beacons"] = num(d.get("beacons_received"))
        hb = d.get("handshake_bytes", [])
        V["net-hs-min"] = num(min(hb)) if hb else "--"
        V["net-hs-max"] = num(max(hb)) if hb else "--"

    lines = [r"% generated by scripts/make_tables.py from results/*.csv -- do not edit",
             r"\makeatletter", r"\newcommand\V[1]{\@ifundefined{qv@#1}{\textbf{??#1??}}{\csname qv@#1\endcsname}}"]
    for k, v in sorted(V.items()):
        lines.append(r"\expandafter\def\csname qv@" + k + r"\endcsname{" + str(v) + "}")
    lines.append(r"\makeatother")
    (OUT / "numbers.tex").write_text("\n".join(lines) + "\n")
    (OUT / "numbers.json").write_text(json.dumps(V, indent=1))
    print(f"wrote {len(V)} numbers and {len(list(OUT.glob('tab-*.tex')))} tables to {OUT}")


if __name__ == "__main__":
    sys.exit(main())
