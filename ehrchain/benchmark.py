"""Benchmarks -> CSV files in results/. Usage: python -m ehrchain.benchmark <suite> [options]
suites: pbft | pow | central | powbits | failures | filesize | storage"""
import argparse
import csv
import os
import sys
import time

from .baselines import run_central, run_pow
from .crypto import decrypt, encrypt, sha256_hex
from .network import BYZ_VOTER, OFFLINE
from .workload import make_workload

RES = os.path.join(os.path.dirname(__file__), "..", "results")
NODES, LOADS = [4, 7, 10, 13], [100, 500, 1000, 2500, 10000]


def append(fname, rows):
    os.makedirs(RES, exist_ok=True)
    path = os.path.join(RES, fname)
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        if new:
            w.writeheader()
        w.writerows(rows)


BUDGET = {"end": None}


def done_keys(fname, cols):
    path = os.path.join(RES, fname)
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return {tuple(str(r[c]) for c in cols) for r in csv.DictReader(f)}


def out_of_time():
    return BUDGET["end"] is not None and time.time() > BUDGET["end"]


def pbft(nodes, loads, repeats, hop_ms, out):
    done = done_keys(out, ("nodes", "load", "rep"))
    for n in nodes:
        for load in loads:
            rows = []
            for rep in range(repeats):
                if (str(n), str(load), str(rep)) in done:
                    continue
                if out_of_time():
                    return
                w, txs = make_workload(load, n, seed=rep, hop_ms=hop_ms)
                for t in txs:
                    w.net.submit(t)
                r = w.net.process_all()
                assert w.net.chain_consistent() and not r["stalled"]
                rows.append({"system": "PBFT", "nodes": n, "load": load, "rep": rep, "hop_ms": hop_ms,
                             **{k: r[k] for k in ("blocks", "model_ms_total", "wall_ms_total", "throughput_tps",
                                                  "avg_tx_latency_ms", "avg_block_confirm_ms", "messages", "bytes")},
                             "consensus_share": 1.0})
                append(out, rows[-1:])
            if rows:
                print("pbft", n, load, len(rows), "new reps", flush=True)


def baseline(kind, loads, repeats, bits, out):
    name = "central" if kind == "central" else f"PoW-{bits}bit"
    done = done_keys(out, ("system", "load", "rep"))
    for load in loads:
        rows = []
        for rep in range(repeats):
            if (name, str(load), str(rep)) in done:
                continue
            if out_of_time():
                return
            w, txs = make_workload(load, 4, seed=rep)
            r = run_pow(w.admin.sk.public_hex, txs, bits=bits) if kind == "PoW" else run_central(w.admin.sk.public_hex, txs)
            rows.append({"system": kind if kind != "PoW" else f"PoW-{bits}bit", "nodes": 1 if kind == "central" else "n/a",
                         "load": load, "rep": rep, **{k: r.get(k, "") for k in
                         ("model_ms_total", "throughput_tps", "avg_tx_latency_ms", "avg_block_confirm_ms")}})
            append(out, rows[-1:])
        print(kind, load, len(rows), "new reps", flush=True)


def powbits(repeats, out):
    for bits in (8, 12, 16, 18, 20, 22):
        rows = []
        for rep in range(repeats):
            w, txs = make_workload(1000, 4, seed=rep)
            r = run_pow(w.admin.sk.public_hex, txs, bits=bits)
            rows.append({"bits": bits, "rep": rep, "blocks": r["blocks"], "hashes": r["hashes"],
                         "mine_ms_total": r["mine_ms_total"], "throughput_tps": r["throughput_tps"],
                         "avg_block_confirm_ms": r["avg_block_confirm_ms"]})
        append(out, rows)
        print("powbits", bits, flush=True)


def failures(repeats, out, load=1000, nodes=NODES):
    done = done_keys(out, ("nodes", "behavior", "faulty", "rep"))
    for n in nodes:
        f = (n - 1) // 3
        for beh in (OFFLINE, BYZ_VOTER):
            for k in range(0, f + 2):
                rows = []
                for rep in range(repeats):
                    if (str(n), beh, str(k), str(rep)) in done:
                        continue
                    if out_of_time():
                        return
                    w, txs = make_workload(load, n, seed=rep)
                    for i in range(k):                       # V0 is primary of the first block: hit it too
                        w.net.set_behavior(f"V{i}", beh)
                    for t in txs:
                        w.net.submit(t)
                    r = w.net.process_all()
                    rows.append({"nodes": n, "f": f, "faulty": k, "behavior": beh, "rep": rep,
                                 "stalled": int(r["stalled"]), "committed_txs": r["txs"],
                                 "view_changes": r["view_changes"], "model_ms_total": r["model_ms_total"],
                                 "throughput_tps": r["throughput_tps"],
                                 "avg_tx_latency_ms": r["avg_tx_latency_ms"],
                                 "consistent": int(w.net.chain_consistent())})
                    append(out, rows[-1:])
                print("fail", n, beh, k, flush=True)


def filesize(repeats, out):
    sizes = [("3KB", 3_000), ("100KB", 100_000), ("1MB", 1 << 20), ("10MB", 10 << 20),
             ("32MB(DICOM)", 32 << 20), ("100MB", 100 << 20)]
    for label, sz in sizes:
        reps = repeats if sz <= (10 << 20) else min(repeats, 5)
        rows = []
        raw = os.urandom(sz)
        for rep in range(reps):
            t0 = time.perf_counter(); h = sha256_hex(raw); t1 = time.perf_counter()
            key, blob = encrypt(raw); t2 = time.perf_counter()
            plain = decrypt(key, blob); t3 = time.perf_counter()
            assert sha256_hex(plain) == h; t4 = time.perf_counter()
            rows.append({"size": label, "bytes": sz, "rep": rep, "hash_ms": (t1 - t0) * 1e3,
                         "encrypt_ms": (t2 - t1) * 1e3, "decrypt_ms": (t3 - t2) * 1e3,
                         "verify_hash_ms": (t4 - t3) * 1e3})
        append(out, rows)
        print("filesize", label, flush=True)


def storage(out):
    """On-chain bytes vs off-chain bytes for the real dataset subset (done in experiments)."""
    raise SystemExit("run experiments.py (storage experiment) instead")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("suite")
    ap.add_argument("--nodes", type=int, nargs="*", default=NODES)
    ap.add_argument("--loads", type=int, nargs="*", default=LOADS)
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--hop", type=float, default=5.0)
    ap.add_argument("--bits", type=int, default=16)
    ap.add_argument("--out", default=None)
    ap.add_argument("--budget", type=float, default=None, help="stop after this many seconds (resume by re-running)")
    a = ap.parse_args()
    if os.environ.get("BENCH_DEADLINE"):
        BUDGET["end"] = float(os.environ["BENCH_DEADLINE"])
    elif a.budget:
        BUDGET["end"] = time.time() + a.budget
    if a.suite == "pbft":
        pbft(a.nodes, a.loads, a.repeats, a.hop, a.out or f"bench_pbft_hop{int(a.hop)}.csv")
    elif a.suite == "pow":
        baseline("PoW", a.loads, a.repeats, a.bits, a.out or "bench_pow.csv")
    elif a.suite == "central":
        baseline("central", a.loads, a.repeats, a.bits, a.out or "bench_central.csv")
    elif a.suite == "powbits":
        powbits(a.repeats, a.out or "bench_powbits.csv")
    elif a.suite == "failures":
        failures(a.repeats, a.out or "bench_failures.csv", nodes=a.nodes)
    elif a.suite == "filesize":
        filesize(a.repeats, a.out or "bench_filesize.csv")
