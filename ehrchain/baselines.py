"""Baselines for comparison: proof-of-work chain and a plain centralized database."""
import hashlib
import os
import sqlite3
import tempfile
import time

from .contract import State
from .ledger import build_block, tx_sig_ok


def _leading_zero_bits(d: bytes) -> int:
    v = int.from_bytes(d, "big")
    return 256 - v.bit_length()


def mine(header_hash_hex: str, bits: int):
    base = bytes.fromhex(header_hash_hex)
    nonce = 0
    while True:
        if _leading_zero_bits(hashlib.sha256(base + nonce.to_bytes(8, "big")).digest()) >= bits:
            return nonce
        nonce += 1


def run_pow(admin_pub, txs, bits=16, batch_size=200, hop_ms=5.0):
    """Single-miner PoW chain. Each block: execute contract, mine, then one validator
    (all validators work in parallel) re-verifies signatures + replays the contract."""
    st = State(admin_pub)
    ref = State(admin_pub)
    prev, idx, cum, lat, mine_total, hashes = "0" * 64, 1, 0.0, [], 0.0, 0
    n_blocks = 0
    for i in range(0, len(txs), batch_size):
        batch = txs[i:i + batch_size]
        t0 = time.perf_counter()
        st.begin()
        res = [st.execute(t, 1_700_000_000.0) for t in batch]
        st.commit()
        blk = build_block(idx, prev, 1_700_000_000.0, batch, res, "miner", 0)
        t1 = time.perf_counter()
        nonce = mine(blk["hash"], bits)
        t2 = time.perf_counter()
        ok = all(tx_sig_ok(t) for t in batch)          # a validating node's work
        ref.begin(); [ref.execute(t, 1_700_000_000.0) for t in batch]; ref.commit()
        t3 = time.perf_counter()
        block_ms = ((t1 - t0) + (t2 - t1) + (t3 - t2)) * 1000 + hop_ms
        cum += block_ms
        lat += [cum] * len(batch)
        mine_total += (t2 - t1) * 1000
        hashes += nonce + 1
        prev, idx, n_blocks = blk["hash"], idx + 1, n_blocks + 1
    n = len(txs)
    return {"blocks": n_blocks, "txs": n, "model_ms_total": cum, "throughput_tps": n / (cum / 1000) if cum else 0,
            "avg_tx_latency_ms": sum(lat) / len(lat) if lat else 0, "avg_block_confirm_ms": cum / max(n_blocks, 1),
            "mine_ms_total": mine_total, "hashes": hashes}


def run_central(admin_pub, txs, batch_size=200):
    """Centralized DB: one server, no signatures, no replication, no consensus."""
    tmp = tempfile.mkdtemp(prefix="central_")
    con = sqlite3.connect(os.path.join(tmp, "db.sqlite"))
    con.execute("create table log(tx_id text primary key, sender text, type text, result text, payload text)")
    st = State(admin_pub)
    cum, lat = 0.0, []
    import json
    for i in range(0, len(txs), batch_size):
        batch = txs[i:i + batch_size]
        t0 = time.perf_counter()
        rows = []
        for t in batch:
            r = st.execute(t, 1_700_000_000.0)
            rows.append((t["tx_id"], t["sender"], t["type"], r, json.dumps(t["payload"])))
        con.executemany("insert into log values (?,?,?,?,?)", rows)
        con.commit()
        cum += (time.perf_counter() - t0) * 1000
        lat += [cum] * len(batch)
    con.close()
    n = len(txs)
    return {"txs": n, "model_ms_total": cum, "throughput_tps": n / (cum / 1000) if cum else 0,
            "avg_tx_latency_ms": sum(lat) / len(lat) if lat else 0,
            "avg_block_confirm_ms": cum / max(1, -(-n // batch_size))}
