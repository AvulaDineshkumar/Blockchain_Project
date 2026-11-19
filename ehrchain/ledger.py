"""Transactions, Merkle tree, blocks, quorum certificates and the per-node ledger."""
import hashlib
import json

from .contract import State
from .crypto import canon, sha256_hex, verify

SKEW = 5.0  # seconds a block timestamp may be ahead of a validator's clock


# ------------------------------------------------------------------ Merkle tree ---------
def merkle_root(leaf_hexes):
    if not leaf_hexes:
        return sha256_hex(b"")
    level = [bytes.fromhex(x) for x in leaf_hexes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(leaf_hexes, index):
    """Return [(sibling_hex, sibling_is_right), ...] proving leaf `index` is in the root."""
    level = [bytes.fromhex(x) for x in leaf_hexes]
    proof, idx = [], index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = idx ^ 1
        proof.append((level[sib].hex(), sib > idx))
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_proof(leaf_hex, proof, root_hex):
    cur = bytes.fromhex(leaf_hex)
    for sib_hex, sib_is_right in proof:
        sib = bytes.fromhex(sib_hex)
        cur = hashlib.sha256(cur + sib).digest() if sib_is_right else hashlib.sha256(sib + cur).digest()
    return cur.hex() == root_hex


# ------------------------------------------------------------------ transactions --------
def tx_body(tx):
    return {k: tx[k] for k in ("type", "sender", "sender_pub", "payload", "ts", "nonce")}


def make_tx(key, sender, ttype, payload, ts, nonce):
    body = {"type": ttype, "sender": sender, "sender_pub": key.public_hex,
            "payload": payload, "ts": ts, "nonce": nonce}
    data = canon(body)
    return {**body, "tx_id": sha256_hex(data), "sig": key.sign(data)}


def tx_sig_ok(tx) -> bool:
    try:
        data = canon(tx_body(tx))
        return sha256_hex(data) == tx["tx_id"] and verify(tx["sender_pub"], data, tx["sig"])
    except (KeyError, TypeError, ValueError):
        return False


# ------------------------------------------------------------------ blocks --------------
def results_hash(results):
    return sha256_hex(canon(results))


def header_hash(header):
    return sha256_hex(canon(header))


def build_block(index, prev_hash, ts, txs, results, proposer, view, config=None):
    header = {"index": index, "prev_hash": prev_hash, "ts": ts,
              "merkle_root": merkle_root([t["tx_id"] for t in txs]),
              "results_hash": results_hash(results), "proposer": proposer,
              "view": view, "tx_count": len(txs)}
    if config is not None:
        header["config"] = config
    return {"header": header, "hash": header_hash(header), "txs": txs,
            "results": results, "cert": [], "proposer_sig": None}


def make_genesis(admin_pub, validators, ts):
    n = len(validators)
    f = (n - 1) // 3
    cfg = {"admin_pub": admin_pub, "validators": validators, "n": n, "f": f, "quorum": 2 * f + 1}
    return build_block(0, "0" * 64, ts, [], [], "genesis", 0, config=cfg)


def vote_body(phase, height, view, bhash, node):
    return {"phase": phase, "height": height, "view": view, "hash": bhash, "node": node}


def check_cert(block, cfg) -> bool:
    """A block is final only if >= 2f+1 distinct validators signed its COMMIT vote."""
    h = block["header"]
    ok = set()
    for c in block.get("cert", []):
        node = c.get("node")
        if node in ok or node not in cfg["validators"]:
            continue
        msg = canon(vote_body("COMMIT", h["index"], h["view"], block["hash"], node))
        if verify(cfg["validators"][node], msg, c.get("sig", "")):
            ok.add(node)
    return len(ok) >= cfg["quorum"]


def check_block_static(b, index, prev_hash, prev_ts, cfg):
    """Everything that can be checked without executing the contract. Returns a reason or None."""
    h = b["header"]
    if h["index"] != index:
        return "bad_index"
    if h["prev_hash"] != prev_hash:
        return "bad_prev_hash"
    if header_hash(h) != b["hash"]:
        return "bad_block_hash"
    if h["merkle_root"] != merkle_root([t["tx_id"] for t in b["txs"]]):
        return "bad_merkle_root"
    if len(b["results"]) != len(b["txs"]) or h["results_hash"] != results_hash(b["results"]):
        return "bad_results_hash"
    pub = cfg["validators"].get(h["proposer"])
    if pub is None or not verify(pub, b["hash"].encode(), b.get("proposer_sig") or ""):
        return "bad_proposer_sig"
    if h["ts"] < prev_ts:
        return "bad_timestamp"
    for t in b["txs"]:
        if not tx_sig_ok(t):
            return "bad_tx_signature"
    return None


def clone(block):
    return json.loads(json.dumps(block))


# ------------------------------------------------------------------ ledger --------------
class Ledger:
    """One validator's copy of the chain plus the contract state derived from it."""

    def __init__(self, genesis):
        self.blocks = [genesis]
        self.cfg = genesis["header"]["config"]
        self.state = State(self.cfg["admin_pub"])
        self.index = {}  # tx_id -> (block_index, position)

    @property
    def next_index(self):
        return len(self.blocks)

    @property
    def head_hash(self):
        return self.blocks[-1]["hash"]

    @property
    def head_ts(self):
        return self.blocks[-1]["header"]["ts"]

    def lookup(self, tx_id):
        loc = self.index.get(tx_id)
        if loc is None:
            return None
        b = self.blocks[loc[0]]
        return b, b["txs"][loc[1]], b["results"][loc[1]]

    def append_committed(self, block):
        for pos, t in enumerate(block["txs"]):
            self.index[t["tx_id"]] = (len(self.blocks), pos)
        self.blocks.append(block)

    def add_block(self, b):
        """Fully verify a finished block (hashes, signatures, contract replay, quorum
        certificate) and append it. Used for catching up and for auditing a chain."""
        reason = check_block_static(b, self.next_index, self.head_hash, self.head_ts, self.cfg)
        if reason:
            return False, reason
        self.state.begin()
        results = [self.state.execute(t, b["header"]["ts"]) for t in b["txs"]]
        if results != b["results"]:
            self.state.rollback()
            return False, "contract_replay_mismatch"
        if not check_cert(b, self.cfg):
            self.state.rollback()
            return False, "bad_quorum_certificate"
        self.state.commit()
        self.append_committed(b)
        return True, "ok"


def verify_chain(blocks):
    """Audit a chain from genesis. Returns (ok, reason, failing_block_index)."""
    g = blocks[0]
    if header_hash(g["header"]) != g["hash"]:
        return False, "bad_genesis_hash", 0
    led = Ledger(g)
    for b in blocks[1:]:
        ok, reason = led.add_block(b)
        if not ok:
            return False, reason, b["header"]["index"]
    return True, "ok", None
