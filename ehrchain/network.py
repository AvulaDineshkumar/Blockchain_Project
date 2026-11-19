"""Validator nodes and a PBFT-style consensus round (simulated in one process).

Round for block height h and view v (primary = validators[(h+v) % n], quorum = 2f+1, n >= 3f+1):
  1. PRE-PREPARE : primary broadcasts the proposed block
  2. PREPARE     : every validator that re-executed the block and found it valid broadcasts a
                   signed PREPARE vote; a node that sees a quorum for its block moves on
  3. COMMIT      : signed COMMIT votes; a quorum of COMMIT signatures is the block's
                   commit certificate and makes the block final
If no quorum forms (faulty/offline primary, invalid or conflicting proposals, too many faults),
the validators time out and move to view v+1 with the next primary.

What is real and what is modelled: all cryptography, hashing, contract execution and message
counting are real and measured. Network delay is modelled (hop_ms per message phase) because
all nodes run inside one Python process. Per-phase compute time of the slowest node is used
because real nodes would work in parallel.
"""
import random
import time
from collections import Counter, defaultdict

from .crypto import SigningKey, canon, sha256_hex, verify
from .ledger import (SKEW, Ledger, build_block, check_block_static, clone, header_hash,
                     make_genesis, tx_sig_ok, vote_body, results_hash)

HONEST, OFFLINE, BYZ_VOTER, BYZ_PRIMARY, EQUIVOCATOR = (
    "honest", "offline", "byz_voter", "byz_primary", "equivocator")


class Clock:
    def __init__(self, start=1_700_000_000.0):
        self.t = start

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class Node:
    def __init__(self, nid, key, genesis, behavior=HONEST):
        self.id, self.key, self.behavior = nid, key, behavior
        self.ledger = Ledger(genesis)
        self.pending = None
        self.attack = "forge_result"
        self.last_reject = None

    @property
    def online(self):
        return self.behavior != OFFLINE

    def vote(self, phase, height, view, bhash):
        body = vote_body(phase, height, view, bhash, self.id)
        return {**body, "sig": self.key.sign(canon(body))}

    # -- validation of a proposed block (does not commit) --------------------------------
    def validate_block(self, b, expected_primary, view, now):
        L = self.ledger
        h = b["header"]
        reason = check_block_static(b, L.next_index, L.head_hash, L.head_ts, L.cfg)
        if reason is None and (h["proposer"] != expected_primary or h["view"] != view):
            reason = "wrong_primary_or_view"
        if reason is None and h["ts"] > now + SKEW:
            reason = "timestamp_in_future"
        if reason is not None:
            self.last_reject = reason
            return False
        L.state.begin()
        res = [L.state.execute(t, h["ts"]) for t in b["txs"]]
        if res != b["results"]:
            L.state.rollback()
            self.last_reject = "contract_result_mismatch"
            return False
        self.pending = b
        self.last_reject = None
        return True

    def abort_pending(self):
        if self.pending is not None:
            self.ledger.state.rollback()
            self.pending = None

    def commit_pending(self, cert):
        blk = clone(self.pending)
        blk["cert"] = cert
        self.ledger.state.commit()
        self.ledger.append_committed(blk)
        self.pending = None

    # -- block creation ------------------------------------------------------------------
    def make_proposal(self, txs, now, view):
        L = self.ledger
        L.state.begin()
        res = [L.state.execute(t, now) for t in txs]
        L.state.rollback()
        blk = build_block(L.next_index, L.head_hash, now, txs, res, self.id, view)
        blk["proposer_sig"] = self.key.sign(blk["hash"].encode())
        return blk

    def forge(self, blk):
        """Byzantine primary: tamper with the block so it looks consistent but lies."""
        b = clone(blk)
        if self.attack == "bad_signature" and b["txs"]:
            evil = dict(b["txs"][0], sig="00" * 64)
            b["txs"].append(evil)
            b["results"].append("OK")
        else:  # forge_result: grant what the contract denied
            for i, r in enumerate(b["results"]):
                if r.startswith("DENIED"):
                    b["results"][i] = "GRANTED:CONSENT"
                    break
            else:
                if b["results"]:
                    b["results"][0] = "DENIED:FORGED"
        hdr = dict(b["header"])
        from .ledger import merkle_root
        hdr["merkle_root"] = merkle_root([t["tx_id"] for t in b["txs"]])
        hdr["results_hash"] = results_hash(b["results"])
        hdr["tx_count"] = len(b["txs"])
        b["header"], b["hash"] = hdr, header_hash(hdr)
        b["proposer_sig"] = self.key.sign(b["hash"].encode())
        return b


class Network:
    def __init__(self, n, batch_size=200, hop_ms=5.0, view_timeout_ms=200.0, clock=None,
                 admin_pub="", seed=1):
        if n < 4:
            raise ValueError("PBFT needs at least 4 validators (n >= 3f+1 with f >= 1)")
        self.n, self.batch_size = n, batch_size
        self.hop_ms, self.view_timeout_ms = hop_ms, view_timeout_ms
        self.clock = clock or Clock()
        self.rng = random.Random(seed)
        keys = {f"V{i}": SigningKey() for i in range(n)}
        self.order = list(keys)
        self.pubs = {k: v.public_hex for k, v in keys.items()}
        genesis = make_genesis(admin_pub, self.pubs, self.clock.now())
        self.nodes = {k: Node(k, keys[k], genesis) for k in self.order}
        self.cfg = genesis["header"]["config"]
        self.f, self.quorum = self.cfg["f"], self.cfg["quorum"]
        self.mempool = []
        self.mempool_ids = set()
        self.view = 0
        self.rounds = []         # one dict per consensus attempt
        self.security_log = []   # transactions dropped before consensus (bad signature)
        self.sync_log = []

    # ---- client side ------------------------------------------------------------------
    def submit(self, tx):
        if not tx_sig_ok(tx):
            self.security_log.append({"event": "REJECTED_BAD_SIGNATURE", "sender": tx.get("sender"),
                                      "tx_id": tx.get("tx_id")})
            return False
        if tx["tx_id"] in self.mempool_ids:
            return False
        self.mempool.append(tx)
        self.mempool_ids.add(tx["tx_id"])
        return True

    def set_behavior(self, nid, behavior, attack=None):
        self.nodes[nid].behavior = behavior
        if attack:
            self.nodes[nid].attack = attack

    def reference(self):
        live = [m for m in self.nodes.values() if m.online]
        return max(live, key=lambda m: m.ledger.next_index) if live else None

    @property
    def height(self):
        ref = self.reference()
        return ref.ledger.next_index - 1 if ref else 0

    def recover(self, nid):
        """Bring a node back online and let it catch up from its peers."""
        self.nodes[nid].behavior = HONEST
        return self._sync(self.nodes[nid])

    def _sync(self, node):
        peers = [m for m in self.nodes.values() if m.online and m is not node]
        if not peers:
            return 0
        ref = max(peers, key=lambda m: m.ledger.next_index)
        t0, got = time.perf_counter(), 0
        for b in ref.ledger.blocks[node.ledger.next_index:]:
            ok, reason = node.ledger.add_block(clone(b))
            if not ok:
                self.sync_log.append({"node": node.id, "error": reason})
                break
            got += 1
        self.sync_log.append({"node": node.id, "blocks": got, "ms": (time.perf_counter() - t0) * 1000})
        return got

    # ---- one consensus attempt ---------------------------------------------------------
    def _attempt(self, view, txs):
        now = self.clock.now()
        h = max(m.ledger.next_index for m in self.nodes.values() if m.online)
        primary = self.nodes[self.order[(h + view) % self.n]]
        live = [m for m in self.nodes.values() if m.online]
        t = defaultdict(lambda: defaultdict(float))   # phase -> node -> seconds
        msgs = 0
        info = {"height": h, "view": view, "primary": primary.id, "primary_behavior": primary.behavior,
                "n_tx": len(txs), "committed": False, "reasons": []}
        if not primary.online:
            info.update(reasons=["primary_offline"], model_ms=0.0, wall_ms=0.0, messages=0, bytes=0)
            return info
        t0_wall = time.perf_counter()

        s = time.perf_counter()
        blk = primary.make_proposal(txs, now, view)
        t["propose"][primary.id] = time.perf_counter() - s
        proposals = {m.id: blk for m in live}
        if primary.behavior == BYZ_PRIMARY:
            bad = primary.forge(blk)
            proposals = {m.id: bad for m in live}
        elif primary.behavior == EQUIVOCATOR and len(txs) > 1:
            alt = build_block(blk["header"]["index"], blk["header"]["prev_hash"], now,
                              list(reversed(txs)), [], primary.id, view)
            primary.ledger.state.begin()
            alt["results"] = [primary.ledger.state.execute(x, now) for x in alt["txs"]]
            primary.ledger.state.rollback()
            alt = build_block(alt["header"]["index"], alt["header"]["prev_hash"], now,
                              alt["txs"], alt["results"], primary.id, view)
            alt["proposer_sig"] = primary.key.sign(alt["hash"].encode())
            half = len(live) // 2
            for i, m in enumerate(live):
                proposals[m.id] = blk if i < half else alt
        block_bytes = len(canon({"header": blk["header"], "n": len(txs)})) + sum(len(canon(x)) for x in txs)
        msgs += len(live) - 1

        # phase 1: validate
        prepared_hash = {}
        for m in live:
            b = proposals[m.id]
            s = time.perf_counter()
            if m.behavior in (BYZ_VOTER,):
                prepared_hash[m.id] = None
            elif m.behavior in (BYZ_PRIMARY, EQUIVOCATOR) and m is primary:
                ok = m.validate_block(b, primary.id, view, now) if m.behavior == EQUIVOCATOR else False
                prepared_hash[m.id] = b["hash"] if (ok or m.behavior == BYZ_PRIMARY) else None
            else:
                ok = m.validate_block(b, primary.id, view, now)
                prepared_hash[m.id] = b["hash"] if ok else None
                if not ok:
                    info["reasons"].append(f"{m.id}:{m.last_reject}")
            t["validate"][m.id] = time.perf_counter() - s

        # phase 2: PREPARE votes (broadcast), every node verifies every vote it receives
        prepares = []
        for m in live:
            s = time.perf_counter()
            if m.behavior == BYZ_VOTER:
                prepares.append(m.vote("PREPARE", h, view, sha256_hex(self.rng.randbytes(8))))
            elif prepared_hash[m.id] is not None:
                prepares.append(m.vote("PREPARE", h, view, prepared_hash[m.id]))
            t["prepare"][m.id] += time.perf_counter() - s
        msgs += len(prepares) * (len(live) - 1)
        commit_ready = {}
        for m in live:
            s = time.perf_counter()
            tally = Counter()
            for v in prepares:
                if verify(self.pubs[v["node"]], canon(vote_body(v["phase"], v["height"], v["view"], v["hash"], v["node"])), v["sig"]):
                    tally[v["hash"]] += 1
            mine = prepared_hash.get(m.id)
            commit_ready[m.id] = mine is not None and tally[mine] >= self.quorum
            t["prepare"][m.id] += time.perf_counter() - s

        # phase 3: COMMIT votes
        commits = []
        for m in live:
            s = time.perf_counter()
            if m.behavior == BYZ_VOTER:
                commits.append(m.vote("COMMIT", h, view, sha256_hex(self.rng.randbytes(8))))
            elif commit_ready[m.id]:
                commits.append(m.vote("COMMIT", h, view, prepared_hash[m.id]))
            t["commit"][m.id] += time.perf_counter() - s
        msgs += len(commits) * (len(live) - 1)
        good = Counter()
        valid_commits = defaultdict(list)
        for v in commits:
            if verify(self.pubs[v["node"]], canon(vote_body(v["phase"], v["height"], v["view"], v["hash"], v["node"])), v["sig"]):
                good[v["hash"]] += 1
                valid_commits[v["hash"]].append({"node": v["node"], "sig": v["sig"]})
        winner = next((hh for hh, c in good.items() if c >= self.quorum), None)

        if winner is None:
            for m in live:
                m.abort_pending()
            info.update(model_ms=sum(max(d.values()) if d else 0 for d in t.values()) * 1000 + 3 * self.hop_ms,
                        wall_ms=(time.perf_counter() - t0_wall) * 1000, messages=msgs + 0,
                        bytes=block_bytes * (len(live) - 1) + 200 * (len(prepares) + len(commits)) * (len(live) - 1))
            return info

        cert = valid_commits[winner][:self.quorum]
        winning_block = next(b for b in proposals.values() if b["hash"] == winner)
        for m in live:
            s = time.perf_counter()
            if m.pending is not None and m.pending["hash"] == winner:
                m.commit_pending(cert)
            else:  # this node saw a different proposal: drop it and fetch the agreed block
                m.abort_pending()
                blk2 = clone(winning_block)
                blk2["cert"] = cert
                ok, reason = m.ledger.add_block(blk2)
                if not ok:
                    info["reasons"].append(f"{m.id}:fetch_failed:{reason}")
            t["commit"][m.id] += time.perf_counter() - s
        done = {x["tx_id"] for x in winning_block["txs"]}
        self.mempool = [x for x in self.mempool if x["tx_id"] not in done]
        self.mempool_ids -= done
        model_ms = sum(max(d.values()) if d else 0 for d in t.values()) * 1000 + 3 * self.hop_ms
        info.update(committed=True, block_hash=winner, n_tx=len(winning_block["txs"]),
                    model_ms=model_ms, wall_ms=(time.perf_counter() - t0_wall) * 1000, messages=msgs,
                    bytes=block_bytes * (len(live) - 1) + 200 * (len(prepares) + len(commits)) * (len(live) - 1),
                    phase_ms={p: (max(d.values()) if d else 0) * 1000 for p, d in t.items()})
        return info

    # ---- rounds ----------------------------------------------------------------------
    def run_round(self):
        """Commit one block from the mempool, moving through views if needed.
        Returns a summary dict (committed False and stalled True if no view succeeds)."""
        if not self.mempool:
            return None
        for m in self.nodes.values():            # lagging nodes catch up first
            if m.online and m.ledger.next_index < max(x.ledger.next_index for x in self.nodes.values() if x.online):
                self._sync(m)
        txs = self.mempool[:self.batch_size]
        penalty_ms, attempts = 0.0, []
        for k in range(self.n):
            view = self.view + k
            info = self._attempt(view, txs)
            attempts.append(info)
            self.rounds.append(info)
            if info["committed"]:
                info["view_changes"] = k
                info["total_model_ms"] = info["model_ms"] + penalty_ms
                self.view = 0
                return info
            penalty_ms += info.get("model_ms", 0.0) + self.view_timeout_ms + 2 * self.hop_ms
        self.view = 0
        return {"committed": False, "stalled": True, "view_changes": self.n, "attempts": attempts,
                "total_model_ms": penalty_ms, "n_tx": 0, "messages": sum(a.get("messages", 0) for a in attempts)}

    def process_all(self):
        """Run rounds until the mempool is empty (or consensus stalls)."""
        blocks, cum, tx_lat, total_msgs, total_bytes, wall = [], 0.0, [], 0, 0, 0.0
        stalled = False
        while self.mempool:
            r = self.run_round()
            if r is None:
                break
            cum += r["total_model_ms"]
            total_msgs += r.get("messages", 0)
            if not r["committed"]:
                stalled = True
                break
            total_bytes += r.get("bytes", 0)
            wall += r.get("wall_ms", 0)
            blocks.append(r)
            tx_lat += [cum] * r["n_tx"]
        n_tx = sum(b["n_tx"] for b in blocks)
        return {"blocks": len(blocks), "txs": n_tx, "stalled": stalled, "model_ms_total": cum,
                "wall_ms_total": wall, "throughput_tps": (n_tx / (cum / 1000)) if cum else 0.0,
                "avg_tx_latency_ms": (sum(tx_lat) / len(tx_lat)) if tx_lat else 0.0,
                "avg_block_confirm_ms": (sum(b["total_model_ms"] for b in blocks) / len(blocks)) if blocks else 0.0,
                "view_changes": sum(b.get("view_changes", 0) for b in blocks),
                "messages": total_msgs, "bytes": total_bytes}

    def chain_consistent(self):
        """True if every online honest node holds the same head."""
        heads = {m.ledger.head_hash for m in self.nodes.values() if m.online and m.behavior == HONEST}
        return len(heads) == 1
