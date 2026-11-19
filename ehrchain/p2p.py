"""Real peer-to-peer mode: every validator is its own OS process listening on a TCP port.

Differences from the in-process simulation (network.py):
  * PRE-PREPARE / PREPARE / COMMIT messages are real JSON messages sent over TCP sockets
    directly between validator processes (no shared memory).
  * A validator failure is real: the process is killed; recovery starts a new process that
    fetches and fully re-verifies the chain from its peers over TCP.
  * Clients broadcast signed requests to all validators (as in PBFT); if the primary does
    not produce a committed block in time, the client moves on to the next primary
    (view change driven by the client timeout).
The validators reuse the same Node / Ledger / contract code, so the rules are identical.
Everything still runs on one machine (127.0.0.1), so network latency is the loopback
latency, not a wide-area one.
"""
import json
import multiprocessing as mp
import random
import socket
import socketserver
import struct
import threading
import time
from collections import defaultdict

from .crypto import SigningKey, canon, sha256_hex, verify
from .ledger import clone, make_genesis, tx_sig_ok, vote_body, verify_chain
from .network import HONEST, Node

HOST = "127.0.0.1"


# ------------------------------------------------------------------ wire protocol -------
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def send(port, msg, wait=False, timeout=3.0):
    """Send one JSON message to a validator. Returns the reply if wait=True, else None.
    Raises OSError if the validator is down."""
    data = json.dumps(msg, separators=(",", ":")).encode()
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        s.sendall(struct.pack(">I", len(data)) + data)
        if not wait:
            return None
        n = struct.unpack(">I", _recv_exact(s, 4))[0]
        return json.loads(_recv_exact(s, n))


def _bg_send(port, msg):
    try:
        send(port, msg)
    except OSError:
        pass


# ------------------------------------------------------------------ validator process ---
class P2PNode:
    def __init__(self, nid, key_hex, genesis, order, ports, batch=200):
        self.nid, self.order, self.ports, self.batch = nid, order, ports, batch
        self.node = Node(nid, SigningKey.from_private_hex(key_hex), genesis)
        self.pubs = genesis["header"]["config"]["validators"]
        self.n = len(order)
        self.quorum = genesis["header"]["config"]["quorum"]
        self.lock = threading.RLock()
        self.mempool, self.mempool_ids = [], set()
        self.prepares = defaultdict(dict)   # (h, view, hash) -> {node: vote}
        self.commits = defaultdict(dict)
        self.sent_commit = set()
        self.blocks = {}                    # hash -> proposed block
        self.view_of = {}

    # -- helpers -------------------------------------------------------------------------
    def bcast(self, msg):
        for pid, port in self.ports.items():
            if pid != self.nid:
                threading.Thread(target=_bg_send, args=(port, msg), daemon=True).start()

    def _vote_ok(self, v):
        body = vote_body(v["phase"], v["height"], v["view"], v["hash"], v["node"])
        return v["node"] in self.pubs and verify(self.pubs[v["node"]], canon(body), v["sig"])

    def sync_from_peers(self):
        for pid, port in self.ports.items():
            if pid == self.nid:
                continue
            try:
                got = send(port, {"t": "GETBLOCKS", "from": self.node.ledger.next_index}, wait=True, timeout=10)
            except OSError:
                continue
            for b in got["blocks"]:
                ok, _ = self.node.ledger.add_block(b)
                if not ok:
                    break
        return self.node.ledger.next_index - 1

    # -- consensus handlers (all called with self.lock held) ------------------------------
    def on_preprepare(self, b, view):
        L = self.node.ledger
        if b["header"]["index"] != L.next_index:
            return
        if self.node.pending is not None:
            if self.node.pending["hash"] == b["hash"]:
                return
            self.node.abort_pending()                       # a new view supersedes the old proposal
        h = b["header"]["index"]
        primary = self.order[(h + view) % self.n]
        if self.node.behavior == "byz_voter":
            bad = sha256_hex(random.randbytes(8))
            self.record_and_send("PREPARE", h, view, bad)
            return
        if not self.node.validate_block(b, primary, view, time.time()):
            return
        self.blocks[b["hash"]] = b
        self.record_and_send("PREPARE", h, view, b["hash"])
        self.progress()

    def record_and_send(self, phase, h, view, bhash):
        v = self.node.vote(phase, h, view, bhash)
        store = self.prepares if phase == "PREPARE" else self.commits
        store[(h, view, bhash)][self.nid] = v
        self.bcast({"t": phase, "vote": v})

    def progress(self):
        p = self.node.pending
        if p is None:
            return
        h, view = p["header"]["index"], p["header"]["view"]
        key = (h, view, p["hash"])
        if len(self.prepares[key]) >= self.quorum and key not in self.sent_commit:
            self.sent_commit.add(key)
            self.record_and_send("COMMIT", h, view, p["hash"])
        if len(self.commits[key]) >= self.quorum:
            cert = [{"node": nid, "sig": v["sig"]} for nid, v in list(self.commits[key].items())[:self.quorum]]
            done = {t["tx_id"] for t in p["txs"]}
            self.node.commit_pending(cert)
            self.mempool = [t for t in self.mempool if t["tx_id"] not in done]
            self.mempool_ids -= done
            for d in (self.prepares, self.commits):
                for k in [k for k in d if k[0] <= h]:
                    del d[k]

    # -- message dispatch ------------------------------------------------------------------
    def handle(self, m):
        t = m["t"]
        L = self.node.ledger
        with self.lock:
            if t == "TXS":
                added = 0
                for tx in m["txs"]:
                    if tx["tx_id"] in self.mempool_ids or tx["tx_id"] in L.index or not tx_sig_ok(tx):
                        continue
                    self.mempool.append(tx); self.mempool_ids.add(tx["tx_id"]); added += 1
                return {"added": added}
            if t == "PROPOSE":
                txs = self.mempool[:self.batch]
                if not txs:
                    return {"ok": False}
                self.node.abort_pending()                      # drop any stalled proposal before building a new one
                blk = self.node.make_proposal(txs, time.time(), m["view"])
                if self.node.behavior == "byz_primary":
                    blk = self.node.forge(blk)
                self.bcast({"t": "PREPREPARE", "block": blk, "view": m["view"]})
                self.on_preprepare(blk, m["view"])
                return {"ok": True}
            if t == "PREPREPARE":
                self.on_preprepare(m["block"], m["view"]); return None
            if t in ("PREPARE", "COMMIT"):
                v = m["vote"]
                if self._vote_ok(v) and v["height"] >= L.next_index:
                    (self.prepares if t == "PREPARE" else self.commits)[(v["height"], v["view"], v["hash"])][v["node"]] = v
                    self.progress()
                return None
            if t == "STATUS":
                return {"height": L.next_index - 1, "head": L.head_hash, "mempool": len(self.mempool),
                        "behavior": self.node.behavior}
            if t == "LOOKUP":
                f = L.lookup(m["tx_id"])
                return {"found": False} if f is None else {"found": True, "result": f[2], "sender": f[1]["sender"],
                                                           "type": f[1]["type"], "payload": f[1]["payload"], "block": f[0]["header"]["index"]}
            if t == "RECORD":
                return {"record": L.state.records.get(m["rid"])}
            if t == "GETBLOCKS":
                return {"blocks": L.blocks[m["from"]:m["from"] + 400]}
            if t == "SET":
                self.node.behavior = m["behavior"]
                if m.get("attack"):
                    self.node.attack = m["attack"]
                return {"ok": True}
            if t == "ALLBLOCKS":
                return {"blocks": L.blocks}
        return None


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            n = struct.unpack(">I", _recv_exact(self.request, 4))[0]
            msg = json.loads(_recv_exact(self.request, n))
            reply = self.server.p2p.handle(msg)
            if reply is not None:
                data = json.dumps(reply, separators=(",", ":")).encode()
                self.request.sendall(struct.pack(">I", len(data)) + data)
        except (ConnectionError, OSError, ValueError):
            pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def node_main(nid, key_hex, genesis, order, ports, sync):
    """Entry point of one validator process."""
    p2p = P2PNode(nid, key_hex, genesis, order, ports)
    srv = _Server((HOST, ports[nid]), _Handler)
    srv.p2p = p2p
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    if sync:
        with p2p.lock:
            p2p.sync_from_peers()
    th.join()


# ------------------------------------------------------------------ client / driver -----
def _free_ports(k):
    socks, ports = [], []
    for _ in range(k):
        s = socket.socket(); s.bind((HOST, 0)); ports.append(s.getsockname()[1]); socks.append(s)
    for s in socks:
        s.close()
    return ports


class RemoteLedger:
    """Client-side view of the chain: a fact is accepted only if f+1 validators report the same."""

    def __init__(self, net):
        self.net = net
        self.state = self
        self.records = self

    def _agree(self, msg, field):
        votes = {}
        for nid in self.net.alive():
            try:
                r = send(self.net.ports[nid], msg, wait=True)
            except OSError:
                continue
            votes.setdefault(json.dumps(r.get(field), sort_keys=True), []).append(r)
        for k, rs in votes.items():
            if len(rs) >= self.net.f + 1:
                return rs[0]
        return None

    def lookup(self, tx_id):
        r = self._agree({"t": "LOOKUP", "tx_id": tx_id}, "result")
        if not r or not r["found"]:
            return None
        return None, {"type": r["type"], "sender": r["sender"], "payload": r["payload"]}, r["result"]

    def __getitem__(self, rid):
        r = self._agree({"t": "RECORD", "rid": rid}, "record")
        if not r or r["record"] is None:
            raise KeyError(rid)
        return r["record"]


class P2PNetwork:
    def __init__(self, n, admin_pub, timeout_view=2.0):
        self.n = n
        self.f = (n - 1) // 3
        self.quorum = 2 * self.f + 1
        self.order = [f"V{i}" for i in range(n)]
        self.keys = {k: SigningKey() for k in self.order}
        self.pubs = {k: v.public_hex for k, v in self.keys.items()}
        self.genesis = make_genesis(admin_pub, self.pubs, time.time())
        self.ports = dict(zip(self.order, _free_ports(n)))
        self.ctx = mp.get_context("spawn")
        self.procs = {}
        self.timeout_view = timeout_view
        self.stalled_txs = 0
        for nid in self.order:
            self._spawn(nid, sync=False)
        self.wait_ready(self.order)

    def _spawn(self, nid, sync):
        p = self.ctx.Process(target=node_main, args=(nid, self.keys[nid].private_hex(), self.genesis,
                                                     self.order, self.ports, sync), daemon=True)
        p.start()
        self.procs[nid] = p

    def wait_ready(self, ids, timeout=30):
        t0 = time.time()
        for nid in ids:
            while True:
                try:
                    send(self.ports[nid], {"t": "STATUS"}, wait=True, timeout=1)
                    break
                except OSError:
                    if time.time() - t0 > timeout:
                        raise RuntimeError(f"{nid} did not start")
                    time.sleep(0.05)

    # -- failures -----------------------------------------------------------------------
    def kill(self, nid):
        self.procs[nid].terminate(); self.procs[nid].join()

    def restart(self, nid):
        self._spawn(nid, sync=True)
        self.wait_ready([nid])

    def set_behavior(self, nid, behavior, attack=None):
        send(self.ports[nid], {"t": "SET", "behavior": behavior, "attack": attack}, wait=True)

    def alive(self):
        return [n for n in self.order if self.procs[n].is_alive()]

    # -- client operations ----------------------------------------------------------------
    def status(self, nid):
        try:
            return send(self.ports[nid], {"t": "STATUS"}, wait=True, timeout=1)
        except OSError:
            return None

    def heights(self):
        return {n: (self.status(n) or {}).get("height") for n in self.order}

    def submit(self, txs, chunk=100):
        for i in range(0, len(txs), chunk):
            for nid in self.alive():
                try:
                    send(self.ports[nid], {"t": "TXS", "txs": txs[i:i + chunk]}, wait=True, timeout=10)
                except OSError:
                    pass

    def _live_height(self):
        hs = [s["height"] for s in (self.status(n) for n in self.alive()) if s]
        return sorted(hs)[len(hs) - self.quorum] if len(hs) >= self.quorum else min(hs, default=0)

    def commit_one(self):
        """Ask primaries in turn until a block commits at a quorum of validators."""
        h0 = self._live_height()
        t0 = time.perf_counter()
        for view in range(self.n):
            primary = self.order[(h0 + 1 + view) % self.n]
            try:
                r = send(self.ports[primary], {"t": "PROPOSE", "view": view}, wait=True, timeout=2)
                if not r.get("ok"):
                    # this primary has nothing to propose: only stop if nobody has pending requests
                    if not any((self.status(n) or {}).get("mempool") for n in self.alive()):
                        return {"committed": False, "empty": True}
                    continue
            except OSError:
                continue                         # primary is down: go to next view immediately
            deadline = time.time() + self.timeout_view
            while time.time() < deadline:
                hs = [s["height"] for s in (self.status(n) for n in self.alive()) if s]
                if sum(1 for x in hs if x > h0) >= self.quorum:
                    return {"committed": True, "view_changes": view, "ms": (time.perf_counter() - t0) * 1000}
                time.sleep(0.001)
        return {"committed": False, "stalled": True, "ms": (time.perf_counter() - t0) * 1000}

    def run_until_empty(self, max_blocks=100):
        out = []
        for _ in range(max_blocks):
            r = self.commit_one()
            if not r["committed"]:
                if r.get("stalled"):
                    out.append(r)
                break
            out.append(r)
        return out

    def result(self, tx_id):
        f = RemoteLedger(self).lookup(tx_id)
        return f[2] if f else None

    def ledger(self):
        return RemoteLedger(self)

    def audit_chain(self, nid):
        blocks = send(self.ports[nid], {"t": "ALLBLOCKS"}, wait=True, timeout=30)["blocks"]
        return verify_chain(blocks)

    def close(self):
        for p in self.procs.values():
            if p.is_alive():
                p.terminate()
        for p in self.procs.values():
            p.join(timeout=2)
