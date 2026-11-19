"""Glue: a permissioned network + actors + off-chain store, optionally loaded from the
Synthea Coherent subset."""
import re

from .actors import Actor
from .data import insurance_view, load_subset
from .network import Clock, Network
from .storage import OffChainStore

DAY = 86400.0


def slug(prefix, text):
    return f"{prefix}-" + re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:40]


class World:
    def __init__(self, n_nodes=4, hop_ms=5.0, batch_size=200, store_in_memory=False, seed=1):
        self.clock = Clock()
        self.admin = Actor("admin", "admin", "Network admin")
        self.net = Network(n_nodes, batch_size=batch_size, hop_ms=hop_ms, clock=self.clock,
                           admin_pub=self.admin.sk.public_hex, seed=seed)
        self.store = OffChainStore(in_memory=store_in_memory)
        self.actors = {}
        self.patients = {}      # patient id -> PatientData
        self.records = {}       # record_id -> {patient, hospital, kind, plaintext_hash}
        self.doctor_of = {}     # patient id -> list of doctor ids that treated them
        self.insurer_of = {}

    # ---- helpers -----------------------------------------------------------------------
    def commit(self):
        """Run consensus until the mempool is empty."""
        return self.net.process_all()

    def submit(self, actor, ttype, payload):
        tx = actor.tx(ttype, payload, self.clock.now())
        self.net.submit(tx)
        return tx

    def register(self, actor):
        return self.submit(self.admin, "REGISTER", actor.register_payload())

    def new_actor(self, aid, role, name=""):
        a = Actor(aid, role, name)
        self.actors[aid] = a
        return a

    def result(self, tx):
        found = self.net.reference().ledger.lookup(tx["tx_id"])
        return found[2] if found else None

    # ---- loading real data ---------------------------------------------------------------
    def load_dataset(self, root, limit=None, progress=None):
        data = load_subset(root)[:limit]
        orgs = {h for p in data for h in p.hospitals} | {p.imaging_hospital for p in data}
        for h in sorted(orgs):
            self.register(self.new_actor(slug("H", h), "hospital", h))
        docs = {}
        for p in data:
            for d, h in p.doctors:
                docs[(d, h)] = None
        for (d, h) in sorted(docs):
            self.register(self.new_actor(slug("D", d + h), "doctor", d))
        for ins in sorted({p.insurer for p in data}):
            self.register(self.new_actor(slug("I", ins), "insurer", ins))
        self.register(self.new_actor("auditor-1", "auditor", "Independent auditor"))
        for p in data:
            self.register(self.new_actor("P-" + p.pid[:8], "patient", p.name))
        self.commit()
        for i, p in enumerate(data):
            pid = "P-" + p.pid[:8]
            self.patients[pid] = p
            self.doctor_of[pid] = [slug("D", d + h) for d, h in p.doctors]
            self.insurer_of[pid] = slug("I", p.insurer)
            hosp = self.actors[slug("H", p.imaging_hospital)]
            for kind, path in (("FHIR", p.fhir_path), ("MRI", p.dicom_path), ("FHIR_INS", p.fhir_path)):
                with open(path, "rb") as f:
                    raw = f.read()
                if kind == "FHIR_INS":
                    raw = insurance_view(raw)
                rid = f"{kind}-{p.pid[:8]}" if kind != "FHIR_INS" else f"INS-{p.pid[:8]}"
                h = self.store.put(rid, raw, hosp)
                self.records[rid] = {"patient": pid, "hospital": hosp.id, "kind": kind, "hash": h, "size": len(raw)}
                self.submit(hosp, "ADD_RECORD", {"record_id": rid, "patient_id": pid, "kind": kind,
                                                 "file_hash": h, "size": len(raw)})
            self.commit()
            if progress:
                progress(i + 1, len(data))
        self.assign_nodes()
        return data

    def assign_nodes(self):
        """Each validator node is operated by a hospital (recorded on-chain by the admin).
        The hospitals holding the most records operate the nodes."""
        from collections import Counter
        cnt = Counter(v["hospital"] for v in self.records.values())
        hospitals = sorted((a.id for a in self.actors.values() if a.role == "hospital"),
                           key=lambda h: (-cnt[h], h))
        for i, nid in enumerate(self.net.order):
            hid = hospitals[i % len(hospitals)]
            self.submit(self.admin, "ASSIGN_NODE", {"node": nid, "operator": hid, "node_pub": self.net.pubs[nid]})
        self.commit()

    # ---- access flow ---------------------------------------------------------------------
    def request_and_fetch(self, actor, record_id):
        """Signed request -> consensus -> (if granted) encrypted file -> decrypt + hash check."""
        tx = self.submit(actor, "REQUEST_ACCESS", {"record_id": record_id})
        self.commit()
        res = self.result(tx)
        if res is None or not res.startswith("GRANTED"):
            return res, None, tx
        resp = self.store.serve(tx["tx_id"], actor.id, actor.bk.public_hex,
                                self.net.reference().ledger, self.actors)
        if "error" in resp:
            return resp["error"], None, tx
        status, plain = actor.open_response(resp)
        return f"{res}|{status}", plain, tx

    def grant(self, patient, grantee_id, record_id="*", kinds=("FHIR", "MRI"), days=30):
        return self.submit(patient, "GRANT_CONSENT", {
            "grantee": grantee_id, "record_id": record_id, "kinds": list(kinds),
            "expires_at": self.clock.now() + days * DAY})


def access_history(world, patient_id):
    """Everything on the ledger about this patient's records (granted AND denied), in order."""
    led = world.net.reference().ledger
    mine = {r for r, v in led.state.records.items() if v["patient"] == patient_id}
    out = []
    for b in led.blocks[1:]:
        for t, res in zip(b["txs"], b["results"]):
            rid = t["payload"].get("record_id") if isinstance(t["payload"], dict) else None
            if t["type"] == "REQUEST_ACCESS" and rid in mine:
                who = led.state.identities.get(t["sender"], {})
                out.append({"block": b["header"]["index"], "time": b["header"]["ts"], "record": rid,
                            "requester": t["sender"], "role": who.get("role", "UNREGISTERED"), "result": res,
                            "tx_id": t["tx_id"]})
            elif t["type"] in ("GRANT_CONSENT", "REVOKE_CONSENT") and t["sender"] == patient_id:
                out.append({"block": b["header"]["index"], "time": b["header"]["ts"], "record": t["payload"].get("record_id"),
                            "requester": t["sender"], "role": "patient", "result": t["type"] + ":" + res,
                            "tx_id": t["tx_id"]})
    return out
