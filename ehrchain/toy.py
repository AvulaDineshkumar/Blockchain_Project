"""Small synthetic world (random bytes as files) used by tests and the scalability sweeps."""
import os

from .world import World


def toy_world(n_nodes=4, hosp=2, docs=3, pats=3, file_size=2048, **kw):
    w = World(n_nodes=n_nodes, store_in_memory=True, **kw)
    H = [w.new_actor(f"H{i}", "hospital") for i in range(hosp)]
    D = [w.new_actor(f"D{i}", "doctor") for i in range(docs)]
    P = [w.new_actor(f"P{i}", "patient") for i in range(pats)]
    I = w.new_actor("I0", "insurer")
    A = w.new_actor("A0", "auditor")
    for a in H + D + P + [I, A]:
        w.register(a)
    w.commit()
    recs = []
    for i, p in enumerate(P):
        h = H[i % hosp]
        rid = f"MRI-{i}"
        raw = os.urandom(file_size)
        hh = w.store.put(rid, raw, h)
        w.records[rid] = {"patient": p.id, "hospital": h.id, "kind": "MRI", "hash": hh, "size": file_size}
        w.submit(h, "ADD_RECORD", {"record_id": rid, "patient_id": p.id, "kind": "MRI", "file_hash": hh, "size": file_size})
        recs.append(rid)
    w.commit()
    return w, H, D, P, I, A, recs
