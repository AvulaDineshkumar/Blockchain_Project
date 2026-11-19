"""Real peer-to-peer demo: validators are separate processes talking over TCP sockets.
  python p2p_demo.py            # PDF section 11 scenarios on real data, with a real node kill
  python p2p_demo.py --bench    # latency/throughput over real sockets (writes results/p2p_bench.csv)
"""
import argparse
import csv
import json
import os
import random
import sys
import time

from ehrchain.actors import Actor
from ehrchain.data import insurance_view, load_subset
from ehrchain.p2p import P2PNetwork
from ehrchain.storage import OffChainStore
from ehrchain.world import slug

ROOT = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(ROOT, "results")


def commit(net, txs):
    net.submit(txs)
    return net.run_until_empty()


def fetch(net, store, actor, rid, delay=0):
    """Signed request -> consensus over TCP -> file from the gateway (only if the ledger says GRANTED)."""
    tx = actor.tx("REQUEST_ACCESS", {"record_id": rid}, time.time())
    commit(net, [tx])
    res = net.result(tx["tx_id"])
    if res is None or not res.startswith("GRANTED"):
        return res
    resp = store.serve(tx["tx_id"], actor.id, actor.bk.public_hex, net.ledger(), ACTORS)
    status, _ = actor.open_response(resp) if "error" not in resp else (resp["error"], None)
    return f"{res}|{status}"


ACTORS = {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=4)
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--loads", type=int, nargs="*", default=[100, 500, 1000])
    ap.add_argument("--repeats", type=int, default=5)
    a = ap.parse_args()
    data = load_subset(os.path.join(ROOT, "data", "subset"))[:4]
    admin = Actor("admin", "admin", "admin")
    net = P2PNetwork(a.nodes, admin.sk.public_hex)
    store = OffChainStore(in_memory=False)
    out = {"nodes": a.nodes, "ports": net.ports}
    p = data[0]

    def reg(aid, role, name):
        x = Actor(aid, role, name); ACTORS[aid] = x
        return admin.tx("REGISTER", x.register_payload(), time.time()), x

    # ---- setup: identities taken from the real FHIR data ------------------------------------
    txs, hosp = [], {}
    for d in data:
        h = slug("H", d.imaging_hospital)
        if h not in ACTORS:
            t, x = reg(h, "hospital", d.imaging_hospital); txs.append(t); hosp[h] = x
    pat_id = "P-" + p.pid[:8]
    t, pat = reg(pat_id, "patient", p.name); txs.append(t)
    doc_name, doc_h = p.doctors[0]
    t, doc = reg(slug("D", doc_name + doc_h), "doctor", doc_name); txs.append(t)
    other = data[1]
    t, stranger = reg(slug("D", other.doctors[0][0] + other.doctors[0][1]), "doctor", other.doctors[0][0]); txs.append(t)
    t, ins = reg(slug("I", p.insurer), "insurer", p.insurer); txs.append(t)
    t, aud = reg("auditor-1", "auditor", "auditor"); txs.append(t)
    extra = []
    if a.bench:
        for i in range(30):
            t, x = reg(f"BD{i}", "doctor", f"Bench doctor {i}"); txs.append(t); extra.append(x)
    commit(net, txs)
    custodian = ACTORS[slug("H", p.imaging_hospital)]
    commit(net, [admin.tx("ASSIGN_NODE", {"node": nid, "operator": list(hosp)[i % len(hosp)], "node_pub": net.pubs[nid]}, time.time())
                 for i, nid in enumerate(net.order)])
    recs = {}
    for kind, path in (("FHIR", p.fhir_path), ("MRI", p.dicom_path), ("INS", p.fhir_path)):
        raw = open(path, "rb").read()
        if kind == "INS":
            raw = insurance_view(raw)
        rid = f"{kind}-{p.pid[:8]}"
        h = store.put(rid, raw, custodian)
        recs[rid] = h
        commit(net, [custodian.tx("ADD_RECORD", {"record_id": rid, "patient_id": pat_id, "kind": "FHIR_INS" if kind == "INS" else kind,
                                                  "file_hash": h, "size": len(raw)}, time.time())])
    mri, fhir, insr = f"MRI-{p.pid[:8]}", f"FHIR-{p.pid[:8]}", f"INS-{p.pid[:8]}"
    print(f"{a.nodes} validator processes up on TCP ports {list(net.ports.values())}; chain heights {net.heights()}")

    if a.bench:
        return bench(net, a, admin, extra, pat, mri)

    R = []

    def log(name, res):
        R.append({"scenario": name, "result": res}); print(f"{name:55s} -> {res}")

    log("1. doctor with no consent requests the MRI", fetch(net, store, doc, mri))
    commit(net, [pat.tx("GRANT_CONSENT", {"grantee": doc.id, "record_id": "*", "kinds": ["FHIR", "MRI"], "expires_at": time.time() + 6}, time.time())])
    log("2. authorized doctor requests the MRI (consent valid 6 s)", fetch(net, store, doc, mri))
    log("3. a different, unconsented doctor requests the MRI", fetch(net, store, stranger, mri))
    ghost = Actor("ghost", "doctor")
    log("4. unregistered user requests the MRI", fetch(net, store, ghost, mri))
    commit(net, [pat.tx("GRANT_CONSENT", {"grantee": ins.id, "record_id": "*", "kinds": ["FHIR_INS"], "expires_at": time.time() + 600}, time.time())])
    log("5. insurer requests the billing view", fetch(net, store, ins, insr))
    log("6. insurer requests the MRI", fetch(net, store, ins, mri))
    time.sleep(6.5)
    log("7. same doctor after the consent expired (real 6 s)", fetch(net, store, doc, mri))
    commit(net, [pat.tx("GRANT_CONSENT", {"grantee": doc.id, "record_id": "*", "kinds": ["FHIR", "MRI"], "expires_at": time.time() + 600}, time.time())])
    store.tamper_ciphertext(fhir)
    log("8. stored FHIR file modified (1 bit), doctor requests it", fetch(net, store, doc, fhir))
    # ---- node failure with real processes ---------------------------------------------------
    f = net.f
    victims = net.order[1:1 + f]
    for v in victims:
        net.kill(v)
    log(f"9. {f} validator process(es) killed {victims}; request MRI", fetch(net, store, doc, mri))
    log("   heights now", json.dumps(net.heights()))
    extra_v = net.order[1 + f]
    net.kill(extra_v)
    t_stall = doc.tx("REQUEST_ACCESS", {"record_id": mri}, time.time())
    r = commit(net, [t_stall])
    log(f"10. one more killed ({extra_v}): more than f faulty", "NOT committed (stalled), ledger unchanged" if r and r[-1].get("stalled") else str(r))
    for v in victims + [extra_v]:
        net.restart(v)
    r = net.run_until_empty()
    log("11. all restarted (fetch + re-verify chain from peers over TCP)", f"stalled request committed after recovery: {net.result(t_stall['tx_id'])}; heights {net.heights()}")
    audits = {n: net.audit_chain(n)[:2] for n in net.order}
    log("12. every validator's chain re-verified from genesis", str(audits))
    # ---- malicious primary --------------------------------------------------------------------
    h0 = max(h for h in net.heights().values() if h is not None)
    bad = net.order[(h0 + 1) % net.n]
    net.set_behavior(bad, "byz_primary", "forge_result")
    t_b = stranger.tx("REQUEST_ACCESS", {"record_id": mri}, time.time())
    r = commit(net, [t_b])
    log(f"13. next primary {bad} forges a contract result", f"committed after view change(s)={r[-1].get('view_changes')}; true result on ledger: {net.result(t_b['tx_id'])}")
    log("14. final heights (all validators identical)", json.dumps(net.heights()))
    os.makedirs(RES, exist_ok=True)
    json.dump(R, open(os.path.join(RES, f"p2p_demo_n{a.nodes}.json"), "w"), indent=2)
    net.close()


def bench(net, a, admin, extra, pat, mri):
    rng = random.Random(1)
    rows = []
    print("real-socket benchmark (5 ms is NOT added here: this is loopback TCP between processes)")
    for load in a.loads:
        for rep in range(a.repeats):
            txs = []
            for _ in range(load):
                d = rng.choice(extra)
                txs.append(d.tx("REQUEST_ACCESS", {"record_id": mri}, time.time()))
            t0 = time.perf_counter()
            net.submit(txs)
            blocks = []
            while True:
                r = net.commit_one()
                if not r["committed"]:
                    break
                blocks.append((time.perf_counter() - t0) * 1000)
            total = (time.perf_counter() - t0) * 1000
            # latency of a tx = time its block committed (burst model, same definition as the simulation)
            per_block = [200] * (load // 200) + ([load % 200] if load % 200 else [])
            lat = sum(t * c for t, c in zip(blocks, per_block)) / load
            rows.append({"mode": "real-tcp", "nodes": a.nodes, "load": load, "rep": rep, "blocks": len(blocks),
                         "total_ms": total, "avg_tx_latency_ms": lat, "throughput_tps": load / (total / 1000)})
        sub = [r for r in rows if r["load"] == load]
        print(f"n={a.nodes} load={load}: latency {sum(r['avg_tx_latency_ms'] for r in sub)/len(sub):.1f} ms, throughput {sum(r['throughput_tps'] for r in sub)/len(sub):.0f} tx/s", flush=True)
    path = os.path.join(RES, "p2p_bench.csv")
    new = not os.path.exists(path)
    with open(path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); new and w.writeheader(); w.writerows(rows)
    net.close()


if __name__ == "__main__":
    main()
