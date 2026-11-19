"""Attack / failure / correctness experiments on the Synthea Coherent subset.
Run: python -m ehrchain.experiments [--patients 20] [--data data/subset]
Writes results/experiments.json and results/experiments_summary.md"""
import argparse
import copy
import json
import os
import time
from collections import Counter

from .actors import Actor
from .crypto import canon
from .ledger import (header_hash, merkle_proof, merkle_root, results_hash, verify_chain, verify_proof)
from .network import BYZ_PRIMARY, BYZ_VOTER, EQUIVOCATOR, OFFLINE
from .world import World, access_history, DAY

RES = os.path.join(os.path.dirname(__file__), "..", "results")


def pick(w, pid):
    """(patient actor, treating doctor, insurer) for a patient id."""
    return w.actors[pid], w.actors[w.doctor_of[pid][0]], w.actors[w.insurer_of[pid]]


def e1_normal(w):
    ok = fail = 0
    for pid, p in w.patients.items():
        pat, doc, ins = pick(w, pid)
        w.grant(pat, doc.id, "*", ("FHIR", "MRI"), days=30)
        w.grant(pat, ins.id, "*", ("FHIR_INS",), days=30)
    w.commit()
    for pid, p in w.patients.items():
        pat, doc, ins = pick(w, pid)
        for kind in ("FHIR", "MRI"):
            r, plain, _ = w.request_and_fetch(doc, f"{kind}-{p.pid[:8]}")
            ok += r == "GRANTED:CONSENT|OK"; fail += r != "GRANTED:CONSENT|OK"
        r, plain, _ = w.request_and_fetch(pat, f"MRI-{p.pid[:8]}")
        ok += r == "GRANTED:OWNER|OK"; fail += r != "GRANTED:OWNER|OK"
        r, plain, _ = w.request_and_fetch(ins, f"INS-{p.pid[:8]}")
        ok += r == "GRANTED:CONSENT|OK"; fail += r != "GRANTED:CONSENT|OK"
    return {"requests": ok + fail, "granted_and_hash_verified": ok, "failed": fail}


def e2_unauthorized(w):
    c = Counter()
    pids = list(w.patients)
    for pid in pids:
        p = w.patients[pid]
        rid = f"MRI-{p.pid[:8]}"
        other = w.actors[w.doctor_of[pids[(pids.index(pid) + 1) % len(pids)]][0]]
        _, doc, ins = pick(w, pid)
        # 1. doctor with no consent (a doctor who treated someone else)
        if other.id not in w.doctor_of[pid]:
            c["doctor_without_consent:" + w.request_and_fetch(other, rid)[0]] += 1
        # 2. insurer asks for the MRI, and for the full clinical FHIR record (policy: billing view only)
        c["insurer_asks_MRI:" + w.request_and_fetch(ins, rid)[0]] += 1
        c["insurer_asks_full_FHIR:" + w.request_and_fetch(ins, f"FHIR-{p.pid[:8]}")[0]] += 1
        # 3. auditor asks for content
        c["auditor_content:" + w.request_and_fetch(w.actors["auditor-1"], rid)[0]] += 1
    # 4. unregistered attacker with a valid signature of its own
    ghost = Actor("ghost", "doctor")
    c["unregistered_signer:" + w.request_and_fetch(ghost, f"MRI-{w.patients[pids[0]].pid[:8]}")[0]] += 1
    # 5. impersonation: claim to be a registered doctor but sign with another key
    victim = w.actors[w.doctor_of[pids[0]][0]]
    imp = Actor(victim.id, "doctor"); imp._nonce = 999
    c["impersonation:" + w.request_and_fetch(imp, f"MRI-{w.patients[pids[0]].pid[:8]}")[0]] += 1
    # 6. forged / modified-after-signing transaction rejected before consensus
    tx = victim.tx("REQUEST_ACCESS", {"record_id": f"MRI-{w.patients[pids[0]].pid[:8]}"}, w.clock.now())
    tx["payload"] = {"record_id": f"MRI-{w.patients[pids[1]].pid[:8]}"}
    c["modified_after_signing:" + ("accepted" if w.net.submit(tx) else "REJECTED_BAD_SIGNATURE")] += 1
    # 7. replay of an already committed request
    t0 = victim.tx("REQUEST_ACCESS", {"record_id": f"MRI-{w.patients[pids[0]].pid[:8]}"}, w.clock.now())
    w.net.submit(t0); w.commit()
    w.net.mempool.append(t0); w.net.mempool_ids.discard(t0["tx_id"]); w.commit()
    last = w.net.reference().ledger.blocks[-1]
    c["replay:" + last["results"][-1]] += 1
    return dict(c)


def e10_hospital_request(w):
    """Hospital B requests a patient's MRI from hospital A (PDF: hospitals request data)."""
    hosp = sorted(a.id for a in w.actors.values() if a.role == "hospital")
    for pid in w.patients:
        rid = f"MRI-{w.patients[pid].pid[:8]}"
        owner_h = w.records[rid]["hospital"]
        other = next(h for h in hosp if h != owner_h)
        hb = w.actors[other]; pat = w.actors[pid]
        before = w.request_and_fetch(hb, rid)[0]
        w.grant(pat, hb.id, rid, ("MRI",), days=30); w.commit()
        after = w.request_and_fetch(hb, rid)[0]
        return {"hospital_B_without_consent": before, "hospital_B_with_consent": after}


def e11_privacy_scan(w):
    """Search the whole serialized ledger for patient names, full patient UUIDs and FHIR field names."""
    blob = b"".join(canon(b) for b in w.net.reference().ledger.blocks).decode("utf-8", "ignore")
    names = [p.name for p in w.patients.values()]
    return {"ledger_bytes_scanned": len(blob),
            "patient_names_found_on_chain": sum(blob.count(n) for n in names),
            "full_patient_uuids_found": sum(blob.count(p.pid) for p in w.patients.values()),
            "fhir_markers_found (birthDate, resourceType)": blob.count("birthDate") + blob.count("resourceType")}


def e3_expiry_revoke(w):
    pid = next(iter(w.patients)); p = w.patients[pid]; rid = f"MRI-{p.pid[:8]}"
    pat, doc, ins = pick(w, pid)
    out = {}
    w.submit(pat, "REVOKE_CONSENT", {"grantee": doc.id, "record_id": "*"}); w.commit()
    out["after_revoke"] = w.request_and_fetch(doc, rid)[0]
    w.grant(pat, doc.id, rid, ("MRI",), days=1); w.commit()
    out["within_validity"] = w.request_and_fetch(doc, rid)[0]
    w.clock.advance(2 * DAY)
    out["after_expiry"] = w.request_and_fetch(doc, rid)[0]
    return out


def e4_tamper(w):
    out = {}
    pids = list(w.patients)
    # --- off-chain file attacks ---
    pid = pids[1]; p = w.patients[pid]; pat, doc, ins = pick(w, pid)
    w.grant(pat, doc.id, "*", ("FHIR", "MRI"), days=30); w.commit()
    rid = f"FHIR-{p.pid[:8]}"
    w.store.tamper_ciphertext(rid)
    out["ciphertext_bit_flip"] = w.request_and_fetch(doc, rid)[0]
    pid2 = pids[2]; p2 = w.patients[pid2]; pat2, doc2, _ = pick(w, pid2)
    w.grant(pat2, doc2.id, "*", ("MRI",), days=30); w.commit()
    rid2 = f"MRI-{p2.pid[:8]}"
    w.store.replace_file_consistently(rid2, b"forged scan " * 1000, w.actors[w.records[rid2]["hospital"]])
    out["insider_replaces_file"] = w.request_and_fetch(doc2, rid2)[0]
    # --- ledger attacks (on a copy of one node's chain) ---
    blocks = copy.deepcopy(w.net.reference().ledger.blocks)
    out["ledger_untouched"] = verify_chain(blocks)[:2]
    k = next(i for i in range(len(blocks) - 1, 0, -1) if any(r.startswith("DENIED") for r in blocks[i]["results"]))
    b = blocks[k]
    j = next(i for i, r in enumerate(b["results"]) if r.startswith("DENIED"))
    b["results"][j] = "GRANTED:CONSENT"                      # attacker erases a denied attempt
    out["ledger_result_edited"] = verify_chain(blocks)[:2]
    b["header"]["results_hash"] = results_hash(b["results"]); b["hash"] = header_hash(b["header"])
    out["ledger_edited_and_hash_recomputed"] = verify_chain(blocks)[:2]
    blocks2 = copy.deepcopy(w.net.reference().ledger.blocks)
    del blocks2[k]
    out["ledger_block_deleted"] = verify_chain(blocks2)[:2]
    blocks3 = copy.deepcopy(w.net.reference().ledger.blocks)
    blocks3[k], blocks3[k - 1] = blocks3[k - 1], blocks3[k] if k > 1 else blocks3[k]
    out["ledger_blocks_reordered"] = verify_chain(blocks3)[:2] if k > 1 else "n/a"
    return {a: (list(v) if isinstance(v, tuple) else v) for a, v in out.items()}


def e5_merkle(w):
    led = w.net.reference().ledger
    b = max(led.blocks, key=lambda x: len(x["txs"]))
    leaves = [t["tx_id"] for t in b["txs"]]
    i = len(leaves) // 2
    proof = merkle_proof(leaves, i)
    return {"block": b["header"]["index"], "txs_in_block": len(leaves), "proof_length": len(proof),
            "proof_bytes": sum(len(s) // 2 + 1 for s, _ in proof),
            "valid_proof_accepted": verify_proof(leaves[i], proof, b["header"]["merkle_root"]),
            "wrong_tx_rejected": not verify_proof(leaves[i][::-1], proof, b["header"]["merkle_root"])}


def e6_byzantine(data_root):
    rows = []
    for n in (4, 7, 10, 13):
        f = (n - 1) // 3
        cases = [("no_fault", 0, None, None), ("f_offline", f, OFFLINE, None), ("f_bogus_voters", f, BYZ_VOTER, None),
                 ("bad_primary_forged_result", 1, BYZ_PRIMARY, "forge_result"),
                 ("bad_primary_bad_signature", 1, BYZ_PRIMARY, "bad_signature"),
                 ("equivocating_primary", 1, EQUIVOCATOR, None),
                 ("f_plus_1_offline", f + 1, OFFLINE, None), ("f_plus_1_bogus_voters", f + 1, BYZ_VOTER, None)]
        for name, k, beh, atk in cases:
            w = World(n_nodes=n, store_in_memory=True)
            w.load_dataset(data_root, limit=2)
            pids = list(w.patients); pid = pids[0]; p = w.patients[pid]
            pat, doc, ins = pick(w, pid)
            w.grant(pat, doc.id, "*", ("FHIR",), days=30); w.commit()
            nxt = w.net.order[w.net.nodes["V0"].ledger.next_index % n]
            targets = [nxt] if name.startswith(("bad_primary", "equivocating")) else [f"V{i + 1}" for i in range(k)]
            for t in targets:
                w.net.set_behavior(t, beh, atk)
            h0 = w.net.height
            txs = [w.submit(doc, "REQUEST_ACCESS", {"record_id": f"FHIR-{p.pid[:8]}"}),
                   w.submit(w.actors[w.doctor_of[pids[1]][0]], "REQUEST_ACCESS", {"record_id": f"FHIR-{p.pid[:8]}"})]
            r = w.net.run_round()
            progressed = w.net.height > h0
            forged = False
            if progressed:
                led = w.net.reference().ledger
                forged = any(led.lookup(t["tx_id"])[2] == "GRANTED:CONSENT" and t["sender"] != doc.id for t in txs)
            rows.append({"nodes": n, "f": f, "case": name, "faulty_nodes": len(targets),
                         "made_progress": progressed, "view_changes": r.get("view_changes"),
                         "latency_ms": round(r["total_model_ms"], 1), "honest_nodes_consistent": w.net.chain_consistent(),
                         "forged_result_on_chain": forged, "stalled": bool(r.get("stalled"))})
            print("byz", n, name, flush=True)
    return rows


def e7_recovery(w):
    pid = next(iter(w.patients)); p = w.patients[pid]; pat, doc, ins = pick(w, pid)
    w.net.set_behavior("V3", OFFLINE)
    for i in range(10):
        w.request_and_fetch(doc, f"FHIR-{p.pid[:8]}"); w.clock.advance(60)
    behind = w.net.nodes["V3"].ledger.next_index
    t0 = time.perf_counter(); got = w.net.recover("V3"); ms = (time.perf_counter() - t0) * 1000
    ok, reason, _ = verify_chain(w.net.nodes["V3"].ledger.blocks)
    return {"blocks_missed": got, "height_before": behind - 1, "sync_ms": round(ms, 1),
            "recovered_chain_verifies": ok, "consistent_with_peers": w.net.chain_consistent()}


def e8_storage(w):
    led = w.net.reference().ledger
    on = sum(len(canon(b)) for b in led.blocks)
    on_min = sum(len(canon({"header": b["header"], "txs": b["txs"]})) for b in led.blocks)
    off = w.store.disk_bytes()
    plain = sum(m["size"] for m in w.records.values())
    return {"records": len(w.records), "plaintext_bytes": plain, "off_chain_ciphertext_bytes": off,
            "on_chain_bytes_total": on, "on_chain_bytes_without_certs": on_min,
            "on_chain_share_of_data_pct": round(100 * on / (on + off), 4), "blocks": len(led.blocks),
            "avg_bytes_per_record_on_chain": round(on / len(w.records), 1)}


def e9_audit(w):
    pid = next(iter(w.patients))
    h = access_history(w, pid)
    return {"patient": pid, "events": len(h), "denied_events": sum(1 for e in h if e["result"].startswith("DENIED")),
            "granted_events": sum(1 for e in h if e["result"].startswith("GRANTED")), "sample": h[:6]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--patients", type=int, default=20)
    ap.add_argument("--data", default=os.path.join(os.path.dirname(__file__), "..", "data", "subset"))
    a = ap.parse_args()
    t0 = time.time()
    w = World(n_nodes=4, store_in_memory=False)
    print("loading", a.patients, "patients ...", flush=True)
    w.load_dataset(a.data, limit=a.patients, progress=lambda i, n: print(f"  {i}/{n}", flush=True) if i % 5 == 0 else None)
    load_s = time.time() - t0
    R = {"patients": len(w.patients), "records": len(w.records), "participants": Counter(x.role for x in w.actors.values()),
         "load_seconds": round(load_s, 1)}
    R["participants"] = dict(R["participants"])
    R["E1_normal_sharing"] = e1_normal(w);       print("E1", R["E1_normal_sharing"], flush=True)
    R["E2_unauthorized"] = e2_unauthorized(w);   print("E2", R["E2_unauthorized"], flush=True)
    R["E10_hospital_to_hospital"] = e10_hospital_request(w); print("E10", R["E10_hospital_to_hospital"], flush=True)
    R["E11_privacy_scan"] = e11_privacy_scan(w); print("E11", R["E11_privacy_scan"], flush=True)
    R["E3_expiry_revoke"] = e3_expiry_revoke(w); print("E3", R["E3_expiry_revoke"], flush=True)
    R["E4_tamper"] = e4_tamper(w);               print("E4", R["E4_tamper"], flush=True)
    R["E5_merkle_proof"] = e5_merkle(w);         print("E5", R["E5_merkle_proof"], flush=True)
    R["E7_recovery"] = e7_recovery(w);           print("E7", R["E7_recovery"], flush=True)
    R["E9_audit_trail"] = e9_audit(w);           print("E9", R["E9_audit_trail"]["events"], flush=True)
    R["E8_storage"] = e8_storage(w);             print("E8", R["E8_storage"], flush=True)
    R["chain_verifies"] = verify_chain(w.net.reference().ledger.blocks)[:2]
    R["E6_byzantine"] = e6_byzantine(a.data)
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "experiments.json"), "w") as f:
        json.dump(R, f, indent=2, default=str)
    print("done in %.0fs" % (time.time() - t0))


if __name__ == "__main__":
    main()
