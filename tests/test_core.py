import copy, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from ehrchain.crypto import SigningKey, verify, encrypt, decrypt, BoxKey, wrap_key, unwrap_key
from ehrchain.ledger import merkle_root, merkle_proof, verify_proof, verify_chain, make_tx, header_hash
from ehrchain.network import Network, BYZ_PRIMARY, BYZ_VOTER, OFFLINE, EQUIVOCATOR
from ehrchain.toy import toy_world
from cryptography.exceptions import InvalidTag


def test_signature_and_aes():
    k = SigningKey(); s = k.sign(b"x")
    assert verify(k.public_hex, b"x", s) and not verify(k.public_hex, b"y", s)
    key, blob = encrypt(b"secret"); assert decrypt(key, blob) == b"secret"
    bad = bytearray(blob); bad[-1] ^= 1
    with pytest.raises(InvalidTag): decrypt(key, bytes(bad))
    b = BoxKey(); assert unwrap_key(b, wrap_key(key, b.public_hex)) == key


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13])
def test_merkle_proofs(n):
    leaves = [os.urandom(32).hex() for _ in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        assert verify_proof(leaves[i], merkle_proof(leaves, i), root)
    assert not verify_proof(os.urandom(32).hex(), merkle_proof(leaves, 0), root)


def test_access_flow_consent_expiry_revoke():
    w, H, D, P, I, A, recs = toy_world()
    rid, doc, pat = recs[0], D[0], P[0]
    assert w.request_and_fetch(doc, rid)[0] == "DENIED:NO_CONSENT"
    w.grant(pat, doc.id, rid, ("MRI",), days=1); w.commit()
    r, plain, _ = w.request_and_fetch(doc, rid); assert r == "GRANTED:CONSENT|OK" and plain
    assert w.request_and_fetch(D[1], rid)[0] == "DENIED:NO_CONSENT"         # other doctor
    assert w.request_and_fetch(A[0] if isinstance(A, list) else A, rid)[0] == "DENIED:AUDITOR_NO_CONTENT"
    w.clock.advance(2 * 86400)
    assert w.request_and_fetch(doc, rid)[0] == "DENIED:EXPIRED"
    w.grant(pat, doc.id, rid, ("MRI",), days=10); w.commit()
    assert w.request_and_fetch(doc, rid)[0].startswith("GRANTED")
    w.submit(pat, "REVOKE_CONSENT", {"grantee": doc.id, "record_id": "*"}); w.commit()
    assert w.request_and_fetch(doc, rid)[0] == "DENIED:NO_CONSENT"


def test_forged_signature_rejected_before_consensus():
    w, H, D, P, I, A, recs = toy_world()
    tx = D[0].tx("REQUEST_ACCESS", {"record_id": recs[0]}, w.clock.now())
    tx["payload"] = {"record_id": recs[1]}          # tamper after signing
    assert not w.net.submit(tx) and w.net.security_log[-1]["event"] == "REJECTED_BAD_SIGNATURE"


def test_replay_denied():
    w, H, D, P, I, A, recs = toy_world()
    tx = P[0].tx("REQUEST_ACCESS", {"record_id": recs[0]}, w.clock.now())
    w.net.submit(tx); w.commit()
    led = w.net.reference().ledger
    from ehrchain.ledger import build_block  # replaying the same tx in a new block
    w.net.mempool.append(tx); w.net.mempool_ids.discard(tx["tx_id"]); w.commit()
    assert any(r == "DENIED:REPLAY" for b in w.net.reference().ledger.blocks[-1:] for r in b["results"])


def test_ledger_tamper_detected_even_if_hashes_recomputed():
    w, H, D, P, I, A, recs = toy_world()
    w.request_and_fetch(D[0], recs[0])   # a DENIED event on the ledger
    blocks = copy.deepcopy(w.net.reference().ledger.blocks)
    assert verify_chain(blocks)[0]
    b = blocks[-1]
    b["results"][0] = "GRANTED:CONSENT"                       # rewrite history
    assert not verify_chain(blocks)[0]
    from ehrchain.ledger import results_hash
    b["header"]["results_hash"] = results_hash(b["results"]); b["hash"] = header_hash(b["header"])
    ok, reason, _ = verify_chain(blocks)
    assert not ok                                              # signatures/quorum cert no longer match


def test_file_tamper_detected():
    w, H, D, P, I, A, recs = toy_world()
    w.grant(P[0], D[0].id, recs[0], ("MRI",)); w.commit()
    w.store.tamper_ciphertext(recs[0])
    assert w.request_and_fetch(D[0], recs[0])[0].endswith("TAMPERED_CIPHERTEXT")
    w2, H, D, P, I, A, recs = toy_world()
    w2.grant(P[0], D[0].id, recs[0], ("MRI",)); w2.commit()
    cust = w2.actors[w2.records[recs[0]]["hospital"]]
    w2.store.replace_file_consistently(recs[0], b"forged scan", cust)
    assert w2.request_and_fetch(D[0], recs[0])[0].endswith("HASH_MISMATCH")


@pytest.mark.parametrize("n,f", [(4, 1), (7, 2), (10, 3), (13, 4)])
def test_byzantine_tolerance(n, f):
    for beh in (OFFLINE, BYZ_VOTER):
        w, H, D, P, I, A, recs = toy_world(n_nodes=n)
        for i in range(1, f + 1):                       # f faulty non-primary-first nodes
            w.net.set_behavior(f"V{i}", beh)
        h0 = w.net.height
        w.request_and_fetch(D[0], recs[0])
        assert w.net.height > h0 and w.net.chain_consistent(), (n, f, beh)
    # f+1 faulty: no progress, no inconsistent commit
    w, H, D, P, I, A, recs = toy_world(n_nodes=n)
    for i in range(1, f + 2):
        w.net.set_behavior(f"V{i}", BYZ_VOTER)
    h0 = w.net.height
    w.submit(D[0], "REQUEST_ACCESS", {"record_id": recs[0]})
    out = w.commit()
    assert out["stalled"] and w.net.height == h0 and w.net.chain_consistent()


@pytest.mark.parametrize("beh,attack", [(BYZ_PRIMARY, "forge_result"), (BYZ_PRIMARY, "bad_signature"), (EQUIVOCATOR, None)])
def test_bad_primary_triggers_view_change(beh, attack):
    w, H, D, P, I, A, recs = toy_world(n_nodes=4)
    w.grant(P[0], D[0].id, recs[0], ("MRI",)); w.commit()
    nxt = f"V{w.net.nodes['V0'].ledger.next_index % 4}"          # the next primary
    w.net.set_behavior(nxt, beh, attack)
    w.submit(D[1], "REQUEST_ACCESS", {"record_id": recs[0]}); w.submit(D[0], "REQUEST_ACCESS", {"record_id": recs[0]})
    r = w.net.run_round()
    assert r["committed"] and r["view_changes"] >= 1 and w.net.chain_consistent()
    ok, reason, _ = verify_chain(w.net.reference().ledger.blocks); assert ok
    for b in w.net.reference().ledger.blocks[1:]:        # forged outcome never made it on-chain
        assert "GRANTED:CONSENT" not in [r for t, r in zip(b["txs"], b["results"]) if t["sender"] == D[1].id]


def test_node_recovery():
    w, H, D, P, I, A, recs = toy_world(n_nodes=4)
    w.net.set_behavior("V3", OFFLINE)
    for _ in range(3):
        w.request_and_fetch(D[0], recs[0]); w.clock.advance(1)
    behind = w.net.nodes["V3"].ledger.next_index
    got = w.net.recover("V3")
    assert got > 0 and w.net.nodes["V3"].ledger.next_index > behind and w.net.chain_consistent()


def test_node_operator_assignment():
    w, H, D, P, I, A, recs = toy_world(n_nodes=4)
    pub = w.net.pubs["V0"]
    t_ok = w.submit(w.admin, "ASSIGN_NODE", {"node": "V0", "operator": H[0].id, "node_pub": pub})
    t_doc = w.submit(w.admin, "ASSIGN_NODE", {"node": "V1", "operator": D[0].id, "node_pub": w.net.pubs["V1"]})
    t_dup = w.submit(w.admin, "ASSIGN_NODE", {"node": "V0", "operator": H[1].id, "node_pub": pub})
    t_bad = w.submit(H[0], "ASSIGN_NODE", {"node": "V2", "operator": H[0].id, "node_pub": w.net.pubs["V2"]})
    w.commit()
    assert [w.result(t) for t in (t_ok, t_doc, t_dup, t_bad)] == [
        "OK", "DENIED:OPERATOR_NOT_HOSPITAL", "DENIED:NODE_ALREADY_ASSIGNED", "DENIED:NOT_ADMIN"]


def test_insurer_policy_billing_view_only():
    from ehrchain.data import insurance_view
    import json
    w, H, D, P, I, A, recs = toy_world()
    # a patient cannot even grant an insurer clinical kinds
    t = w.grant(P[0], I.id, "*", ("MRI",), days=5); w.commit()
    assert w.result(t) == "DENIED:INSURER_POLICY"
    # insurer is denied clinical records even if a consent entry existed for a doctor
    assert w.request_and_fetch(I, recs[0])[0] == "DENIED:INSURER_POLICY"
    raw = json.dumps({"entry": [{"resource": {"resourceType": "Patient", "id": "1", "name": [{"family": "X"}], "gender": "male", "birthDate": "1990-01-01", "address": [{"city": "secret"}]}},
                                {"resource": {"resourceType": "Condition", "id": "c"}},
                                {"resource": {"resourceType": "Claim", "id": "k", "status": "active", "total": {"value": 5}, "diagnosis": [{"x": 1}]}}]}).encode()
    view = json.loads(insurance_view(raw))["entry"]
    types = [e["resource"]["resourceType"] for e in view]
    assert types == ["Patient", "Claim"] and "address" not in view[0]["resource"] and "diagnosis" not in view[1]["resource"]


def test_hospital_requests_and_patient_pseudonymous():
    import json
    w, H, D, P, I, A, recs = toy_world(hosp=2, pats=2)
    rid = recs[0]                                  # held by H[0]
    assert w.request_and_fetch(H[1], rid)[0] == "DENIED:NO_CONSENT"
    w.grant(P[0], H[1].id, rid, ("MRI",), days=3); w.commit()
    assert w.request_and_fetch(H[1], rid)[0] == "GRANTED:CONSENT|OK"
    assert w.request_and_fetch(H[0], rid)[0] == "GRANTED:CUSTODIAN|OK"
    P[0].name = "Jane Secret"
    reg = P[0].register_payload()
    assert reg["name"] == "" and "Jane" not in json.dumps(reg)
